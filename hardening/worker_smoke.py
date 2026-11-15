"""Real API → JSON broker → Celery worker → PostgreSQL audit controls, synthetic data only."""

from contextlib import suppress
import hashlib
import hmac
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from runtime_smoke import request

OUT = Path("/out")
SECRET = "synthetic-legacy-body-cookie-must-never-enter-worker-logs"


def wait_for(predicate, message, seconds=35):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise AssertionError(message)


def main():
    assert os.getuid() != 0
    sys.path.insert(0, "/code")
    os.environ["DJANGO_SETTINGS_MODULE"] = "plane.settings.hardened"
    assert os.environ["AMQP_URL"].startswith("redis://")
    with (OUT / "worker-migrations.log").open("w") as log:
        subprocess.run(
            [sys.executable, "/code/manage.py", "migrate", "--noinput"],
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
            timeout=240,
        )
    import django

    django.setup()
    from django.conf import settings
    from plane.bgtasks.logger_task import process_logs
    from plane.celery import app
    from plane.db.models import APIActivityLog, APIToken, Project, ProjectMember, User, Workspace, WorkspaceMember
    from plane.utils.request_logging import AUDIT_SCHEMA

    owner = User.objects.create(email="worker@fixture.invalid", username="worker-fixture")
    workspace = Workspace.objects.create(name="Worker fixture", slug="worker-fixture", owner=owner)
    WorkspaceMember.objects.create(workspace=workspace, member=owner, role=20)
    project = Project.objects.create(name="Worker project", identifier="WRK", workspace=workspace, created_by=owner)
    ProjectMember.objects.create(project=project, member=owner, role=20)
    token = APIToken.objects.create(user=owner, label="worker-fixture")
    identifier = hmac.new(settings.SECRET_KEY.encode(), token.token.encode(), hashlib.sha256).hexdigest()
    processes = []
    try:
        for mode in ("worker", "api"):
            log = (OUT / ("worker-" + mode + ".log")).open("w")
            child = subprocess.Popen(
                [sys.executable, "/opt/plane-hardening/backend_entrypoint.py", mode],
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            log.close()
            processes.append(child)
        wait_for(lambda: bool(app.control.ping(timeout=1)), "Worker did not answer a broker control ping", seconds=60)

        def healthy():
            try:
                return request("GET", "/")[0] == 200
            except OSError:
                return False

        wait_for(healthy, "API startup failed")
        assert not app.conf.task_always_eager
        assert (
            request("GET", "/api/v1/workspaces/worker-fixture/projects/?secret=" + SECRET, token=token.token)[0] == 200
        )
        wait_for(lambda: APIActivityLog.objects.filter(token_identifier=identifier).exists(), "API audit not consumed")
        row = APIActivityLog.objects.get(token_identifier=identifier)
        assert row.path == "/api/v1/workspaces/<str:slug>/projects/"
        assert row.response_code == 200 and row.method == "GET"
        for field in ("headers", "body", "response_body", "user_agent"):
            assert getattr(row, field) is None
        assert row.query_params == ""

        # Queue legacy and deliberately dirty current-schema payloads. Producer
        # representations are masked as in the real middleware; no fixture secret is logged.
        marker = "a" * 64
        process_logs.apply_async(kwargs={"log_data": {"body": SECRET}}, argsrepr="()", kwargsrepr="[fixture metadata]")
        process_logs.apply_async(
            kwargs={
                "audit_schema": AUDIT_SCHEMA,
                "log_data": {
                    "token_identifier": marker,
                    "path": "/api/fixture/",
                    "method": "POST",
                    "response_code": 201,
                    "query_params": SECRET,
                    "headers": {"Cookie": SECRET},
                    "body": SECRET,
                    "response_body": SECRET,
                    "user_agent": SECRET,
                },
            },
            argsrepr="()",
            kwargsrepr="[fixture metadata]",
        )
        wait_for(lambda: APIActivityLog.objects.filter(token_identifier=marker).exists(), "Dirty payload not consumed")
        sanitized = APIActivityLog.objects.get(token_identifier=marker)
        assert sanitized.query_params == "" and sanitized.headers is None and sanitized.body is None
        wait_for(
            lambda: "Discarded legacy API activity payload" in (OUT / "worker-worker.log").read_text(),
            "Legacy guard not run",
        )
        assert APIActivityLog.objects.count() == 2
    finally:
        for child in processes:
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGTERM)
        for child in processes:
            try:
                child.wait(timeout=35)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
    output = (OUT / "worker-worker.log").read_text() + (OUT / "worker-api.log").read_text()
    assert SECRET not in output and token.token not in output
    result = {
        "passed": True,
        "checks": [
            "Production API producer sends JSON through real Valkey broker to real prefork Celery worker",
            "Actual PostgreSQL metadata persistence, keyed token correlation, route/status and secret stripping",
            "Legacy payload rejection and worker-side revalidation of dirty current-schema records",
            "API and worker logs omit synthetic credentials and payload markers",
        ],
        "limits": [
            "Valkey broker qualification does not qualify RabbitMQ transport",
            "Synthetic data only; no S3, beat or VPS action",
        ],
    }
    (OUT / "worker-results.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
