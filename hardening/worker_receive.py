"""Actual-worker privacy controls for unmasked v1/v2 messages, results and failures."""

import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import threading
from uuid import uuid4
from unittest.mock import patch

MARKER = "synthetic-unmasked-worker-payload-return-exception"


def child():
    source = Path(__file__).resolve().parents[1] / "apps/api"
    sys.path.insert(0, str(source if source.is_dir() else Path("/code")))
    os.environ.update({"DJANGO_SETTINGS_MODULE": "plane.settings.hardened", "AMQP_URL": "memory://",
                       "DATABASE_URL": "postgresql://fixture:synthetic@database.invalid/plane",
                       "REDIS_URL": "redis://cache.invalid:6379/0",
                       "SECRET_KEY": "isolated-worker-reception-test-key-not-production",
                       "PLANE_LOG_DIR": "/tmp/worker-reception-logs",
                       "WEB_URL": "http://fixture.invalid", "AWS_EC2_METADATA_DISABLED": "true"})
    import django

    django.setup()
    from celery.contrib.testing.worker import start_worker
    from celery.signals import task_postrun, worker_init
    from plane.bgtasks.logger_task import process_logs
    from plane.bgtasks.notification_task import notifications
    from plane.celery import app

    @app.task(name="plane.fixture.worker_return", ignore_result=True)
    def return_value():
        return MARKER

    @app.task(name="plane.fixture.worker_failure", ignore_result=True)
    def failure():
        raise ValueError(MARKER)

    identities = {name: str(uuid4()) for name in ("v1", "v2", "return", "failure", "notification")}
    states = {}
    complete = threading.Event()

    def finished(task_id=None, state=None, **_):
        for name, identity in identities.items():
            if identity == task_id:
                states[name] = state
        if len(states) == len(identities):
            complete.set()

    task_postrun.connect(finished, weak=False)
    app.conf.update(task_always_eager=False, task_ignore_result=True, broker_url="memory://")

    def enable_probe_diagnostics(**_):
        for name in ("celery.app.trace", "celery.worker.consumer.consumer"):
            logger = logging.getLogger(name)
            logger.disabled = False
            logger.setLevel(logging.INFO)

    worker_init.connect(enable_probe_diagnostics, weak=False)
    with patch("plane.bgtasks.notification_task.ProjectMember.objects.filter", side_effect=RuntimeError(MARKER)), \
            start_worker(app, perform_ping_check=False, pool="solo", loglevel="INFO"):
        # No argsrepr/kwargsrepr override: these are the original exposed wire representations.
        process_logs.apply_async(kwargs={"log_data": {"body": MARKER}}, task_id=identities["v2"])
        message = app.amqp.as_task_v1(identities["v1"], process_logs.name,
                                     kwargs={"log_data": {"body": MARKER}})
        with app.producer_or_acquire() as producer:
            app.amqp.send_task_message(producer, process_logs.name, message)
        app.send_task("unknown." + MARKER, kwargs={"body": MARKER}, ignore_result=True)
        return_value.apply_async(task_id=identities["return"])
        failure.apply_async(task_id=identities["failure"])
        notifications.apply_async(kwargs={
            "type": "issue.created", "issue_id": "fixture", "project_id": "fixture", "actor_id": "fixture",
            "subscriber": None, "issue_activities_created": None, "requested_data": {"body": MARKER},
            "current_instance": None,
        }, task_id=identities["notification"])
        assert complete.wait(20), "Worker did not complete every control"
    assert states == {"v1": "SUCCESS", "v2": "SUCCESS", "return": "SUCCESS", "failure": "FAILURE",
                      "notification": "SUCCESS"}
    print(json.dumps({"control_states": states, "identities": identities}))


def main():
    assert os.getuid() != 0
    if sys.argv[1:] == ["--child"]:
        child()
        return 0
    result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--child"],
                            capture_output=True, text=True, timeout=55)
    output = result.stdout + result.stderr
    Path("/out/worker-reception-child.log").write_text(output)
    logs = []
    controls = None
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if type(row) is dict and "control_states" in row:
            controls = row
        elif type(row) is dict and "message" in row:
            logs.append(row)
    events = {row["message"] for row in logs}
    identities_visible = controls is not None and all(
        any(row.get("task_id") == identity for row in logs) for identity in controls["identities"].values()
    )
    required = {"Task received", "Task succeeded", "Task failed", "Discarded legacy API activity payload",
                "Unregistered task rejected"}
    passed = result.returncode == 0 and MARKER not in output and required <= events and identities_visible
    summary = {"passed": passed, "child_exit": result.returncode, "payload_leaked": MARKER in output,
               "control_states": controls["control_states"] if controls else None,
               "required_events_visible": required <= events, "task_identities_visible": identities_visible,
               "scope": ("Actual Celery/audit code; real solo worker and memory broker; default v1/v2 payloads, "
                         "unknown task, return, failure and actual notification error path; no database/network")}
    Path("/out/worker-reception.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
