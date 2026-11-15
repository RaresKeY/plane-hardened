"""Exercise the built backend's production entrypoint and HTTP parser with synthetic data."""

from contextlib import suppress
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

OUT = Path("/out")
MARKER = "synthetic-secret-must-not-be-logged-6f72e1"


def request(method, path, body=None, token=None):
    connection = http.client.HTTPConnection("127.0.0.1", 8000, timeout=5)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Api-Key"] = token
    try:
        connection.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = connection.getresponse()
        payload = response.read(1024 * 1024)
        try:
            decoded = json.loads(payload) if payload else None
        except ValueError:
            decoded = None
        return response.status, decoded
    finally:
        connection.close()


def malformed(payload):
    with socket.create_connection(("127.0.0.1", 8000), timeout=5) as peer:
        peer.settimeout(5)
        peer.sendall(payload)
        response = peer.recv(4096)
    assert response.startswith(b"HTTP/1.1 400 "), response[:120]


def cors_header(origin):
    connection = http.client.HTTPConnection("127.0.0.1", 8000, timeout=5)
    try:
        connection.request("GET", "/", headers={"Origin": origin})
        response = connection.getresponse()
        assert response.status == 200
        response.read(1024 * 1024)
        return response.getheader("Access-Control-Allow-Origin")
    finally:
        connection.close()


def main():
    assert os.getuid() != 0
    status = Path("/proc/self/status").read_text()
    assert "NoNewPrivs:\t1" in status
    sys.path.insert(0, "/code")
    os.environ["DJANGO_SETTINGS_MODULE"] = "plane.settings.hardened"
    os.environ["AMQP_URL"] = "memory://"
    with (OUT / "runtime-migrations.log").open("w") as log:
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
    from plane.db.models import APIToken, Project, ProjectMember, User, Workspace, WorkspaceMember

    assert settings.DEBUG is False and settings.SCOUT_MONITOR is False
    assert not any(
        handler.get("class", "").endswith("FileHandler") for handler in settings.LOGGING["handlers"].values()
    )
    owner = User.objects.create(email="owner@fixture.invalid", username="fixture-owner")
    owner.set_password("synthetic-password-not-used-outside-fixture")
    owner.save()
    outsider = User.objects.create(email="outsider@fixture.invalid", username="fixture-outsider")
    workspace = Workspace.objects.create(name="Runtime fixture", slug="runtime-fixture", owner=owner)
    WorkspaceMember.objects.create(workspace=workspace, member=owner, role=20)
    project = Project.objects.create(name="Runtime project", identifier="RTP", workspace=workspace, created_by=owner)
    ProjectMember.objects.create(project=project, member=owner, role=20)
    token = APIToken.objects.create(user=owner, label="runtime-fixture")
    other_token = APIToken.objects.create(user=outsider, label="outsider-fixture")
    log_path = OUT / "runtime-api.log"
    checks = []
    with log_path.open("w") as log:
        server = subprocess.Popen(
            [sys.executable, "/opt/plane-hardening/backend_entrypoint.py", "api"],
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("Backend entrypoint exited before healthy")
                try:
                    if request("GET", "/")[0] == 200:
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.2)
            else:
                raise RuntimeError("Backend startup timed out")
            checks.append("production entrypoint healthy with readonly root and non-root UID")
            assert cors_header("https://untrusted.fixture.invalid") is None
            checks.append("unset CORS origin configuration denies arbitrary credentialed browser origins")
            base = "/api/v1/workspaces/runtime-fixture/projects/"
            assert request("GET", base, token=token.token)[0] == 200
            assert request("GET", base, token=other_token.token)[0] in (403, 404)
            assert request("GET", base, token="invalid-" + MARKER)[0] in (401, 403)
            checks.append("HTTP API token authentication and workspace isolation")
            path = base + str(project.id) + "/issues/"
            code, issue = request(
                "POST",
                path + "?fixture=" + MARKER,
                {"name": "Runtime issue", "description_html": "<p>" + MARKER + "</p><img src=x onerror=alert(1)>"},
                token.token,
            )
            assert code == 201, (code, issue)
            assert "onerror" not in issue.get("description_html", "")
            assert MARKER in issue.get("description_html", "")
            checks.append("HTTP issue create, HTML sanitization, ordinary content retention")
            assert request("GET", "/missing-" + MARKER + "?token=" + MARKER)[0] == 404
            assert request("GET", "/?token=" + MARKER)[0] == 200
            for payload in [
                b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: nope\r\n\r\n",
                b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx",
                b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip\r\n\r\n",
                b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\nx\r\n0\r\n\r\n",
                b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Oversized: " + b"x" * 65536,
            ]:
                malformed(payload)
            checks.append("five malformed/oversized HTTP parser rejection controls")
        finally:
            with suppress(ProcessLookupError):
                os.killpg(server.pid, signal.SIGTERM)
            try:
                server.wait(timeout=35)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(server.pid, signal.SIGKILL)
                server.wait(timeout=5)
    output = log_path.read_text()
    for secret in [MARKER, token.token, other_token.token]:
        assert secret not in output, "Synthetic secret leaked in production server logs"
    checks.append("production server logs omit token, query, body and arbitrary path markers")
    # Exercise the valid origin control in a fresh process reading actual settings,
    # rather than reproducing the setting in a mocked middleware configuration.
    with (OUT / "runtime-cors.log").open("w") as log:
        server = subprocess.Popen(
            [sys.executable, "/opt/plane-hardening/backend_entrypoint.py", "api"],
            env={**os.environ, "CORS_ALLOWED_ORIGINS": "https://web.fixture.invalid"},
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("CORS positive-control API exited")
                try:
                    if request("GET", "/")[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.2)
            else:
                raise RuntimeError("CORS positive-control startup timed out")
            assert cors_header("https://web.fixture.invalid") == "https://web.fixture.invalid"
            assert cors_header("https://untrusted.fixture.invalid") is None
            checks.append("explicit configured CORS origin succeeds and other origins remain denied")
        finally:
            with suppress(ProcessLookupError):
                os.killpg(server.pid, signal.SIGTERM)
            try:
                server.wait(timeout=35)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(server.pid, signal.SIGKILL)
                server.wait(timeout=5)
    result = {
        "passed": True,
        "checks": checks,
        "image_source": "/code",
        "limits": ["Celery uses memory transport here; no live worker/RabbitMQ or S3/UI qualification"],
    }
    (OUT / "runtime-results.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
