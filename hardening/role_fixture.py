"""Owned Podman test controller; all application code executes inside isolated fixtures."""


def run_role_fixture(cfg, out, network):
    import json
    import subprocess
    import time
    from uuid import uuid4

    marker = "synthetic-role-fixture-must-not-appear-in-logs"
    names = []
    results = {}
    roles = {}

    def invoke(command, *, timeout=30, check=True):
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError("Role fixture command failed: " + result.stderr[-1500:])
        return result

    def create(role, arguments):
        name = cfg["id"] + "-" + role + "-" + uuid4().hex[:6]
        command = [
            "podman", "create", "--name", name, "--label", "io.rareskey.project=plane-hardened",
            "--label", "io.rareskey.retention=ephemeral", "--userns=keep-id:uid=1000,gid=1000",
            "--user=1000:1000", "--network=" + network, "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=128", "--cpus=1", "--memory=1g",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m", "--health-interval=2s", "--health-start-period=0s",
        ]
        environment = {
            "DATABASE_URL": "postgresql://plane_fixture:isolated-synthetic-password@postgres:5432/plane",
            "REDIS_URL": "redis://:isolated-cache-fixture@cache:6379/0",
            "AMQP_URL": "redis://:isolated-cache-fixture@cache:6379/1",
            "SECRET_KEY": "isolated-role-fixture-key-not-valid-for-production",
            "WEB_URL": "http://fixture.invalid", "AWS_EC2_METADATA_DISABLED": "true",
            "GUNICORN_WORKERS": "1", "PORT": "8123",
        }
        for key, value in environment.items():
            command.extend(["--env", key + "=" + value])
        command.extend([cfg["image"], *arguments])
        invoke(command)
        names.append(name)
        info = json.loads(invoke(["podman", "inspect", name]).stdout)[0]
        (out / (role + "-isolation.json")).write_text(json.dumps(info, indent=2))
        host = info["HostConfig"]
        if (info["Config"]["User"] != "1000:1000" or not host["ReadonlyRootfs"]
                or host.get("CapAdd") or not host["CapDrop"] or host.get("PortBindings")
                or "no-new-privileges" not in host["SecurityOpt"] or host["Memory"] != 1024**3
                or host["PidsLimit"] != 128 or any(m["Type"] == "bind" for m in info["Mounts"])
                or set(info["NetworkSettings"]["Networks"]) != {network}):
            raise RuntimeError("Role container isolation differs from the prescribed boundary")
        health = info["Config"]["Healthcheck"]
        if "health" not in health["Test"] or "backend_entrypoint.py" not in " ".join(health["Test"]):
            raise RuntimeError("Role fixture must use the image's actual role-aware health check")
        return name

    def one_shot(role, arguments, timeout=60):
        name = create(role, arguments)
        result = invoke(["podman", "start", "--attach", name], timeout=timeout, check=False)
        (out / (role + ".log")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("One-shot fixture failed: " + role)
        return name

    def health(name, expected=True, seconds=35):
        deadline = time.monotonic() + seconds
        while True:
            result = invoke(["podman", "healthcheck", "run", name], timeout=10, check=False)
            if (result.returncode == 0) == expected:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("Unexpected role health result")
            time.sleep(0.5)

    try:
        one_shot("migrator", ["./bin/docker-entrypoint-migrator.sh"], timeout=300)
        results["legacy_migrator_alias"] = "passed real migrations without invoking the old shell script"
        seed = (
            "import json;from django_celery_beat.models import IntervalSchedule,PeriodicTask;"
            "interval=IntervalSchedule.objects.create(every=1,period=IntervalSchedule.SECONDS);"
            "PeriodicTask.objects.create(name='role-fixture-audit',interval=interval,"
            "task='plane.bgtasks.logger_task.process_logs',kwargs=json.dumps({'audit_schema':1,"
            "'log_data':{'token_identifier':'c'*64,'path':'/api/scheduled-secret?token=synthetic',"
            "'method':'GET','response_code':200,"
            "'body':" + repr(marker) + "}}))"
        )
        one_shot("seed", ["manage", "shell", "-c", seed])
        for role in ("api", "worker", "beat"):
            roles[role] = create(role, ["./bin/docker-entrypoint-" + role + ".sh"])
            invoke(["podman", "start", roles[role]])
        for role, name in roles.items():
            health(name)
            results[role + "_health"] = "passed actual image health check in its own PID1 container"
        results["api_custom_port"] = 8123
        verify = """import time
from plane.db.models import APIActivityLog
deadline = time.monotonic() + 25
while not APIActivityLog.objects.filter(token_identifier='c'*64).exists():
    assert time.monotonic() < deadline, 'scheduled task did not persist'
    time.sleep(0.2)
rows = APIActivityLog.objects.filter(token_identifier='c'*64)
assert all(row.body is None and row.headers is None and row.query_params == '' for row in rows)
assert all(row.path == '/[unresolved]' for row in rows)
print('scheduled persistence and payload stripping passed')
"""
        one_shot("verify", ["manage", "shell", "-c", verify])
        results["scheduled_delivery"] = "DatabaseScheduler→Valkey→standalone prefork worker→PostgreSQL"

        invoke(["podman", "kill", "--signal", "STOP", roles["worker"]])
        try:
            health(roles["worker"], expected=False, seconds=10)
        finally:
            invoke(["podman", "kill", "--signal", "CONT", roles["worker"]])
        health(roles["worker"])
        results["worker_unresponsive_and_recovery"] = "passed negative and positive RPC controls"

        invoke(["podman", "kill", "--signal", "STOP", roles["beat"]])
        try:
            time.sleep(31)
            health(roles["beat"], expected=False, seconds=10)
        finally:
            invoke(["podman", "kill", "--signal", "CONT", roles["beat"]])
        health(roles["beat"])
        results["beat_stale_and_recovery"] = "passed negative and positive scheduler-loop controls"
        for role, name in roles.items():
            # Podman may send application logs to either captured stream.
            captured = invoke(["podman", "logs", name])
            log = captured.stdout + captured.stderr
            (out / (role + ".log")).write_text(log)
            if marker in log:
                raise RuntimeError("Scheduled payload entered role logs")
        results["scheduled_payload_log_privacy"] = "passed with default unmasked message representation"
        results["scope"] = "Synthetic fixtures only; Valkey transport, not RabbitMQ or production restore"
        (out / "role-results.json").write_text(json.dumps(results, indent=2))
        print(json.dumps({"role_fixture": "passed", "results": results}), flush=True)
        return 0
    finally:
        for name in reversed(names):
            invoke(["podman", "kill", "--signal", "CONT", name], check=False)
            captured = invoke(["podman", "logs", name], check=False)
            (out / (name + "-console.log")).write_text(captured.stdout + captured.stderr)
            invoke(["podman", "rm", "--force", name], check=False)
