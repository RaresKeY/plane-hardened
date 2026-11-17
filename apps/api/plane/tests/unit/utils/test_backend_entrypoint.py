import importlib.util
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest

from plane.utils import runtime_health


@pytest.fixture
def entrypoint(monkeypatch):
    # The build copies this exact pure-stdlib module alongside the entrypoint.
    monkeypatch.setitem(sys.modules, "runtime_health", runtime_health)
    path = Path(__file__).resolve().parents[6] / "hardening/backend_entrypoint.py"
    spec = importlib.util.spec_from_file_location("qualified_backend_entrypoint", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.os, "getuid", lambda: 1000)
    monkeypatch.setattr(module.os, "chdir", Mock())
    monkeypatch.setattr(module.os, "execvp", Mock())
    monkeypatch.setattr(module.socket, "gethostname", lambda: "fixture")
    monkeypatch.setattr(module, "register_runtime", Mock())
    for key, value in {"SECRET_KEY": "synthetic-entrypoint-key-of-sufficient-length",
                       "DATABASE_URL": "postgresql://fixture.invalid/plane",
                       "REDIS_URL": "redis://fixture.invalid/0"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("GUNICORN_WORKERS", raising=False)
    return module


@pytest.mark.parametrize("mode,executable,argument", [
    ("api", "gunicorn", "plane.asgi:application"),
    ("worker", "celery", "worker"),
    ("beat", "celery", "beat"),
    ("migrator", sys.executable, "migrate"),
])
def test_legacy_compose_aliases_execute_safe_modes_without_shell_scripts(
    entrypoint, monkeypatch, mode, executable, argument
):
    monkeypatch.setattr(sys, "argv", ["entrypoint", f"./bin/docker-entrypoint-{mode}.sh"])
    entrypoint.main()
    command = entrypoint.os.execvp.call_args.args[1]
    assert command[0] == executable and argument in command
    assert not any("docker-entrypoint" in value or value in ("sh", "bash") for value in command)
    if mode == "migrator":
        assert command == [sys.executable, "/code/manage.py", "migrate", "--noinput"]
    else:
        assert "migrate" not in command


@pytest.mark.parametrize("arguments", [
    ["./bin/docker-entrypoint-api.sh", "&&", "evil"], ["/bin/sh"], ["../bin/docker-entrypoint-api.sh"],
    ["./bin/docker-entrypoint-api.sh;evil"], ["worker", "--include=unreviewed"], ["api", "extra"],
])
def test_unknown_commands_and_extra_legacy_arguments_are_rejected(entrypoint, arguments):
    with pytest.raises(ValueError):
        entrypoint.mode_arguments(arguments)
    entrypoint.os.execvp.assert_not_called()


def test_default_api_port_and_custom_port_bind_health_identity(entrypoint, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["entrypoint"])
    entrypoint.main()
    entrypoint.register_runtime.assert_called_with("api", port=8000)
    monkeypatch.setenv("PORT", "8123")
    entrypoint.main()
    assert "0.0.0.0:8123" in entrypoint.os.execvp.call_args.args[1]
    entrypoint.register_runtime.assert_called_with("api", port=8123)


def test_worker_node_and_beat_scheduler_match_health_contract(entrypoint, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["entrypoint", "worker"])
    entrypoint.main()
    entrypoint.register_runtime.assert_called_with("worker", node="plane@fixture")
    assert "--hostname=plane@fixture" in entrypoint.os.execvp.call_args.args[1]
    monkeypatch.setattr(sys, "argv", ["entrypoint", "beat"])
    entrypoint.main()
    assert "--scheduler=plane.utils.celery_health:HeartbeatDatabaseScheduler" in entrypoint.os.execvp.call_args.args[1]


def test_health_returns_bounded_probe_status_without_executing_a_service(entrypoint, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["entrypoint", "health"])
    monkeypatch.setattr(sys, "path", [path for path in sys.path if path != "/code"])
    monkeypatch.setattr(entrypoint, "health_main", Mock(return_value=1))
    monkeypatch.delenv("SECRET_KEY")
    assert entrypoint.main() == 1
    assert sys.path[0] == "/code"
    entrypoint.os.execvp.assert_not_called()


@pytest.mark.parametrize("key,value", [("SECRET_KEY", "short"), ("DATABASE_URL", ""), ("REDIS_URL", ""),
                                      ("PORT", "80"), ("GUNICORN_WORKERS", "100")])
def test_invalid_service_configuration_does_not_register_or_execute(entrypoint, monkeypatch, key, value):
    monkeypatch.setattr(sys, "argv", ["entrypoint", "api"])
    monkeypatch.setenv(key, value)
    with pytest.raises(ValueError):
        entrypoint.main()
    entrypoint.register_runtime.assert_not_called()
    entrypoint.os.execvp.assert_not_called()
