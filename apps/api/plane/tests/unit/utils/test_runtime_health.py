import os
from unittest.mock import Mock

import pytest

from plane.utils import runtime_health as health


@pytest.fixture
def state_root(tmp_path, monkeypatch):
    monkeypatch.setattr(health, "ROOT", tmp_path / "runtime")
    return health.ROOT


def test_state_uses_current_process_identity_and_private_permissions(state_root):
    health.register_runtime("api", port=8123)
    state = health.read_state(f"runtime-{os.getpid()}.json")
    assert state == {"schema": 1, "role": "api", "port": 8123, "pid": os.getpid(),
                     "start": health.process_start(os.getpid())}
    assert state_root.stat().st_mode & 0o777 == 0o700
    assert (state_root / f"runtime-{os.getpid()}.json").stat().st_mode & 0o777 == 0o600
    assert not list(state_root.glob(".state-*"))


def test_failed_write_does_not_replace_state_or_leave_temporary_files(state_root):
    health.register_runtime("manage")
    with pytest.raises(TypeError):
        health.write_state(f"runtime-{os.getpid()}.json", {"not-json": object()})
    assert health.read_state(f"runtime-{os.getpid()}.json")["role"] == "manage"
    assert not list(state_root.glob(".state-*"))


def test_api_probe_honors_port_and_ignores_proxy_configuration(state_root, monkeypatch):
    import urllib.request

    health.register_runtime("api", port=8123)
    response = Mock(status=200)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    opener = Mock()
    opener.open.return_value = response
    build = Mock(return_value=opener)
    monkeypatch.setattr(urllib.request, "build_opener", build)
    assert health.check_health(os.getpid())
    opener.open.assert_called_once_with("http://127.0.0.1:8123/", timeout=2)
    assert build.call_args.args[0].proxies == {}


@pytest.mark.parametrize("port", [1, 65536, "8000", True, None])
def test_api_invalid_ports_fail_closed(state_root, port):
    health.register_runtime("api", port=port)
    assert not health.check_health(os.getpid())


@pytest.mark.parametrize("reply,expected", [([{ "plane@fixture": {"ok": "pong"}}], True),
                                           ([{"other@fixture": {"ok": "pong"}}], False),
                                           ([{"plane@fixture": {"error": "offline"}}], False), ([], False)])
def test_worker_requires_ping_from_its_own_node(state_root, monkeypatch, reply, expected):
    from plane.celery import app

    health.register_runtime("worker", node="plane@fixture")
    ping = Mock(return_value=reply)
    monkeypatch.setattr(app.control, "ping", ping)
    assert health.check_health(os.getpid()) is expected
    ping.assert_called_once_with(destination=["plane@fixture"], timeout=2)


def test_beat_requires_recent_loop_heartbeat_and_matching_process(state_root, monkeypatch):
    health.register_runtime("beat")
    with pytest.raises(FileNotFoundError):
        health.check_health(os.getpid())
    health.beat_heartbeat()
    assert health.check_health(os.getpid())
    state = health.read_state(f"beat-{os.getpid()}.json")
    monkeypatch.setattr(health.time, "monotonic", lambda: state["at"] + 31)
    assert not health.check_health(os.getpid())


@pytest.mark.parametrize("at", [-1, float("nan"), float("inf"), "secret", True])
def test_beat_invalid_heartbeat_fails_closed(state_root, at):
    health.register_runtime("beat")
    health.write_state(f"beat-{os.getpid()}.json", {"pid": os.getpid(), "start": health.process_start(os.getpid()),
                                                 "at": at})
    assert not health.check_health(os.getpid())


def test_stale_pid_identity_and_unknown_role_fail_closed(state_root):
    health.register_runtime("manage")
    assert health.check_health(os.getpid())
    state = health.read_state(f"runtime-{os.getpid()}.json")
    state["start"] = "stale"
    health.write_state(f"runtime-{os.getpid()}.json", state)
    assert not health.check_health(os.getpid())
    health.register_runtime("unknown")
    assert not health.check_health(os.getpid())


@pytest.mark.parametrize("data", [b"{}" * 2000, b"[]", b"not json"])
def test_invalid_or_oversized_state_rejected(state_root, data):
    state_root.mkdir(mode=0o700)
    (state_root / "invalid.json").write_bytes(data)
    with pytest.raises(ValueError):
        health.read_state("invalid.json")


@pytest.mark.parametrize("symlink", [False, True])
def test_public_or_symlink_runtime_roots_are_rejected(state_root, symlink):
    if symlink:
        state_root.symlink_to(state_root.parent)
    else:
        state_root.mkdir(mode=0o777)
        state_root.chmod(0o777)
    with pytest.raises(ValueError):
        health.register_runtime("manage")


def test_health_cli_bounds_checks_and_never_prints_exception_input(monkeypatch, capsys):
    alarm = Mock()
    monkeypatch.setattr(health.signal, "alarm", alarm)
    monkeypatch.setattr(health.signal, "signal", Mock())
    monkeypatch.setattr(health, "check_health", Mock(side_effect=RuntimeError("synthetic-secret")))
    assert health.main() == 1
    assert capsys.readouterr().out == "unhealthy\n"
    assert alarm.call_args_list[0].args == (4,) and alarm.call_args_list[-1].args == (0,)


def test_scheduler_preserves_delay_and_only_heartbeats_after_success(monkeypatch):
    from plane.utils import celery_health

    tick = Mock(return_value=2.5)
    heartbeat = Mock()
    monkeypatch.setattr(celery_health.DatabaseScheduler, "tick", tick)
    monkeypatch.setattr(celery_health, "beat_heartbeat", heartbeat)
    scheduler = object.__new__(celery_health.HeartbeatDatabaseScheduler)
    assert scheduler.tick() == 2.5
    heartbeat.assert_called_once_with()
    tick.side_effect = RuntimeError("failed loop")
    with pytest.raises(RuntimeError):
        scheduler.tick()
    assert heartbeat.call_count == 1
