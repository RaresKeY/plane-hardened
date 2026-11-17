"""Role-aware health state for the immutable backend; no credentials in state or output."""

import json
import math
import os
from pathlib import Path
import signal
import stat
import tempfile
import time

ROOT = Path("/tmp/plane-runtime")
BEAT_MAX_AGE = 30


def private_root(create=False):
    if create:
        ROOT.mkdir(mode=0o700, exist_ok=True)
    info = ROOT.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Runtime health directory must be private and owned by the service")


def process_start(pid):
    if type(pid) is not int or pid < 1:
        raise ValueError("Invalid runtime process")
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    if stat[0] in ("Z", "X"):
        raise ValueError("Runtime process exited")
    return stat[19]


def write_state(name, state):
    private_root(create=True)
    target = ROOT / name
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=ROOT, prefix=".state-", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(state, handle)
        temporary.replace(target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def register_runtime(role, *, port=None, node=None):
    pid = os.getpid()
    state = {"schema": 1, "role": role, "pid": pid, "start": process_start(pid)}
    if port is not None:
        state["port"] = port
    if node is not None:
        state["node"] = node
    write_state(f"runtime-{pid}.json", state)


def beat_heartbeat():
    pid = os.getpid()
    write_state(f"beat-{pid}.json", {"pid": pid, "start": process_start(pid), "at": time.monotonic()})


def read_state(name):
    private_root()
    path = ROOT / name
    with path.open("rb") as handle:
        data = handle.read(2049)
    if len(data) > 2048:
        raise ValueError("Invalid runtime state")
    state = json.loads(data)
    if type(state) is not dict:
        raise ValueError("Invalid runtime state")
    return state


def check_health(pid=1):
    state = read_state(f"runtime-{pid}.json")
    if (type(state.get("schema")) is not int or state["schema"] != 1 or type(state.get("pid")) is not int
            or state["pid"] != pid or state.get("start") != process_start(pid)):
        return False
    role = state.get("role")
    if role == "api":
        import urllib.request

        port = state.get("port")
        if type(port) is not int or not 1024 <= port <= 65535:
            return False
        # Never inherit an operator proxy for a local liveness probe.
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with client.open(f"http://127.0.0.1:{port}/", timeout=2) as response:
            return response.status == 200
    if role == "worker":
        from plane.celery import app

        node = state.get("node")
        if type(node) is not str or not node or len(node) > 255:
            return False
        replies = app.control.ping(destination=[node], timeout=2)
        return any(type(reply) is dict and reply.get(node) == {"ok": "pong"} for reply in replies)
    if role == "beat":
        heartbeat = read_state(f"beat-{pid}.json")
        stamp = heartbeat.get("at")
        return (heartbeat.get("pid") == pid and heartbeat.get("start") == state["start"]
                and type(stamp) in (int, float) and math.isfinite(stamp)
                and 0 <= time.monotonic() - stamp <= BEAT_MAX_AGE)
    # One-shot management jobs are accepted by their exit status, not HTTP.
    return role == "manage"


def main():
    def timeout(_signal, _frame):
        raise TimeoutError("Health probe deadline")

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(4)
    try:
        healthy = check_health()
    except Exception:
        healthy = False
    finally:
        signal.alarm(0)
    print("healthy" if healthy else "unhealthy")
    return 0 if healthy else 1
