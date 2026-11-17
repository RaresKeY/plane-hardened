"""Explicit API/worker/beat/manage modes; no automatic data or host mutation."""

import os
from pathlib import Path
import socket
import sys

from runtime_health import main as health_main, register_runtime

LEGACY_MODES = {
    "./bin/docker-entrypoint-api.sh": ["api"],
    "./bin/docker-entrypoint-worker.sh": ["worker"],
    "./bin/docker-entrypoint-beat.sh": ["beat"],
    "./bin/docker-entrypoint-migrator.sh": ["manage", "migrate", "--noinput"],
}


def mode_arguments(arguments):
    arguments = list(arguments) or ["api"]
    if arguments[0] in LEGACY_MODES:
        if len(arguments) != 1:
            raise ValueError("Legacy mode aliases do not accept shell arguments")
        arguments = list(LEGACY_MODES[arguments[0]])
    if arguments[0] not in {"api", "worker", "beat", "manage", "health"}:
        raise ValueError("Unknown backend mode")
    if arguments[0] != "manage" and len(arguments) != 1:
        raise ValueError("Configure this mode through its documented environment settings")
    return arguments


def main():
    if os.getuid() == 0:
        raise RuntimeError("The hardened backend must run as a non-root user")
    arguments = mode_arguments(sys.argv[1:])
    if arguments[0] == "health":
        # Python starts this script beside the helper, outside the application
        # tree. Worker RPC imports must resolve the immutable image's API code.
        sys.path.insert(0, "/code")
        return health_main()
    if len(os.environ.get("SECRET_KEY", "")) < 32:
        raise ValueError("Configure a strong shared SECRET_KEY before starting the hardened backend")
    if not os.environ.get("DATABASE_URL") or not os.environ.get("REDIS_URL"):
        raise ValueError("Configure DATABASE_URL and REDIS_URL before starting the hardened backend")
    # Runtime wrappers may set another working directory; imports must still
    # resolve the immutable application, never a mounted test/output folder.
    os.chdir("/code")
    mode = arguments[0]
    if mode == "api":
        workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
        port = int(os.environ.get("PORT", "8000"))
        if not 1 <= workers <= 16 or not 1024 <= port <= 65535:
            raise ValueError("Backend worker or port setting out of allowed bounds")
        register_runtime(mode, port=port)
        # Default access logs contain full request targets; only the minimized
        # application request logger is enabled. No system fingerprint collection.
        command = [
            "gunicorn",
            "plane.asgi:application",
            "-k",
            "uvicorn.workers.UvicornWorker",
            "--workers",
            str(workers),
            "--bind",
            f"0.0.0.0:{port}",
            "--error-logfile",
            "-",
            "--timeout",
            "60",
            "--graceful-timeout",
            "30",
            "--max-requests",
            "1200",
            "--max-requests-jitter",
            "200",
        ]
    elif mode == "worker":
        node = "plane@" + socket.gethostname()
        register_runtime(mode, node=node)
        command = ["celery", "-A", "plane", "worker", "--loglevel=info", "--concurrency=2", "--hostname=" + node]
    elif mode == "beat":
        register_runtime(mode)
        command = ["celery", "-A", "plane", "beat", "--loglevel=info", "--pidfile=/tmp/celerybeat.pid",
                   "--scheduler=plane.utils.celery_health:HeartbeatDatabaseScheduler"]
    elif mode == "manage":
        register_runtime(mode)
        command = [sys.executable, str(Path("/code/manage.py")), *arguments[1:]]
    else:
        raise ValueError("Unknown backend mode")
    os.execvp(command[0], command)


if __name__ == "__main__":
    sys.exit(main())
