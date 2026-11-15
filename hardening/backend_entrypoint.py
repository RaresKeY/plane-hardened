"""Explicit API/worker/beat/manage modes; no automatic data or host mutation."""

import os
from pathlib import Path
import sys


def main():
    if os.getuid() == 0:
        raise RuntimeError("The hardened backend must run as a non-root user")
    if len(os.environ.get("SECRET_KEY", "")) < 32:
        raise ValueError("Configure a strong shared SECRET_KEY before starting the hardened backend")
    if not os.environ.get("DATABASE_URL") or not os.environ.get("REDIS_URL"):
        raise ValueError("Configure DATABASE_URL and REDIS_URL before starting the hardened backend")
    # Runtime wrappers may set another working directory; imports must still
    # resolve the immutable application, never a mounted test/output folder.
    os.chdir("/code")
    mode = sys.argv[1] if len(sys.argv) > 1 else "api"
    if mode == "api":
        workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
        port = int(os.environ.get("PORT", "8000"))
        if not 1 <= workers <= 16 or not 1024 <= port <= 65535:
            raise ValueError("Backend worker or port setting out of allowed bounds")
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
        command = ["celery", "-A", "plane", "worker", "--loglevel=info", "--concurrency=2"]
    elif mode == "beat":
        command = ["celery", "-A", "plane", "beat", "--loglevel=info", "--pidfile=/tmp/celerybeat.pid"]
    elif mode == "manage":
        command = [sys.executable, str(Path("/code/manage.py")), *sys.argv[2:]]
    else:
        raise ValueError("Unknown backend mode")
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
