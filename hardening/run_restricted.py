#!/usr/bin/env python3
"""Launch only this fork's offline qualification on the authorized Debian host.

Inputs must already have an external-intake decision for the selected use.
No fetch, deployment, host setup, home mount or engine socket is supported.
"""

import argparse
import os
import re
from pathlib import Path
import subprocess
import sys
import uuid

from operator_config import operator_config
from source_snapshot import stage

IMAGE = "2704858657c97e141cb2934dc6893e46c1094503bd7890536ab6eda295265dd0"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lane", choices=["tools", "python", "database", "integration", "server", "worker"])
    parser.add_argument("--backend-image", help="Exact qualified backend image sha256, for the Python3.12 lane")
    args = parser.parse_args()
    operator = operator_config(parser)
    if args.lane != "tools" and not args.backend_image:
        parser.error("Application lanes require an exact built backend image ID")
    if args.backend_image and not re.fullmatch(r"[0-9a-f]{64}", args.backend_image):
        parser.error("--backend-image requires an exact 64-character image ID")
    if not os.environ.get("SSH_AUTH_SOCK"):
        parser.error("Set the existing dedicated session SSH_AUTH_SOCK; do not provide a passphrase here")
    run_id = "plane-qualification-" + uuid.uuid4().hex[:12]
    config = {
        "id": run_id,
        "image": args.backend_image or IMAGE,
        "root": operator.root,
        "lane": args.lane,
        "python": "/opt/venv/bin/python" if args.backend_image else "/usr/bin/python3",
    }
    ssh_base = operator.ssh
    if args.lane != "tools":
        destination = operator.root + "/snapshots/" + run_id
        config["source_digest"] = stage(Path(__file__).resolve().parents[1], destination, ssh_base)
    remote = Path(__file__).with_name("remote_runner.py").read_text()
    remote += "\nmain(" + repr(config) + ")\n"
    ssh = ssh_base + ["python3 -"]
    result = subprocess.run(ssh, input=remote, text=True, check=False)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
