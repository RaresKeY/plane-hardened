#!/usr/bin/env python3
"""Qualify frozen JavaScript inputs in a restricted remote snapshot, without fetching."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

from operator_config import operator_config
from source_snapshot import stage

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = "6a4fa43e8a2765ab882ef6bb1e72d7c9b0c6727f62bbd64fcd403ee941acd605"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["build", "types", "test", "all"])
    parser.add_argument(
        "--dependencies", required=True, help="Exact intake-qualified dependency root on the reviewed host"
    )
    parser.add_argument("--manifest", required=True, type=Path, help="Intake-qualified dependency file/link manifest")
    parser.add_argument("--image", required=True, help="Exact qualified backend image SHA256, supplying filtered trust")
    args = parser.parse_args()
    operator = operator_config(parser)
    if not re.fullmatch(r"[0-9a-f]{64}", args.image):
        parser.error("Use an exact qualified image ID")
    try:
        args.dependencies = operator.dependency_directory(args.dependencies)
    except ValueError as error:
        parser.error(str(error))
    if not os.environ.get("SSH_AUTH_SOCK"):
        parser.error("Reuse the dedicated session SSH agent")
    raw = args.manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != DEPENDENCIES:
        parser.error("Dependency manifest changed: complete intake and update the reviewed identity before activation")
    manifest = json.loads(raw)
    identity = "plane-js-" + uuid.uuid4().hex[:12]
    ssh = operator.ssh
    config = {
        "id": identity,
        "root": operator.root,
        "image": args.image,
        "action": args.action,
        "dependencies": args.dependencies,
        "lock_sha256": hashlib.sha256((ROOT / "bun.lock").read_bytes()).hexdigest(),
        "source_digest": stage(ROOT, operator.root + "/snapshots/" + identity, ssh),
    }
    program = Path(__file__).with_name("remote_javascript.py").read_text()
    program += "\nmain(" + repr(config) + ", " + repr(manifest) + ")\n"
    subprocess.run(ssh + ["python3 -"], input=program, text=True, check=True)


if __name__ == "__main__":
    main()
