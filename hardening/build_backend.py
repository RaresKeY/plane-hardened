#!/usr/bin/env python3
"""Stage qualified inputs and build the fork backend offline on the qualified Debian host."""

import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path

import subprocess
import tarfile
import tempfile
import uuid

from operator_config import operator_config
from source_snapshot import source_name, source_path

REPO = Path(__file__).resolve().parents[1]


def api_sources(repo, names):
    sources = {}
    total = 0
    for name in sorted(set(filter(None, names))):
        relative = source_name(name)
        if not relative.is_relative_to("apps/api"):
            raise ValueError("API build path is outside the API source tree")
        path = source_path(repo, relative)
        if path.is_file():
            size = path.stat().st_size
            total += size
            if size > 100 * 1024**2 or total > 512 * 1024**2:
                raise ValueError("API source exceeds reviewed build size bounds")
            sources["api/" + str(relative.relative_to("apps/api"))] = path
    return sources


def verify_build_inputs(root, manifest):
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("Build inputs must not contain symlinks")
        if path.is_file():
            actual.add(str(path.relative_to(root)))
    if actual != set(manifest):
        raise ValueError("Extracted build inputs differ from the reviewed manifest")
    for name, digest in manifest.items():
        path = root / name
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("Build input escapes the reviewed context")
        with path.open("rb") as handle:
            if hashlib.file_digest(handle, "sha256").hexdigest() != digest:
                raise ValueError("Build input changed after intake or source staging")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheels", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--zlib-deb", type=Path, required=True, help="Intake-qualified Debian13 zlib security update")
    args = parser.parse_args()
    operator = operator_config(parser)
    ssh = operator.ssh
    if not os.environ.get("SSH_AUTH_SOCK"):
        parser.error("Reuse the dedicated session agent; no passphrase accepted here")
    entries = json.loads(args.manifest.read_text())
    sources = {
        "Dockerfile": REPO / "hardening/backend.Dockerfile",
        "backend_entrypoint.py": REPO / "hardening/backend_entrypoint.py",
        "runtime_health.py": REPO / "apps/api/plane/utils/runtime_health.py",
        "runtime_image.py": REPO / "hardening/runtime_image.py",
        "http_framing_patch.py": REPO / "hardening/http_framing_patch.py",
        "production-py312.lock": REPO / "hardening/production-py312.lock",
        "trust_policy.py": REPO / "hardening/trust/trust_policy.py",
        "policy.json": REPO / "hardening/trust/policy.json",
        "LICENSE.txt": REPO / "LICENSE.txt",
    }
    sources = {name: source_path(REPO, path.relative_to(REPO)) for name, path in sources.items()}
    if hashlib.sha256(args.zlib_deb.read_bytes()).hexdigest() != (
        "8c27c342230503b73dfde629642c3b352e87b554e06d60cf58772f236a305ceb"
    ):
        raise ValueError("The qualified Debian13 zlib package changed")
    sources["zlib1g.deb"] = args.zlib_deb
    listed = (
        subprocess.check_output(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "apps/api"], cwd=REPO
        )
        .decode()
        .split("\0")
    )
    sources.update(api_sources(REPO, listed))
    for entry in entries:
        filename = entry["file"]
        if Path(filename).name != filename:
            raise ValueError("Wheel manifest filename must be a basename")
        path = args.wheels / filename
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("Qualified wheel changed: " + filename)
        sources["wheels/" + filename] = path
    # The separately qualified bootstrap wheel is used only in the discarded builder stage.
    bootstrap = args.wheels / "pip-26.3-py3-none-any.whl"
    if (
        hashlib.sha256(bootstrap.read_bytes()).hexdigest()
        != "f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13"
    ):
        raise ValueError("Qualified bootstrap wheel changed")
    sources["wheels/" + bootstrap.name] = bootstrap
    manifest = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(sources.items())}
    if any(path.is_symlink() for path in sources.values()):
        raise ValueError("Build inputs must be regular reviewed files")
    build_id = "backend-build-" + uuid.uuid4().hex[:12]
    destination = operator.root + "/builds/" + build_id
    subprocess.run(ssh + ["mkdir -p " + destination], check=True)
    with tempfile.TemporaryFile() as archive:
        with tarfile.open(fileobj=archive, mode="w") as output:
            for name, path in sources.items():
                output.add(path, arcname=name, recursive=False)
        archive.seek(0)
        subprocess.run(
            ssh + ["tar -xf - -C " + destination + " --no-same-owner --no-same-permissions"], stdin=archive, check=True
        )
    script = r"""import json,subprocess
from pathlib import Path
root=Path(DESTINATION)
verify_build_inputs(root,MANIFEST)
(root/'input-manifest.json').write_text(json.dumps(MANIFEST,indent=2))
command=['flock','-s','/run/user/1000/podman-build-retention.lock',
 'podman','build','--format=docker','--network=none','--pull=never','--cap-drop=ALL',
 '--security-opt=no-new-privileges','--memory=4g','--cpu-period=100000','--cpu-quota=200000',
 '--layer-label','io.rareskey.retention=ephemeral','--layer-label','io.rareskey.project=plane-hardened',
 '--label','io.rareskey.retention=ephemeral','--label','io.rareskey.project=plane-hardened',
 '--label','io.rareskey.purpose=backend-qualification','--iidfile',str(root/'image.id'),
 '--tag','localhost/plane-hardened-backend:'+root.name,str(root)]
with (root/'build.log').open('w') as log:
 result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=1200,check=False)
print((root/'build.log').read_text()[-7000:])
print(json.dumps({'build':str(root),'exit_code':result.returncode,
                 'image':(root/'image.id').read_text().strip() if (root/'image.id').exists() else None}))
raise SystemExit(result.returncode)
"""
    script = "\n".join(("import hashlib", "DESTINATION=" + repr(destination), "MANIFEST=" + repr(manifest),
                         inspect.getsource(verify_build_inputs), script))
    subprocess.run(ssh + ["python3 -"], input=script, text=True, check=True)


if __name__ == "__main__":
    main()
