"""Image-only offline dependency installation and explicit trust-data hardening.

Invoked only by hardening/backend.Dockerfile. Never run on a workstation/VPS host.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def install():
    target = Path("/opt/venv")
    subprocess.run([sys.executable, "-I", "-m", "venv", "--without-pip", str(target)], check=True)
    wheels = Path("/wheels")
    pip = next(wheels.glob("pip-26.3-*.whl"))
    bootstrap = "import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pip',run_name='__main__')"
    command = [
        str(target / "bin/python"),
        "-I",
        "-c",
        bootstrap,
        str(pip),
        "install",
        "--no-index",
        "--find-links=/wheels",
        "--require-hashes",
        "--only-binary=:all:",
        "--no-compile",
        "-r",
        "/build/production-py312.lock",
    ]
    subprocess.run(command, check=True, env={**os.environ, "PIP_CONFIG_FILE": "/dev/null"})


def harden():
    import ssl

    from trust_policy import CERTIFICATE, filter_bundle, inspect_bundle, load_policy

    from http_framing_patch import patch_cpython

    client_path = Path("/usr/local/lib/python3.12/http/client.py")
    before = client_path.read_bytes()
    after = patch_cpython(before)
    client_path.write_bytes(after)
    for path in (client_path.parent / "__pycache__").glob("client.*.pyc"):
        path.unlink()
    Path("/opt/plane-hardening/runtime-patches.json").write_text(
        json.dumps(
            {
                "cpython_http_client": {
                    "before": hashlib.sha256(before).hexdigest(),
                    "after": hashlib.sha256(after).hexdigest(),
                },
                "urllib3": "2.8.0+plane.2 hash-pinned locally rebuilt wheel",
                "scope": "Strict response chunk grammar and terminators; urllib3 total trailer cap64KiB",
            },
            indent=2,
        )
    )
    policy = load_policy(Path("/opt/plane-hardening/policy.json"))
    # Runtime packaging is intentionally absent; old ensurepip carries its own
    # obsolete pip/CA payload even when an application venv uses newer wheels.
    library = Path("/usr/local/lib/python3.12")
    for path in (library / "site-packages").glob("pip*"):
        if path.name == "pip" or path.name.startswith("pip-") and path.name.endswith(".dist-info"):
            shutil.rmtree(path)
    shutil.rmtree(library / "ensurepip")
    for path in Path("/usr/local/bin").glob("pip*"):
        if path.name in {"pip", "pip3", "pip3.12"}:
            path.unlink()
    changed = []
    removed = []
    roots = Path("/usr/share/ca-certificates")
    for path in roots.rglob("*.crt"):
        _, rows = inspect_bundle(path.read_bytes(), policy)
        if any(row["blocked"] for row in rows):
            path.unlink()
            removed.append(str(path))
    directory = Path("/etc/ssl/certs")
    for path in directory.iterdir():
        if path.is_symlink() and not path.exists():
            path.unlink()
        elif not path.is_symlink() and path.is_file() and path.name != "ca-certificates.crt":
            data = path.read_bytes()
            if CERTIFICATE.search(data) and all(row["blocked"] for row in inspect_bundle(data, policy)[1]):
                path.unlink()
                removed.append(str(path))
    bundles = [directory / "ca-certificates.crt"]
    for pattern in ["cacert.pem", "roots.pem", "ca-bundle.crt"]:
        bundles.extend(Path("/opt/venv").rglob(pattern))
    for path in bundles:
        data = path.read_bytes()
        filtered, rows = filter_bundle(data, policy)
        if data != filtered:
            path.write_bytes(filtered)
        changed.append({"path": str(path), "certificates": len(rows), "removed": sum(row["blocked"] for row in rows)})
    # Check the actual default file and directory, including hashed aliases.
    defaults = ssl.get_default_verify_paths()
    candidates = [Path(defaults.cafile)] if defaults.cafile else []
    if defaults.capath:
        candidates.extend(path for path in Path(defaults.capath).iterdir() if path.is_file())
    for path in candidates:
        data = path.read_bytes()
        if CERTIFICATE.search(data) and any(row["blocked"] for row in inspect_bundle(data, policy)[1]):
            raise RuntimeError("Blocked key remains in effective system trust: " + str(path))
    result = {"stores": changed, "removed_files": removed, "bootstrap_packaging": "pip/ensurepip removed"}
    Path("/opt/plane-hardening/trust-build.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["install", "harden"])
    parser.add_argument("--image-build", action="store_true", required=True)
    args = parser.parse_args()
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    print(
        json.dumps(
            {
                "build_isolation": {
                    "effective_capabilities": status["CapEff"].strip(),
                    "no_new_privileges": status["NoNewPrivs"].strip(),
                }
            }
        )
    )
    if int(status["CapEff"].strip(), 16) != 0 or status["NoNewPrivs"].strip() != "1":
        raise RuntimeError("Image build must drop capabilities and enable no-new-privileges")
    if args.operation == "install":
        install()
    else:
        harden()


if __name__ == "__main__":
    main()
