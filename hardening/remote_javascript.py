"""Owned offline JavaScript qualification; receives only reviewed source/input identities."""

import hashlib
import json
import os
from pathlib import Path
import subprocess


def main(cfg, dependencies):
    root = Path(cfg["root"])
    source = root / "snapshots" / cfg["id"]
    original = json.loads(source.with_suffix(".manifest.json").read_text())
    assert hashlib.sha256(json.dumps(original, sort_keys=True).encode()).hexdigest() == cfg["source_digest"]
    staged = Path(cfg["dependencies"])
    assert not staged.is_symlink()
    assert hashlib.sha256((staged / "bun.lock").read_bytes()).hexdigest() == cfg["lock_sha256"]
    out = root / "runs" / cfg["id"]
    out.mkdir(mode=0o700)
    (out / "run-inputs.json").write_text(json.dumps(cfg, indent=2))

    def verify_source():
        for name, digest in original.items():
            path = source / name
            data = ("SYMLINK:" + os.readlink(path)).encode() if path.is_symlink() else path.read_bytes()
            assert hashlib.sha256(data).hexdigest() == digest, "Build modified tracked source: " + name

    verify_source()
    # Copy only dependency directories. Reflinks are independent writable copies;
    # never link a build's writable files back into the screened intake directory.
    for directory, dirs, _files in os.walk(staged):
        if "node_modules" in dirs:
            candidate = Path(directory) / "node_modules"
            relative = candidate.relative_to(staged)
            assert len(relative.parts) == 1 or (len(relative.parts) == 3 and relative.parts[0] in {"apps", "packages"})
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["cp", "-a", "--reflink=auto", str(candidate), str(target)], check=True)
            dirs.remove("node_modules")
    assert len(dependencies["files"]) < 200000 and len(dependencies["links"]) < 20000
    for row in dependencies["files"]:
        path = source / row["path"]
        assert "node_modules" in Path(row["path"]).parts and path.resolve().is_relative_to(source)
        assert path.is_file() and not path.is_symlink()
        assert path.stat().st_size == row["size"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"], row["path"]
    for row in dependencies["links"]:
        path = source / row["path"]
        assert not row["escapes"] and path.is_symlink() and os.readlink(path) == row["target"]
        assert path.resolve().is_relative_to(source), row["path"]
    verify_source()
    results = []

    def execute(label, program, arguments, network="none", extra=None):
        name = cfg["id"] + "-" + label
        command = [
            "podman",
            "create",
            "--name",
            name,
            "--label",
            "io.rareskey.project=plane-hardened",
            "--label",
            "io.rareskey.retention=ephemeral",
            "--userns=keep-id:uid=1000,gid=1000",
            "--user=1000:1000",
            "--network=" + network,
            "--read-only",
            "--no-healthcheck",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--cpus=2",
            "--memory=6g",
            "--pids-limit=256",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=2g",
            "--workdir=/work",
            "--volume",
            str(source) + ":/work:rw",
            "--volume",
            str(out) + ":/out:rw",
            "--volume",
            str(root / "tools") + ":/tools:ro",
        ]
        env = {
            "HOME": "/tmp",
            "CI": "1",
            "PLANE_CA_POLICY": "/work/hardening/trust/policy.json",
            "API_BASE_URL": "http://api:8000",
            "LIVE_SERVER_SECRET_KEY": "synthetic-live-key-not-for-production",
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "http_proxy": "",
            "https_proxy": "",
            **(extra or {}),
        }
        for key, value in env.items():
            command += ["--env", key + "=" + value]
        command += ["--entrypoint=" + program, cfg["image"], *arguments]
        created = False
        try:
            subprocess.run(command, capture_output=True, check=True)
            created = True
            info = json.loads(subprocess.check_output(["podman", "inspect", name]))[0]
            host = info["HostConfig"]
            assert info["Config"]["User"] == "1000:1000" and host["ReadonlyRootfs"]
            assert not host.get("CapAdd") and host["CapDrop"]
            assert not info.get("EffectiveCaps")
            if network == "none":
                assert host["NetworkMode"] == "none"
            else:
                assert set(info["NetworkSettings"]["Networks"]) == {network}
            assert "no-new-privileges" in host["SecurityOpt"] and not host.get("PortBindings")
            assert host["Memory"] == 6 * 1024**3 and host["PidsLimit"] == 256
            assert all(m["Source"].startswith(str(root) + "/") for m in info["Mounts"] if m["Type"] == "bind")
            (out / (label + "-isolation.json")).write_text(json.dumps(info, indent=2))
            with (out / (label + ".log")).open("w") as log:
                result = subprocess.run(
                    ["podman", "start", "--attach", name], stdout=log, stderr=subprocess.STDOUT, timeout=1800
                )
            row = {"label": label, "command": command, "exit_code": result.returncode}
            results.append(row)
            (out / "results.json").write_text(json.dumps(results, indent=2))
            print(json.dumps({"phase": label, "exit_code": result.returncode, "evidence": str(out)}), flush=True)
            verify_source()
            if result.returncode:
                print((out / (label + ".log")).read_text()[-4000:], flush=True)
                raise RuntimeError("JavaScript qualification failed: " + label)
        finally:
            if created:
                subprocess.run(["podman", "rm", "--force", name], capture_output=True)

    execute("build", "/usr/local/bin/python3", ["/work/hardening/js_cli.py", "build"])
    if cfg["action"] in {"types", "all"}:
        execute("types", "/usr/local/bin/python3", ["/work/hardening/js_cli.py", "types"])
    if cfg["action"] not in {"test", "all"}:
        return
    flags = ["--no-install", "--no-macros", "--use-openssl-ca", "--preload", "/work/hardening/tls_policy.ts"]
    maintained = json.loads((source / "hardening/js-maintained-files.json").read_text())
    assert all(
        not Path(name).is_absolute() and ".." not in Path(name).parts and (source / name).is_file()
        for name in maintained
    )
    execute("format", "/tools/bun", [*flags, "/work/node_modules/oxfmt/bin/oxfmt", "--check", *maintained])
    execute("lint", "/tools/bun", [*flags, "/work/node_modules/oxlint/bin/oxlint", "--max-warnings=0", *maintained])
    for label, app in [("upstream-live", "apps/live"), ("upstream-codemods", "packages/codemods")]:
        execute(
            label,
            "/tools/bun",
            [
                *flags,
                "/work/" + app + "/node_modules/vitest/vitest.mjs",
                "run",
                "--root",
                "/work/" + app,
                "--pool=threads",
                "--maxWorkers=1",
            ],
        )
    execute(
        "unit-pdf",
        "/tools/bun",
        [
            "test",
            *flags,
            "hardening/js_logging.test.ts",
            "hardening/live_errors.test.ts",
            "hardening/pdf_images.test.ts",
            "hardening/pdf_renderer.test.tsx",
        ],
    )
    execute("prototype", "/tools/bun", [*flags, "/work/hardening/test_dependency_patches.ts", "/work", "patched"])
    execute("tls", "/tools/bun", [*flags, "/work/hardening/test_bun_tls.ts"])
    network, cache = cfg["id"] + "-net", cfg["id"] + "-cache"
    subprocess.run(
        ["podman", "network", "create", "--internal", "--label", "io.rareskey.project=plane-hardened", network],
        capture_output=True,
        check=True,
    )
    try:
        cache_command = [
            "podman",
            "run",
            "--detach",
            "--name",
            cache,
            "--label",
            "io.rareskey.project=plane-hardened",
            "--label",
            "io.rareskey.retention=ephemeral",
            "--network=" + network + ":alias=cache",
            "--userns=keep-id:uid=1000,gid=1000",
            "--user=1000:1000",
            "--read-only",
            "--image-volume=ignore",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=512m",
            "--cpus=1",
            "--pids-limit=128",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=64m",
            "--workdir=/tmp",
            "--entrypoint=valkey-server",
            "8b4ec7a03956151ffb8395a2e2fdcab32754a42548b37d209fe4568b9e44cdaa",
            "--bind",
            "0.0.0.0",
            "--save",
            "",
            "--appendonly",
            "no",
            "--requirepass",
            "isolated-live-fixture",
            "--maxmemory",
            "256mb",
            "--maxmemory-policy",
            "noeviction",
        ]
        subprocess.run(cache_command, capture_output=True, check=True)
        (out / "cache-isolation.json").write_bytes(subprocess.check_output(["podman", "inspect", cache]))
        inspected = json.loads(subprocess.check_output(["podman", "network", "inspect", network]))
        assert inspected[0]["internal"]
        (out / "network-isolation.json").write_text(json.dumps(inspected, indent=2))
        execute(
            "live-http",
            "/tools/bun",
            ["test", *flags, "hardening/live_http.test.ts"],
            network,
            {"PLANE_TEST_REDIS_URL": "redis://:isolated-live-fixture@cache:6379/0"},
        )
    finally:
        subprocess.run(["podman", "rm", "--force", cache], capture_output=True)
        subprocess.run(["podman", "network", "rm", network], capture_output=True)
