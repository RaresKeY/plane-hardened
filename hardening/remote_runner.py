"""Owned rootless qualification lifecycle; launched over SSH by run_restricted.py."""

import json
import os
import pathlib
import subprocess
import sys
import hashlib
import time


def main(cfg):
    root = pathlib.Path(cfg["root"])
    out = root / "runs" / cfg["id"]
    out.mkdir(parents=True, mode=0o700)
    source = root / "snapshots" / cfg["id"]
    if cfg["lane"] in ("python", "database", "integration", "server", "worker"):
        links = {str(path.relative_to(source)): os.readlink(path) for path in source.rglob("*") if path.is_symlink()}
        assert links == {"packages/i18n/locales": "src/locales"}
        manifest = {
            str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in source.rglob("*")
            if p.is_file() and not p.is_symlink()
        }
        manifest.update(
            {name: hashlib.sha256(("SYMLINK:" + target).encode()).hexdigest() for name, target in links.items()}
        )
        expected = json.loads(source.with_suffix(".manifest.json").read_text())
        assert manifest == expected
        assert hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest() == cfg["source_digest"]
        (out / "source-manifest.json").write_text(json.dumps(manifest, sort_keys=True))
    command = [
        "podman",
        "create",
        "--interactive",
        "--name",
        cfg["id"],
        "--label",
        "io.rareskey.project=plane-hardened",
        "--label",
        "io.rareskey.purpose=qualification",
        "--label",
        "io.rareskey.retention=ephemeral",
        "--userns=keep-id:uid=1000,gid=1000",
        "--user=1000:1000",
        "--network=none",
        "--read-only",
        "--no-healthcheck",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=256",
        "--cpus=2",
        "--memory=4g",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=1g",
        "--tmpfs",
        "/home/dev:rw,nosuid,nodev,size=16m",
        "--env",
        "HOME=/tmp",
        "--env",
        "HTTP_PROXY=",
        "--env",
        "HTTPS_PROXY=",
        "--env",
        "http_proxy=",
        "--env",
        "https_proxy=",
        "--env",
        "XDG_CONFIG_HOME=/tmp/config",
        "--env",
        "XDG_CACHE_HOME=/tmp/cache",
        "--workdir=/tmp",
        "--volume",
        str(root / "tools") + ":/tools:ro",
        "--volume",
        str(out) + ":/out:rw",
    ]
    if cfg["lane"] in ("python", "database", "integration", "server", "worker"):
        if cfg["lane"] in ("database", "integration", "server", "worker"):
            command[command.index("--network=none")] = "--network=" + cfg["id"] + "-net"
            command += [
                "--env",
                "PLANE_TEST_DATABASE_URL=postgresql://plane_fixture:isolated-synthetic-password@postgres:5432/plane",
            ]
        command += ["--volume", str(source) + ":/src:ro", "--volume", str(root / "wheels") + ":/wheels:ro"]
        command += [
            "--entrypoint=" + cfg["python"],
            cfg["image"],
            (
                {"server": "/src/hardening/runtime_smoke.py", "worker": "/src/hardening/worker_smoke.py"}.get(
                    cfg["lane"], "/src/hardening/qualify.py"
                )
            ),
        ]
        script = None
    else:
        command += ["--entrypoint=/usr/bin/python3", cfg["image"], "-I", "-"]
        script = (
            "import subprocess,json,os\nassert os.getuid()!=0\n"
            "for name in ['bun','trivy','syft','grype']:\n"
            " r=subprocess.run(['/tools/'+name,'--version'],capture_output=True,text=True,timeout=30)\n"
            " print(json.dumps({'tool':name,'exit_code':r.returncode,'stdout':r.stdout,"
            "'stderr':r.stderr}),flush=True)\n"
        )
    created = False
    network = None
    pg = None
    cache = None
    try:
        if cfg["lane"] in ("database", "integration", "server", "worker"):
            network = cfg["id"] + "-net"
            subprocess.run(
                ["podman", "network", "create", "--internal", "--label", "io.rareskey.project=plane-hardened", network],
                check=True,
                capture_output=True,
            )
            pg = cfg["id"] + "-postgres"
            pg_command = [
                "podman",
                "run",
                "--detach",
                "--name",
                pg,
                "--label",
                "io.rareskey.project=plane-hardened",
                "--label",
                "io.rareskey.purpose=qualification",
                "--label",
                "io.rareskey.retention=ephemeral",
                "--userns=keep-id:uid=999,gid=999",
                "--user=999:999",
                "--network=" + network + ":alias=postgres",
                "--read-only",
                "--image-volume=ignore",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--memory=1g",
                "--cpus=1",
                "--pids-limit=256",
                "--shm-size=256m",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=2g",
                "--tmpfs",
                "/var/run/postgresql:rw,nosuid,nodev,size=16m,mode=1777",
                "--env",
                "PGDATA=/tmp/pgdata",
                "--env",
                "POSTGRES_USER=plane_fixture",
                "--env",
                "POSTGRES_PASSWORD=isolated-synthetic-password",
                "--env",
                "POSTGRES_DB=plane",
                "--env",
                "POSTGRES_INITDB_ARGS=--auth-local=scram-sha-256 --auth-host=scram-sha-256",
                "4368ffd9b43260bf9794d9c679495b2a2504da70c0af38a0397ec79fa9e1fa98",
                "postgres",
            ]
            launch = subprocess.run(pg_command, capture_output=True, text=True)
            if launch.returncode:
                (out / "database-startup-error.log").write_text(launch.stderr)
                raise RuntimeError(launch.stderr)
            for attempt in range(60):
                ready = subprocess.run(
                    ["podman", "exec", pg, "pg_isready", "-h", "127.0.0.1", "-U", "plane_fixture"], capture_output=True
                )
                if ready.returncode == 0:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("Synthetic PostgreSQL startup failed")
            (out / "database-isolation.json").write_bytes(subprocess.check_output(["podman", "inspect", pg]))
            network_info = json.loads(subprocess.check_output(["podman", "network", "inspect", network]))
            assert network_info[0]["internal"] is True
            (out / "network-isolation.json").write_text(json.dumps(network_info, indent=2))
        if cfg["lane"] in ("integration", "server", "worker"):
            cache = cfg["id"] + "-cache"
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
                "--userns=keep-id:uid=1000,gid=1000",
                "--user=1000:1000",
                "--network=" + network + ":alias=cache",
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
                "isolated-cache-fixture",
                "--maxmemory",
                "256mb",
                "--maxmemory-policy",
                "noeviction",
            ]
            started = subprocess.run(cache_command, capture_output=True, text=True)
            if started.returncode:
                raise RuntimeError(started.stderr)
            command[-3:-3] = [
                "--env",
                "PLANE_TEST_REDIS_URL=redis://:isolated-cache-fixture@cache:6379/0",
                "--env",
                "PLANE_TEST_FULL_API=1",
            ]
            (out / "cache-isolation.json").write_bytes(subprocess.check_output(["podman", "inspect", cache]))
        if cfg["lane"] in ("server", "worker"):
            command[-3:-3] = [
                "--env",
                "DATABASE_URL=postgresql://plane_fixture:isolated-synthetic-password@postgres:5432/plane",
                "--env",
                "REDIS_URL=redis://:isolated-cache-fixture@cache:6379/0",
                "--env",
                "SECRET_KEY=isolated-runtime-fixture-only-not-production-validity",
                "--env",
                "WEB_URL=http://fixture.invalid",
                "--env",
                "AMQP_URL="
                + ("redis://:isolated-cache-fixture@cache:6379/1" if cfg["lane"] == "worker" else "memory://"),
                "--env",
                "AWS_EC2_METADATA_DISABLED=true",
            ]
        subprocess.run(command, check=True, capture_output=True)
        created = True
        info = json.loads(subprocess.check_output(["podman", "inspect", cfg["id"]]))[0]
        (out / "isolation.json").write_text(json.dumps(info, indent=2))
        host = info["HostConfig"]
        assert host["ReadonlyRootfs"] is True
        if cfg["lane"] not in ("database", "integration", "server", "worker"):
            assert host["NetworkMode"] == "none"
        assert info["Config"]["User"] == "1000:1000"
        assert host["CapDrop"] and not host.get("CapAdd") and not host.get("PortBindings")
        assert host["PidsLimit"] == 256 and host["Memory"] == 4 * 1024**3
        assert "no-new-privileges" in host["SecurityOpt"]
        assert all(m["Source"].startswith(str(root) + "/") for m in info["Mounts"] if m["Type"] == "bind")
        try:
            result = subprocess.run(
                ["podman", "start", "--attach", "--interactive", cfg["id"]],
                input=script,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=1200,
            )
            code = result.returncode
            output = result.stdout
        except subprocess.TimeoutExpired as error:
            subprocess.run(["podman", "kill", cfg["id"]], capture_output=True)
            code = 124
            output = str(error)
        (out / "console.log").write_text(output)
        print(output)
        (out / "run.json").write_text(
            json.dumps({"id": cfg["id"], "lane": cfg["lane"], "exit_code": code, "image": cfg["image"]}, indent=2)
        )
        print(json.dumps({"run": cfg["id"], "exit_code": code, "evidence": str(out)}))
        sys.exit(code)
    finally:
        if created:
            subprocess.run(["podman", "rm", "--force", cfg["id"]], capture_output=True)
        if pg:
            logs = subprocess.run(["podman", "logs", pg], capture_output=True)
            (out / "database-console.log").write_bytes(logs.stdout + logs.stderr)
            subprocess.run(["podman", "rm", "--force", pg], capture_output=True)
        if cache:
            logs = subprocess.run(["podman", "logs", cache], capture_output=True)
            (out / "cache-console.log").write_bytes(logs.stdout + logs.stderr)
            subprocess.run(["podman", "rm", "--force", cache], capture_output=True)
        if network:
            subprocess.run(["podman", "network", "rm", network], capture_output=True)
