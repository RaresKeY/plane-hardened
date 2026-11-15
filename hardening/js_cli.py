"""Build/type-check the frozen Bun workspace in its owned restricted Debian container."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
BUN = Path("/tools/bun")


def workspaces():
    result = {}
    config = json.loads((ROOT / "package.json").read_text())["workspaces"]
    excluded = {path for pattern in config["packages"] if pattern.startswith("!") for path in ROOT.glob(pattern[1:])}
    for pattern in config["packages"]:
        if pattern.startswith("!"):
            continue
        for directory in ROOT.glob(pattern):
            if directory in excluded or not (directory / "package.json").is_file():
                continue
            package = json.loads((directory / "package.json").read_text())
            result[package["name"]] = (directory, package)
    return result


def ordered(packages, selected):
    done, active, output = set(), set(), []

    def visit(name):
        if name in done:
            return
        if name in active:
            raise ValueError("Workspace dependency cycle: " + name)
        active.add(name)
        _directory, package = packages[name]
        for kind in ("dependencies", "devDependencies", "peerDependencies"):
            for dependency, version in sorted(package.get(kind, {}).items()):
                if version.startswith("workspace:"):
                    if dependency not in packages:
                        raise ValueError("Unknown workspace dependency: " + dependency)
                    visit(dependency)
        active.remove(name)
        done.add(name)
        output.append(name)

    for name in sorted(selected):
        visit(name)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["build", "types"])
    parser.add_argument("--only", help="Workspace name, including its dependencies")
    parser.add_argument("--from-workspace", help="Resume after previously verified dependencies in the same snapshot")
    args = parser.parse_args()
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if (
        os.getuid() == 0
        or status["NoNewPrivs"].strip() != "1"
        or int(status["CapEff"].strip(), 16)
        or int(status["CapBnd"].strip(), 16)
    ):
        raise RuntimeError("Run only in the prescribed non-root, capless, no-new-privileges container")
    if (ROOT / ".git").exists():
        raise RuntimeError("Use the qualification snapshot, not the owning checkout or its Git credentials")
    env = {
        "PATH": "/tools:/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp/plane",
        "LANG": "C.UTF-8",
        "CI": "1",
        "PLANE_CA_POLICY": str(ROOT / "hardening/trust/policy.json"),
        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
        "SSL_CERT_DIR": "/etc/ssl/certs",
        "BUN_INSTALL_CACHE_DIR": "/tmp/bun-cache",
        "TMPDIR": "/tmp",
        "XDG_CACHE_HOME": "/tmp/cache",
        "API_BASE_URL": "http://api:8000",
        "VITE_API_BASE_URL": "http://api:8000",
        "LIVE_SERVER_SECRET_KEY": "isolated-js-fixture-not-valid-for-production",
        "REDIS_URL": "",
        "CORS_ALLOWED_ORIGINS": "http://fixture.invalid",
        "APP_VERSION": "1.4.3+hardened",
    }
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    packages = workspaces()
    selected = [args.only] if args.only else list(packages)
    if any(name not in packages for name in selected):
        parser.error("Unknown workspace name")
    results = []

    def execute(name, directory, module, arguments):
        command = [
            str(BUN),
            "--no-install",
            "--no-macros",
            "--use-openssl-ca",
            "--preload",
            str(ROOT / "hardening/tls_policy.ts"),
            str(module),
            *arguments,
        ]
        print(json.dumps({"workspace": name, "command": command}), flush=True)
        started = time.monotonic()
        result = subprocess.run(command, cwd=directory, env=env, check=False, timeout=600)
        row = {"workspace": name, "exit_code": result.returncode, "seconds": round(time.monotonic() - started, 2)}
        results.append(row)
        print(json.dumps(row), flush=True)
        if result.returncode:
            raise RuntimeError("Workspace qualification failed: " + name)

    def tool(directory, name, executable):
        package_root = directory / "node_modules" / name
        if name == "typescript" and not (package_root / "package.json").is_file():
            # Isolated Bun installs do not hoist the compiler into every workspace.
            # Use the editor's same globally pinned compiler, without fetching a tool.
            package_root = ROOT / "packages/editor/node_modules/typescript"
        config = json.loads((package_root / "package.json").read_text())
        binary = config["bin"]
        relative = binary if isinstance(binary, str) else binary[executable]
        path = (package_root / relative).resolve()
        if not path.is_relative_to(ROOT):
            raise ValueError("Review tool path escaping the owned workspace")
        return path

    try:
        sequence = ordered(packages, selected)
        if args.from_workspace:
            if args.from_workspace not in sequence:
                parser.error("Resume workspace is outside the selected dependency closure")
            sequence = sequence[sequence.index(args.from_workspace) :]
        for name in sequence:
            directory, package = packages[name]
            if name == "@plane/i18n":
                execute(name + ":generate-types", directory, directory / "scripts/generate-types.ts", [])
            if args.action == "types":
                if not (directory / "tsconfig.json").is_file():
                    continue
                if directory.parent.name == "apps" and name in ("web", "admin", "space"):
                    execute(
                        name + ":route-types",
                        directory,
                        tool(directory, "@react-router/dev", "react-router"),
                        ["typegen"],
                    )
                execute(
                    name + ":types",
                    directory,
                    tool(directory, "typescript", "tsc"),
                    [
                        "--noEmit",
                        "--incremental",
                        "true",
                        "--tsBuildInfoFile",
                        "/tmp/tsbuild-" + hashlib.sha256(name.encode()).hexdigest()[:12] + ".tsbuildinfo",
                    ],
                )
                continue
            if "build" not in package.get("scripts", {}):
                continue
            if name in ("@plane/editor", "live"):
                execute(
                    name + ":types",
                    directory,
                    tool(directory, "typescript", "tsc"),
                    [
                        "--noEmit",
                        "--incremental",
                        "true",
                        "--tsBuildInfoFile",
                        "/tmp/tsbuild-" + hashlib.sha256(name.encode()).hexdigest()[:12] + ".tsbuildinfo",
                    ],
                )
            if directory.parent.name == "apps" and name in ("web", "admin", "space"):
                execute(name, directory, tool(directory, "@react-router/dev", "react-router"), ["build"])
            else:
                execute(name, directory, tool(directory, "tsdown", "tsdown"), [])
    finally:
        (ROOT / "qualification-build-results.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
