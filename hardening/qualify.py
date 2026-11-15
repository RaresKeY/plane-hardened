#!/usr/bin/env python3
"""Run focused qualification entirely offline inside the restricted runner."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

OUT = Path("/out")
SOURCE = Path("/src")
WHEELS = Path("/wheels")


def run(name, command, *, env, cwd=SOURCE, timeout=600):
    start = time.monotonic()
    with (OUT / (name + ".log")).open("w") as log:
        try:
            result = subprocess.run(
                command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=False
            )
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
    row = {"name": name, "exit_code": code, "seconds": round(time.monotonic() - start, 2), "log": name + ".log"}
    print(json.dumps(row), flush=True)
    return row


def main():
    assert os.getuid() != 0
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    assert int(status["CapEff"].strip(), 16) == 0 and int(status["CapBnd"].strip(), 16) == 0
    assert status["NoNewPrivs"].strip() == "1"
    OUT.mkdir(exist_ok=True)
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "PIP_CONFIG_FILE": "/dev/null",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "DJANGO_SETTINGS_MODULE": "plane.settings.test",
        "REDIS_URL": os.environ.get("PLANE_TEST_REDIS_URL", "redis://127.0.0.1:6379/0"),
        "AMQP_URL": "memory://",
        "DATABASE_URL": os.environ.get("PLANE_TEST_DATABASE_URL", "postgresql://fixture:fixture@127.0.0.1:5432/plane"),
        "SECRET_KEY": "isolated-test-fixture-only-with-no-production-validity",
        "WEB_URL": "http://localhost:3000",
        "AWS_EC2_METADATA_DISABLED": "true",
        "HYPOTHESIS_STORAGE_DIRECTORY": "/tmp/hypothesis",
        "XDG_CACHE_HOME": "/tmp/cache",
        "RUFF_CACHE_DIR": "/tmp/ruff-cache",
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    }
    venv = OUT / "venv"
    if not (venv / "bin/python").exists():
        subprocess.run([sys.executable, "-I", "-m", "venv", "--without-pip", str(venv)], check=True, env=env)
    python = str(venv / "bin/python")
    pip = next(WHEELS.glob("pip-26.3-*.whl"))
    bootstrap = "import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pip',run_name='__main__')"
    checks = [run("native-codecs", ["/tools/bun", "/src/hardening/native_codecs.ts"], env=env)]
    install = [
        python,
        "-I",
        "-c",
        bootstrap,
        str(pip),
        "install",
        "--no-index",
        "--find-links=/wheels",
        "--require-hashes",
        "--only-binary=:all:",
        "-r",
        f"/src/hardening/qualification-py{sys.version_info.major}{sys.version_info.minor}.lock",
    ]
    checks.append(run("install", install, env=env))
    if checks[-1]["exit_code"] == 0:
        checks.append(run("dependency-consistency", [python, "-I", "-m", "pip", "check"], env=env))
        probe = (
            "import sys,runpy;sys.path.insert(0,'/src/apps/api');"
            "runpy.run_path('/src/hardening/logging_control.py',run_name='__main__')"
        )
        checks.append(run("logging-positive-control", [python, "-c", probe], env=env))
        checks.append(run("operator-routing", [python, "-m", "unittest", "-v", "test_operator_config"],
                          cwd=SOURCE / "hardening", env=env))
        tests = [
            "plane/tests/unit/utils/test_request_logging.py",
            "plane/tests/unit/utils/test_redis_tls.py",
            "plane/tests/unit/utils/test_redis_tls_native.py",
            "plane/tests/unit/utils/test_http_timeouts.py",
            "plane/tests/unit/utils/test_html_hardening.py",
            "plane/tests/unit/utils/test_xml_dependency_safety.py",
            "plane/tests/unit/utils/test_url_control_characters.py",
            "plane/tests/unit/utils/test_xlsx_export_sanitization.py",
            "plane/tests/unit/utils/test_csv_export_sanitization.py",
            "plane/tests/unit/middleware/test_logger.py",
            "plane/tests/unit/middleware/test_hardening_logging.py",
            "plane/tests/unit/bg_tasks/test_url_security.py",
            "plane/tests/unit/bg_tasks/test_ssrf_advisories.py",
        ]
        pytest = [
            python,
            "-m",
            "pytest",
            *tests,
            "-o",
            "addopts=--strict-markers --nomigrations",
            "-q",
            "--junitxml=/out/focused.xml",
            "-o",
            "cache_dir=/tmp/pytest-cache",
        ]
        # A fast changed/related subset avoids rerunning migrations to diagnose
        # pure HTML/spreadsheet changes; the database lane still runs everything.
        if os.environ.get("PLANE_TEST_DATABASE_URL"):
            migration = [python, "manage.py", "migrate", "--noinput"]
            checks.append(run("migrations", migration, cwd=SOURCE / "apps/api", env=env))
            unit = [
                python,
                "-m",
                "pytest",
                "plane/tests" if os.environ.get("PLANE_TEST_FULL_API") else "plane/tests/unit",
                "-o",
                "addopts=--strict-markers --nomigrations",
                "-q",
                "--junitxml=/out/upstream-unit.xml",
                "-o",
                "cache_dir=/tmp/pytest-cache",
                "-o",
                "faulthandler_timeout=60",
                "--maxfail=10",
            ]
            checks.append(run("upstream-unit", unit, cwd=SOURCE / "apps/api", env=env))
        else:
            pytest.extend(["-m", "not django_db"])
        checks.append(run("focused", pytest, cwd=SOURCE / "apps/api", env=env))
        trust = [
            python,
            "-m",
            "pytest",
            "/src/hardening/trust/test_trust_policy.py",
            "-q",
            "-o",
            "cache_dir=/tmp/pytest-cache",
            "--junitxml=/out/trust.xml",
        ]
        checks.append(run("trust-policy", trust, cwd=SOURCE / "apps/api", env=env))
        compression = [
            python,
            "-m",
            "pytest",
            "/src/hardening/test_compression_bounds.py",
            "/src/hardening/test_http_framing.py",
            "/src/hardening/test_native_zlib.py",
            "/src/hardening/test_finding_gate.py",
            "/src/hardening/test_source_snapshot.py",
            "-q",
            "-o",
            "cache_dir=/tmp/pytest-cache",
            "--junitxml=/out/compression.xml",
        ]
        checks.append(run("compression-bounds", compression, cwd=SOURCE / "apps/api", env=env))

        sbom = [
            "/tools/syft",
            "dir:/out/venv",
            "-o",
            "syft-json=/out/python-sbom.json",
            "-o",
            "cyclonedx-json=/out/python-cdx.json",
        ]
        checks.append(run("python-sbom", sbom, env=env))
        trivy = [
            "/tools/trivy",
            "fs",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--offline-scan",
            "--scanners",
            "misconfig,secret",
            "--format",
            "json",
            "--output",
            "/out/trivy-static.json",
            "--cache-dir",
            "/tmp/trivy-cache",
            "/src",
        ]
        checks.append(run("trivy-static", trivy, env=env))
        bandit = [
            python,
            "-I",
            "-m",
            "bandit",
            "-r",
            "apps/api/plane",
            "-x",
            "apps/api/plane/tests",
            "-f",
            "json",
            "-o",
            "/out/bandit.json",
        ]
        bandit_result = run("bandit", bandit, env=env)
        checks.append(bandit_result)
        if bandit_result["exit_code"] in (0, 1):
            review = run("bandit-review", [python, "-I", "/src/hardening/check_bandit.py"], env=env)
            checks.append(review)
            if review["exit_code"] == 0:
                bandit_result["accepted_by_exact_review"] = True
                bandit_result["status"] = "findings retained and exactly reviewed; raw scanner exit preserved"
        changed = [
            "apps/api/plane/utils/request_logging.py",
            "apps/api/plane/utils/redis_tls.py",
            "apps/api/plane/middleware/logger.py",
            "apps/api/plane/bgtasks/logger_task.py",
            "apps/api/plane/utils/xlsx.py",
            "hardening/remote_runner.py",
            "hardening/build_backend.py",
            "hardening/build_patched_wheel.py",
            "hardening/http_framing_patch.py",
            "hardening/probe_http_chunks.py",
            "hardening/test_http_framing.py",
            "hardening/backend_entrypoint.py",
            "hardening/runtime_image.py",
            "hardening/native_inventory.py",
            "hardening/js_cli.py",
            "hardening/run_javascript.py",
            "hardening/remote_javascript.py",
            "hardening/worker_smoke.py",
            "hardening/scan_backend.py",
            "hardening/test_native_zlib.py",
            "hardening/test_finding_gate.py",
            "hardening/test_compression_bounds.py",
            "hardening/qualify.py",
            "hardening/run_restricted.py",
            "hardening/operator_config.py",
            "hardening/test_operator_config.py",
            "hardening/source_snapshot.py",
            "hardening/runtime_smoke.py",
            "hardening/test_source_snapshot.py",
            "hardening/logging_control.py",
            "hardening/check_bandit.py",
        ]
        lint = [str(venv / "bin/ruff"), "check", "--no-cache", "--config", "apps/api/pyproject.toml", *changed]
        checks.append(run("ruff-changes", lint, env=env))
    result = {
        "checks": checks,
        "runtime": sys.version,
        "uid": os.getuid(),
        "network": "internal database network" if os.environ.get("PLANE_TEST_DATABASE_URL") else "none",
        "database_tests": "executed" if os.environ.get("PLANE_TEST_DATABASE_URL") else "not run in offline lane",
    }
    (OUT / "results.json").write_text(json.dumps(result, indent=2))
    return int(any(row["exit_code"] and not row.get("accepted_by_exact_review") for row in checks))


if __name__ == "__main__":
    sys.exit(main())
