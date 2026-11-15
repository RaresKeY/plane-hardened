"""Inventory selected effective native dependencies inside the candidate, without network."""

import ctypes
import ctypes.util
import importlib.util
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import pyexpat
import shutil
import sqlite3
import ssl
import sys
import subprocess
import zlib


def shared_version(library, function):
    name = ctypes.util.find_library(library)
    if not name:
        return {"status": "not found"}
    handle = ctypes.CDLL(name)
    getter = getattr(handle, function)
    getter.restype = ctypes.c_char_p
    getter.argtypes = []
    return {"library": name, "version": getter().decode()}


def main():
    from cryptography.hazmat.backends.openssl.backend import backend
    import grpc
    import urllib3

    etree = None
    if importlib.util.find_spec("lxml") is not None:
        from lxml import etree
    import psycopg

    result = {
        "isolation": {
            key: value.strip()
            for key, value in (
                line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line
            )
            if key in {"NoNewPrivs", "CapEff", "CapBnd"}
        },
        "locale_environment": {key: os.environ.get(key) for key in ["LANG", "LC_ALL", "LANGUAGE"]},
        "selected_programs": {
            name: shutil.which(name)
            for name in [
                "systemd",
                "nscd",
                "bzip2recover",
                "dpkg-source",
                "apt-key",
                "infocmp",
                "perl",
                "mount",
                "nsenter",
                "getfacl",
                "setfacl",
                "getfattr",
                "setfattr",
                "chfn",
                "chsh",
                "login",
                "gcc",
                "g++",
                "ssh",
                "sshd",
            ]
        },
        "affected_component_files": {
            path: Path(path).exists()
            for path in [
                "/usr/lib/systemd/systemd-homed",
                "/usr/lib/systemd/systemd-oomd",
                "/usr/lib/systemd/systemd-journald",
                "/usr/sbin/nscd",
                "/usr/bin/bzip2recover",
                "/usr/bin/dpkg-source",
                "/usr/bin/apt-key",
            ]
        },
        "python": sys.version,
        "libc": platform.libc_ver(),
        "ssl": ssl.OPENSSL_VERSION,
        "cryptography_openssl": backend.openssl_version_text(),
        "sqlite": sqlite3.sqlite_version,
        "expat": pyexpat.EXPAT_VERSION,
        "zlib_compiled": zlib.ZLIB_VERSION,
        "zlib_runtime": zlib.ZLIB_RUNTIME_VERSION,
        "lzma": shared_version("lzma", "lzma_version_string"),
        "bzip2": shared_version("bz2", "BZ2_bzlibVersion"),
        "libxml": etree.LIBXML_VERSION if etree else "not installed",
        "libxslt": etree.LIBXSLT_VERSION if etree else "not installed",
        "grpc": grpc.__version__,
        "urllib3": {"runtime": urllib3.__version__, "distribution": importlib.metadata.version("urllib3")},
        "runtime_patches": json.loads(Path("/opt/plane-hardening/runtime-patches.json").read_text()),
        "libpq": {"version": psycopg.pq.version(), "implementation": psycopg.pq.__impl__},
        "ssh": {name: shutil.which(name) for name in ["ssh", "sshd"]},
        "pip_importable": importlib.util.find_spec("pip") is not None,
        "ensurepip_present": (Path(sys.base_prefix) / "lib/python3.12/ensurepip").exists(),
        "ssl_default_paths": ssl.get_default_verify_paths()._asdict(),
    }
    packages = ["openssl", "libssl3t64", "libc6", "liblzma5", "zlib1g", "libsqlite3-0", "libexpat1"]
    metadata = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}=${Version}\\n", *packages],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    result["distro_package_versions"] = metadata.stdout.splitlines()
    print(json.dumps(result))


if __name__ == "__main__":
    main()
