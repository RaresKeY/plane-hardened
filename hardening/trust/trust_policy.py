#!/usr/bin/env python3
"""Inspect/filter explicit public PEM trust bundles; no application imports or downloads."""

import argparse
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import ssl
import subprocess

ROOT = Path(__file__).resolve().parent
CERTIFICATE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


@lru_cache(maxsize=1024)
def identity(pem):
    der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
    public_key = subprocess.run(
        ["openssl", "x509", "-pubkey", "-noout"], input=pem, capture_output=True, check=True, timeout=10
    ).stdout
    spki = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=public_key,
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout
    return hashlib.sha256(der).hexdigest(), hashlib.sha256(spki).hexdigest()


def load_policy(path=ROOT / "policy.json"):
    policy = json.loads(path.read_text())
    if policy["schema"] != 1:
        raise ValueError("Unsupported trust policy schema")
    for name in ["blocked_spki_sha256", "blocked_certificate_sha256"]:
        values = policy.get(name, {})
        if not isinstance(values, dict) or not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in values):
            raise ValueError("Invalid trust policy identities")
    if not policy["blocked_spki_sha256"]:
        raise ValueError("Empty trust policy")
    return policy


def inspect_bundle(data, policy):
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("Trust bundle exceeds bounded input size")
    certificates = CERTIFICATE.findall(data)
    if not 1 <= len(certificates) <= 1024:
        raise ValueError("Missing or excessive certificate count")
    rows = []
    for certificate in certificates:
        if len(certificate) > 64 * 1024:
            raise ValueError("Certificate exceeds bounded input size")
        digest, spki = identity(certificate)
        reason = policy["blocked_spki_sha256"].get(spki) or policy.get("blocked_certificate_sha256", {}).get(digest)
        rows.append({"certificate_sha256": digest, "spki_sha256": spki, "blocked": bool(reason), "reason": reason})
    return certificates, rows


def filter_bundle(data, policy):
    certificates, rows = inspect_bundle(data, policy)
    retained = [pem for pem, row in zip(certificates, rows) if not row["blocked"]]
    if not retained:
        raise ValueError("Refusing to create an empty trust bundle")
    return b"\n".join(retained) + b"\n", rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--policy", type=Path, default=ROOT / "policy.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    policy = load_policy(args.policy)
    if args.bundle.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Trust bundle exceeds bounded input size")
    data = args.bundle.read_bytes()
    if args.output:
        output, rows = filter_bundle(data, policy)
        with args.output.open("xb") as stream:
            stream.write(output)
    else:
        _, rows = inspect_bundle(data, policy)
    print(json.dumps({"certificates": len(rows), "blocked": sum(row["blocked"] for row in rows), "identities": rows}))
    return 0 if args.output or not any(row["blocked"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
