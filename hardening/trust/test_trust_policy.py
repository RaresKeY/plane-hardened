"""Public incident fixture controls and fail-closed trust-data transformations."""

import hashlib
import json
from pathlib import Path
import ssl

import certifi
import pytest

from trust_policy import CERTIFICATE, ROOT, filter_bundle, identity, inspect_bundle, load_policy


FIXTURES = sorted((ROOT / "fixtures").glob("*.pem"))


def test_public_fixture_catalog_is_complete_and_exact():
    catalog = json.loads((ROOT / "fixtures/catalog.json").read_text())
    assert len(catalog) == 29
    assert {row["file"] for row in catalog} == {path.name for path in FIXTURES}
    for row in catalog:
        data = (ROOT / "fixtures" / row["file"]).read_bytes()
        assert CERTIFICATE.sub(b"", data).strip() == b""
        assert identity(data)[0] == row["sha256"]



@pytest.fixture(scope="module")
def policy():
    return load_policy()


@pytest.fixture(scope="module")
def safe_certificate(policy):
    candidates = CERTIFICATE.findall(Path(certifi.where()).read_bytes())
    for certificate in candidates:
        _, rows = inspect_bundle(certificate, policy)
        if not rows[0]["blocked"]:
            return certificate
    pytest.fail("No usable positive-control certificate")


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda path: path.stem)
def test_every_available_incident_or_conservatively_retired_certificate_is_blocked(fixture, policy):
    _, rows = inspect_bundle(fixture.read_bytes(), policy)
    assert len(rows) == 1 and rows[0]["blocked"], fixture.name


def test_cross_signed_root_is_rejected_by_key_not_only_certificate_fingerprint(policy):
    cross = (ROOT / "fixtures/cross-signed-root-g3.pem").read_bytes()
    digest, spki = identity(cross)
    assert digest not in policy["blocked_certificate_sha256"]
    assert spki in policy["blocked_spki_sha256"]
    assert inspect_bundle(cross, policy)[1][0]["blocked"]


def test_clean_bundle_keeps_a_usable_trusted_certificate(safe_certificate, policy, tmp_path):
    filtered, rows = filter_bundle(safe_certificate, policy)
    assert not any(row["blocked"] for row in rows)
    assert identity(filtered)[0] == identity(safe_certificate)[0]
    cafile = tmp_path / "retained.pem"
    cafile.write_bytes(filtered)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(cafile))
    assert context.cert_store_stats()["x509_ca"] == 1


def test_mixed_bundle_preserves_positive_control_and_removes_all_blocked_keys(safe_certificate, policy):
    incident = b"\n".join(fixture.read_bytes() for fixture in FIXTURES)
    original = safe_certificate + b"\n" + incident
    before = hashlib.sha256(original).digest()
    filtered, rows = filter_bundle(original, policy)
    assert sum(row["blocked"] for row in rows) == len(FIXTURES)
    assert identity(filtered)[0] == identity(safe_certificate)[0]
    assert not any(row["blocked"] for row in inspect_bundle(filtered, policy)[1])
    assert hashlib.sha256(original).digest() == before
    assert filter_bundle(filtered, policy)[0] == filtered


@pytest.mark.parametrize(
    "data", [b"", b"no certificate", b"-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----"]
)
def test_missing_or_malformed_certificates_cannot_produce_success(data, policy):
    with pytest.raises((ValueError, ssl.SSLError)):
        filter_bundle(data, policy)


def test_all_blocked_input_cannot_become_an_empty_successful_trust_store(policy):
    with pytest.raises(ValueError, match="empty trust bundle"):
        filter_bundle(FIXTURES[0].read_bytes(), policy)


@pytest.fixture(scope="module")
def native_stores(policy, tmp_path_factory):
    directory = tmp_path_factory.mktemp("chain-stores")
    control = directory / "affected-control.pem"
    control.write_bytes((ROOT / "fixtures/roots-2.pem").read_bytes() + (ROOT / "fixtures/roots-3.pem").read_bytes())
    selected = directory / "selected.pem"
    selected.write_bytes(filter_bundle(Path(certifi.where()).read_bytes(), policy)[0])
    return control, selected


CHAINS = sorted((ROOT / "chains").rglob("*.pem"))


def test_public_chain_catalog_is_complete_and_exact():
    catalog = json.loads((ROOT / "chains/catalog.json").read_text())["files"]
    assert len(catalog) == 16
    assert {row["file"] for row in catalog} == {str(path.relative_to(ROOT / "chains")) for path in CHAINS}
    for row in catalog:
        assert hashlib.sha256((ROOT / "chains" / row["file"]).read_bytes()).hexdigest() == row["sha256"]



@pytest.mark.parametrize("chain", CHAINS, ids=lambda path: path.stem)
def test_real_incident_chains_are_usable_controls_and_rejected_after_root_filter(chain, native_stores, tmp_path):
    import subprocess

    certificates = CERTIFICATE.findall(chain.read_bytes())
    leaf = tmp_path / "leaf.pem"
    intermediates = tmp_path / "intermediates.pem"
    leaf.write_bytes(certificates[0] + b"\n")
    intermediates.write_bytes(b"\n".join(certificates[1:]) + b"\n")
    control, selected = native_stores
    for store, expected in [(control, 0), (selected, 2)]:
        command = [
            "openssl",
            "verify",
            "-no-CAfile",
            "-no-CApath",
            "-no-CAstore",
            "-CAfile",
            str(store),
            "-purpose",
            "sslserver",
            "-verify_hostname",
            chain.stem,
            "-x509_strict",
            "-partial_chain",
            "-attime",
            "1793491200",
            "-untrusted",
            str(intermediates),
            str(leaf),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        assert result.returncode == expected, result.stdout + result.stderr
