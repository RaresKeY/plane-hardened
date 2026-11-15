"""Cross-cutting response-framing and reproducible transport-patch regressions."""

import base64
import csv
import hashlib
import http.client
import io
import json
from pathlib import Path
import zipfile

import pytest
from urllib3.exceptions import ProtocolError

from build_patched_wheel import build
from http_framing_patch import patch_cpython, patch_urllib3
from probe_http_chunks import SocketFixture, observe
from urllib3.response import HTTPResponse

TRANSPORTS = ["stdlib-read", "urllib3-read", "urllib3-stream"]


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.parametrize("size", [b"-1", b"+1", b"0x1", b"1_0", b" 1", b"1 ", b"", b"\xff1"])
def test_non_hex_chunk_is_rejected_before_body_or_unbounded_read(transport, size):
    result = observe(size, transport)
    assert not result["accepted"]
    assert result["unbounded_reads"] == 0


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.parametrize("size", [b"1", b"1;fixture=valid", b"01"])
def test_ordinary_hex_and_extension_controls_still_work(transport, size):
    result = observe(size, transport)
    assert result == {"accepted": True, "first": "A", "unbounded_reads": 0}


def consume(wire, transport):
    fixture = SocketFixture(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + wire)
    original = http.client.HTTPResponse(fixture, method="GET")
    original.begin()
    response = HTTPResponse(
        body=original,
        headers=dict(original.headers.items()),
        status=200,
        original_response=original,
        preload_content=False,
        request_method="GET",
    )
    try:
        if transport == "urllib3-stream":
            return b"".join(response.read_chunked(amt=1))
        target = original if transport == "stdlib-read" else response
        output = []
        while chunk := target.read(1):
            output.append(chunk)
        return b"".join(output)
    finally:
        response.close()


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_multi_chunk_trailer_and_empty_body_controls(transport):
    assert consume(b"1\r\nA\r\n2;extension=valid\r\nBC\r\n0\r\nX-Fixture: ordinary\r\n\r\n", transport) == b"ABC"
    assert consume(b"0\r\n\r\n", transport) == b""


@pytest.mark.parametrize("transport", TRANSPORTS)
@pytest.mark.parametrize("terminator", [b"XY", b"\nX", b"\rX"])
def test_non_crlf_chunk_terminators_are_rejected(transport, terminator):
    with pytest.raises((ProtocolError, http.client.HTTPException, ValueError)):
        consume(b"1\r\nA" + terminator + b"0\r\n\r\n", transport)


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_trailer_stream_has_a_finite_bound(transport):
    with pytest.raises((ProtocolError, http.client.HTTPException, ValueError)):
        consume(b"0\r\n" + b"X-Fixture: " + b"x" * 70000 + b"\r\n\r\n", transport)


def test_urllib3_total_trailer_limit():
    with pytest.raises(ProtocolError, match="maximum total length"):
        consume(b"0\r\n" + (b"X-Fixture: " + b"x" * 1000 + b"\r\n") * 70 + b"\r\n", "urllib3-stream")


def test_invalid_chunk_text_does_not_enter_transport_error():
    secret = b"synthetic-secret-should-not-enter-error"
    with pytest.raises(ProtocolError) as caught:
        consume(secret + b"\r\nignored\r\n", "urllib3-stream")
    assert secret.decode() not in str(caught.value)


@pytest.mark.parametrize("patcher", [patch_cpython, patch_urllib3])
def test_changed_upstream_source_requires_review(patcher):
    with pytest.raises(ValueError, match="Re-review"):
        patcher(b"unreviewed replacement")


def test_requests_version_compatibility_and_private_identity():
    import importlib.metadata
    import warnings
    import requests
    import urllib3
    from urllib3 import _version

    assert importlib.metadata.version("urllib3") == "2.8.0+plane.2"
    assert _version.__plane_revision__ == "2.8.0+plane.2"
    assert urllib3.__version__ == "2.8.0"
    with warnings.catch_warnings():
        warnings.simplefilter("error", requests.exceptions.RequestsDependencyWarning)
        requests.check_compatibility(urllib3.__version__, None, "3.5.2")


def test_private_wheel_is_reproducible_and_every_record_hash_matches(tmp_path):
    original = Path("/wheels/urllib3-2.8.0-py3-none-any.whl")
    first = tmp_path / "first.whl"
    second = tmp_path / "second.whl"
    expected = "c9907ebd38c617f89af7050fa6e26c4409410376d3ff1968787780e82e4dfce3"
    assert build(original, first) == build(original, second) == expected
    with zipfile.ZipFile(first) as archive:
        record = archive.read("urllib3-2.8.0+plane.2.dist-info/RECORD").decode()
        for name, digest, size in csv.reader(io.StringIO(record)):
            if not digest:
                assert name.endswith("/RECORD")
                continue
            content = archive.read(name)
            assert int(size) == len(content)
            actual = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
            assert digest == "sha256=" + actual
        patch = json.loads(archive.read("urllib3/plane_patch.json"))
        assert patch["fork_version"] == "2.8.0+plane.2"
        assert patch["response_source_sha256"] == hashlib.sha256(archive.read("urllib3/response.py")).hexdigest()
        with zipfile.ZipFile(original) as upstream:
            for name in upstream.namelist():
                if "license" in name.lower() and not name.endswith("/"):
                    assert archive.read(
                        name.replace("urllib3-2.8.0.dist-info", "urllib3-2.8.0+plane.2.dist-info")
                    ) == upstream.read(name)
