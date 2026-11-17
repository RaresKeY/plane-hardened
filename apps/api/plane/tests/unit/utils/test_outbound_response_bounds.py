"""Remote bodies must be bounded before Requests can buffer/decompress them."""

from contextlib import contextmanager
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import threading
from unittest.mock import Mock
import zlib

import pytest
import requests

from plane.utils import url_security


pytestmark = pytest.mark.unit
LIMIT = 2 * 1024 * 1024


@contextmanager
def local_response(body, *, headers=None, status=200):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/fixture"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def fetch(url, **kwargs):
    return url_security.pinned_fetch(
        "GET", url, allowed_ips=[ipaddress.ip_network("127.0.0.1/32")], timeout=2, **kwargs
    )


@pytest.mark.parametrize("encoding", [None, "gzip", "deflate"])
def test_default_cap_rejects_large_decoded_response_with_real_requests(encoding):
    body = b"x" * (LIMIT + 1)
    headers = {}
    if encoding:
        body = gzip.compress(body) if encoding == "gzip" else zlib.compress(body)
        headers["Content-Encoding"] = encoding
        headers["Content-Length"] = str(len(body))
    with local_response(body, headers=headers) as url:
        with pytest.raises(requests.RequestException, match="response exceeds size limit"):
            fetch(url)


@pytest.mark.parametrize("body", [b"", b"x" * LIMIT])
def test_empty_and_exact_limit_bodies_remain_usable(body):
    with local_response(body) as url:
        response = fetch(url)
        assert response.status_code == 200 and response.content == body
        assert response.raw.closed


def test_normal_text_json_encoding_and_repeated_content_access_are_preserved():
    body = '{"label":"caf\u00e9"}'.encode("utf-8")
    with local_response(body, headers={"Content-Type": "application/json; charset=utf-8"}) as url:
        response = fetch(url)
        assert response.json() == {"label": "caf\u00e9"}
        assert response.text == body.decode("utf-8")
        assert b"".join(response.iter_content(chunk_size=3)) == body
        assert response.content == body


def test_valid_compressed_body_is_decoded_and_preserved():
    body = gzip.compress(b"ordinary content")
    with local_response(body, headers={"Content-Encoding": "gzip", "Content-Length": str(len(body))}) as url:
        response = fetch(url)
        assert response.content == b"ordinary content"


def test_chunked_body_is_bounded_without_content_length():
    body = b"x" * (LIMIT + 1)
    wire = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    with local_response(wire, headers={"Transfer-Encoding": "chunked"}) as url:
        with pytest.raises(requests.RequestException, match="response exceeds size limit"):
            fetch(url)


@pytest.mark.parametrize("stream", [False, True])
def test_transport_is_always_streamed_and_resources_close_at_the_right_time(monkeypatch, stream):
    response = requests.Response()
    response.iter_content = Mock(return_value=iter([b"normal", b" body"]))
    response.close = Mock()
    close = response.close
    session = Mock()
    session.request.return_value = response
    monkeypatch.setattr(url_security, "resolve_and_validate", Mock(return_value=["93.184.216.34"]))
    monkeypatch.setattr(url_security.requests, "Session", Mock(return_value=session))
    actual = url_security.pinned_fetch("GET", "https://fixture.invalid/", stream=stream)
    assert actual is response
    assert session.request.call_args.kwargs["stream"] is True
    if stream:
        response.iter_content.assert_not_called()
        session.close.assert_not_called()
        actual.close()
    else:
        assert actual.content == b"normal body"
    session.close.assert_called_once()
    close.assert_called_once()


def test_overflow_stops_reading_closes_response_and_does_not_retry_other_addresses(monkeypatch):
    read = []

    def chunks(**_kwargs):
        for body in (b"a" * LIMIT, b"x", b"must not be read"):
            read.append(len(body))
            yield body

    response = Mock()
    response.iter_content.side_effect = chunks
    session = Mock()
    session.request.return_value = response
    monkeypatch.setattr(url_security, "resolve_and_validate", Mock(return_value=["93.184.216.34", "93.184.216.35"]))
    monkeypatch.setattr(url_security.requests, "Session", Mock(return_value=session))
    with pytest.raises(requests.RequestException, match="response exceeds size limit"):
        url_security.pinned_fetch("GET", "https://fixture.invalid/private?token=synthetic-secret")
    assert read == [LIMIT, 1]
    response.close.assert_called_once()
    session.close.assert_called_once()
    assert session.request.call_count == 1


def test_read_failure_closes_both_resources(monkeypatch):
    response = Mock()
    response.iter_content.side_effect = requests.ConnectionError("fixture read failure")
    session = Mock()
    session.request.return_value = response
    monkeypatch.setattr(url_security, "resolve_and_validate", Mock(return_value=["93.184.216.34"]))
    monkeypatch.setattr(url_security.requests, "Session", Mock(return_value=session))
    with pytest.raises(requests.ConnectionError):
        url_security.pinned_fetch("GET", "https://fixture.invalid/")
    response.close.assert_called_once()
    session.close.assert_called_once()


def test_redirect_body_cannot_bypass_cap(monkeypatch):
    response = Mock(status_code=302, headers={"Location": "https://next.fixture.invalid/"})
    response.iter_content.return_value = iter([b"x" * (LIMIT + 1)])
    session = Mock()
    session.request.return_value = response
    monkeypatch.setattr(url_security, "resolve_and_validate", Mock(return_value=["93.184.216.34"]))
    monkeypatch.setattr(url_security.requests, "Session", Mock(return_value=session))
    with pytest.raises(requests.RequestException, match="response exceeds size limit"):
        url_security.pinned_fetch_following_redirects("GET", "https://fixture.invalid/")
    assert session.request.call_count == 1


def test_streaming_caller_retains_ownership_of_size_policy():
    with local_response(b"x" * (LIMIT + 1)) as url:
        response = fetch(url, stream=True)
        try:
            assert not response._content_consumed
            assert next(response.iter_content(chunk_size=17)) == b"x" * 17
        finally:
            response.close()
