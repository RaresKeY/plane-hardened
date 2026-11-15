"""Offline response-framing controls: no servers, network traffic or large allocations."""

import http.client
import io
import json

from urllib3.response import HTTPResponse
from urllib3.exceptions import ProtocolError


class ObservedStream(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.unbounded_reads = 0

    def read(self, size=-1):
        if size < 0:
            self.unbounded_reads += 1
        return super().read(size)


class SocketFixture:
    def __init__(self, data):
        self.stream = ObservedStream(data)

    def makefile(self, *_args, **_kwargs):
        return self.stream


def observe(size, transport="urllib3-stream"):
    fixture = SocketFixture(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + size + b"\r\nA\r\n0\r\n\r\n")
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
        if transport == "stdlib-read":
            first = original.read(1)
        elif transport == "urllib3-read":
            first = response.read(1)
        else:
            first = next(response.read_chunked(amt=1))
        return {"accepted": True, "first": first.decode("ascii"), "unbounded_reads": fixture.stream.unbounded_reads}
    except (ProtocolError, StopIteration, http.client.IncompleteRead):
        return {"accepted": False, "unbounded_reads": fixture.stream.unbounded_reads}
    finally:
        response.close()


if __name__ == "__main__":
    print(
        json.dumps(
            {
                transport: {
                    size.decode(): observe(size, transport)
                    for size in [b"1", b"1;fixture=valid", b"-1", b"+1", b"0x1", b"1_0"]
                }
                for transport in ["urllib3-stream", "urllib3-read", "stdlib-read"]
            }
        )
    )
