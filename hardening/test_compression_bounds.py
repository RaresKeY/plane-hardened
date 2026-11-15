"""Bounded native ZIP decompression regression for CVE-2026-15310."""

import io
import zipfile

import pytest


@pytest.mark.parametrize("compression", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
@pytest.mark.parametrize("simulate_unbounded", [False, True])
def test_chunked_read_bounds_native_output(monkeypatch, compression, simulate_unbounded):
    original = b"P" * (16 * 1024 * 1024)
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=compression) as archive:
        archive.writestr("fixture.txt", original)
    factory = zipfile._get_decompressor
    calls = []

    class ObservedDecoder:
        def __init__(self, decoder):
            self.decoder = decoder

        def __getattr__(self, name):
            return getattr(self.decoder, name)

        def decompress(self, data, max_length=-1):
            # The negative control deliberately restores the vulnerable output
            # behavior, proving this check detects expansion of the entire member.
            output = self.decoder.decompress(data, max_length=-1 if simulate_unbounded else max_length)
            calls.append((max_length, len(output)))
            return output

    monkeypatch.setattr(zipfile, "_get_decompressor", lambda kind: ObservedDecoder(factory(kind)))
    data.seek(0)
    with zipfile.ZipFile(data) as archive:
        with archive.open("fixture.txt") as member:
            assert member.read(1) == b"P"
            assert calls
            bounded = all(0 < limit <= zipfile.ZipExtFile.MIN_READ_SIZE and size <= limit for limit, size in calls)
            assert bounded is (not simulate_unbounded)
            if simulate_unbounded:
                assert any(size == len(original) for _, size in calls)
            assert member.read() == original[1:]
