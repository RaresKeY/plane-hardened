"""Exact, fail-closed response-framing backports for the qualified Python/urllib3 sources."""

import hashlib
import re

CPYTHON_SHA256 = "c2c0694155837d72fc710a4138e5d1e53ae1a652b117a2e23a5b1b0db527a0f9"
URLLIB3_SHA256 = "0e4559c737914d4f8f941dca9ecfaf6caec6792258302bffec7b8b41dae3c71a"


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("Response-framing patch no longer matches its reviewed source")
    return source.replace(old, new, 1)


def checked(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Re-review response-framing backport against changed upstream source")
    return data.decode("utf-8")


def patch_cpython(data):
    source = checked(data, CPYTHON_SHA256)
    source = replace_once(
        source,
        """        i = line.find(b";")
        if i >= 0:
            line = line[:i] # strip chunk-extensions
        try:
            return int(line, 16)
""",
        """        try:
            if not line.endswith(b"\\r\\n"):
                raise ValueError("Invalid response chunk framing")
            size_text = line[:-2].split(b";", 1)[0]
            if not size_text or any(c not in b"0123456789abcdefABCDEF" for c in size_text):
                raise ValueError("Invalid response chunk framing")
            return int(size_text, 16)
""",
    )
    source = replace_once(
        source,
        """                self._safe_read(2)  # toss the CRLF at the end of the chunk
""",
        """                if self._safe_read(2) != b"\\r\\n":
                    self._close_conn()
                    raise IncompleteRead(b"")
""",
    )
    return source.encode("utf-8")


def patch_urllib3(data):
    source = checked(data, URLLIB3_SHA256)
    source = replace_once(
        source,
        """        line = line.split(b";", 1)[0]
        try:
            self.chunk_left = int(line, 16)
""",
        """        try:
            if not line.endswith(b"\\r\\n"):
                raise ValueError("Invalid response chunk framing")
            size_text = line[:-2].split(b";", 1)[0]
            if not size_text or any(c not in b"0123456789abcdefABCDEF" for c in size_text):
                raise ValueError("Invalid response chunk framing")
            self.chunk_left = int(size_text, 16)
""",
    )
    source = replace_once(
        source,
        "raise InvalidChunkLength(self, line) from None",
        'raise InvalidChunkLength(self, b"[invalid]") from None',
    )
    pattern = (
        r"(?m)^( +)self\._fp\._safe_read\(2\)  # type: ignore\[union-attr\]"
        r" # Toss the CRLF at the end of the chunk\.$"
    )

    def terminator(match):
        indent = match[1]
        return (
            indent
            + 'if self._fp._safe_read(2) != b"\\r\\n":  # type: ignore[union-attr]\n'
            + indent
            + '    raise ProtocolError("Invalid response chunk terminator")'
        )

    source, count = re.subn(pattern, terminator, source)
    if count != 3:
        raise ValueError("Review changed urllib3 chunk terminator paths")
    source = replace_once(
        source,
        """            # Chunk content ends with \\r\\n: discard it.
            while self._fp is not None:
                line = self._fp.fp.readline(_MAX_CHUNK_LINE_LENGTH + 1)
""",
        """            # Bound the whole trailer section as well as each individual line.
            trailer_bytes = 0
            while self._fp is not None:
                line = self._fp.fp.readline(_MAX_CHUNK_LINE_LENGTH + 1)
                trailer_bytes += len(line)
                if trailer_bytes > _MAX_CHUNK_LINE_LENGTH:
                    raise ProtocolError("Response chunk trailers exceeded maximum total length")
""",
    )
    return source.encode("utf-8")
