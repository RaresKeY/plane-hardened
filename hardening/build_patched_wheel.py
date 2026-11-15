"""Rebuild a pure wheel from exact qualified input bytes; never import its modules or run hooks."""

import argparse
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import zipfile

from http_framing_patch import patch_urllib3

ORIGINAL = "0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3"
OLD_INFO = "urllib3-2.8.0.dist-info"
NEW_INFO = "urllib3-2.8.0+plane.2.dist-info"


def build(original, output):
    if hashlib.sha256(original.read_bytes()).hexdigest() != ORIGINAL:
        raise ValueError("Only the exact reviewed urllib3 wheel is accepted")
    files = {}
    with zipfile.ZipFile(original) as archive:
        for name in archive.namelist():
            path = Path(name)
            if path.is_absolute() or ".." in path.parts or name.endswith((".jws", ".p7s")):
                raise ValueError("Unexpected wheel path or signature")
            if not name.endswith("/") and not name.endswith("/RECORD"):
                files[name.replace(OLD_INFO, NEW_INFO)] = archive.read(name)
    files["urllib3/response.py"] = patch_urllib3(files["urllib3/response.py"])
    version = files["urllib3/_version.py"].decode()
    assert version.count("'2.8.0'") == 1
    # Requests parses the public runtime version as integer components. Keep its
    # upstream compatibility string; wheel metadata and this marker identify the fork.
    version += "\n__plane_revision__ = '2.8.0+plane.2'\n"
    files["urllib3/_version.py"] = version.encode()
    metadata = files[NEW_INFO + "/METADATA"].decode()
    assert metadata.count("Version: 2.8.0\n") == 1
    files[NEW_INFO + "/METADATA"] = metadata.replace("Version: 2.8.0\n", "Version: 2.8.0+plane.2\n").encode()
    wheel = files[NEW_INFO + "/WHEEL"].decode()
    files[NEW_INFO + "/WHEEL"] = "\n".join(
        "Generator: plane-hardening-wheel-patcher-1" if line.startswith("Generator:") else line
        for line in wheel.split("\n")
    ).encode()
    files["urllib3/plane_patch.json"] = (
        json.dumps(
            {
                "upstream_version": "2.8.0",
                "fork_version": "2.8.0+plane.2",
                "runtime_version": "2.8.0",
                "original_wheel_sha256": ORIGINAL,
                "response_source_sha256": hashlib.sha256(files["urllib3/response.py"]).hexdigest(),
                "purpose": (
                    "Strict hex chunk sizes, CRLF terminators, 64KiB total trailers; "
                    "omit hostile chunk text from errors"
                ),
                "source": "https://github.com/RaresKeY/plane-hardened/tree/hardened/hardening",
            },
            sort_keys=True,
            indent=2,
        ).encode()
        + b"\n"
    )
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([name, "sha256=" + digest, str(len(data))])
    writer.writerow([NEW_INFO + "/RECORD", "", ""])
    files[NEW_INFO + "/RECORD"] = record.getvalue().encode()
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (2026, 11, 15, 0, 0, 0))
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    return hashlib.sha256(output.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps({"sha256": build(args.original, args.output), "file": args.output.name}))


if __name__ == "__main__":
    main()
