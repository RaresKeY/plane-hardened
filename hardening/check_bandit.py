#!/usr/bin/env python3
"""Reject new or changed findings; preserve raw scanner findings and exact review reasons."""

import hashlib
import json
from pathlib import Path
import sys


def key(row):
    return row["test_id"], row["path"], row["line"], row["code_sha256"], row["file_sha256"]


def evaluate(source, report, policy):
    assert not report.get("errors"), "Bandit reported scan errors"
    reviewed = {key(row): row for row in policy["findings"]}
    unexpected = []
    seen = set()
    for item in report["results"]:
        path = item["filename"]
        # Report filenames must be source-relative; never hash arbitrary host paths.
        parsed = Path(path)
        assert not parsed.is_absolute() and ".." not in parsed.parts
        row = {
            "test_id": item["test_id"],
            "path": path,
            "line": item["line_number"],
            "code_sha256": hashlib.sha256(item["code"].encode()).hexdigest(),
            "file_sha256": hashlib.sha256((source / parsed).read_bytes()).hexdigest(),
        }
        identity = key(row)
        seen.add(identity)
        if identity not in reviewed:
            unexpected.append(row)
    stale = set(reviewed) - seen
    result = {
        "raw_findings": len(report["results"]),
        "reviewed": len(report["results"]) - len(unexpected),
        "reviewed_unique": len(seen & set(reviewed)),
        "unexpected": unexpected,
        "stale_dispositions": len(stale),
        "passed": not unexpected and not stale,
    }
    return result


def main():
    source = Path("/src")
    report = json.loads(Path("/out/bandit.json").read_text())
    policy = json.loads((source / "hardening/bandit_dispositions.json").read_text())
    result = evaluate(source, report, policy)
    Path("/out/bandit-review.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
    return int(not result["passed"])


if __name__ == "__main__":
    sys.exit(main())
