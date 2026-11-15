"""Negative controls for the exact SAST finding gate."""

import copy
import hashlib

import pytest

from check_bandit import evaluate


@pytest.fixture
def reviewed(tmp_path):
    code = "random.choice(colors)"
    (tmp_path / "fixture.py").write_text(code)
    item = {"filename": "fixture.py", "test_id": "B311", "line_number": 1, "code": code}
    row = {
        "path": "fixture.py",
        "test_id": "B311",
        "line": 1,
        "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "file_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "reason": "Non-security display color",
    }
    return tmp_path, {"errors": [], "results": [item]}, {"findings": [row]}


def test_exact_review_passes_and_retains_raw_count(reviewed):
    result = evaluate(*reviewed)
    assert result["passed"] and result["raw_findings"] == result["reviewed"] == 1


@pytest.mark.parametrize("field,value", [("test_id", "B602"), ("line_number", 2), ("code", "shell=True")])
def test_new_or_changed_findings_fail(reviewed, field, value):
    source, report, policy = copy.deepcopy(reviewed)
    report["results"][0][field] = value
    result = evaluate(source, report, policy)
    assert not result["passed"] and result["unexpected"] and result["stale_dispositions"] == 1


def test_unreviewed_source_change_fails(reviewed):
    source, report, policy = reviewed
    (source / "fixture.py").write_text("changed")
    assert not evaluate(source, report, policy)["passed"]


def test_stale_disposition_fails(reviewed):
    source, report, policy = reviewed
    report["results"] = []
    assert not evaluate(source, report, policy)["passed"]


@pytest.mark.parametrize("filename", ["../outside", "/etc/passwd"])
def test_report_path_escape_rejected(reviewed, filename):
    source, report, policy = reviewed
    report["results"][0]["filename"] = filename
    with pytest.raises(AssertionError):
        evaluate(source, report, policy)


def test_scan_errors_fail_even_with_no_findings(reviewed):
    source, report, policy = reviewed
    report["errors"] = [{"filename": "fixture.py", "reason": "parse failed"}]
    with pytest.raises(AssertionError):
        evaluate(source, report, policy)
