"""Negative controls for the source boundary used by the restricted runner."""

import hashlib
import json
import tarfile
from unittest.mock import patch

import pytest

from source_snapshot import stage


@pytest.mark.parametrize(
    "name", ["/outside", "../outside", ".git/config", ".local/private", ".env", "apps/api/.env.production"]
)
def test_private_or_unsafe_paths_rejected(tmp_path, name):
    with patch("source_snapshot.subprocess.check_output", return_value=(name + "\0").encode()):
        with pytest.raises(ValueError):
            stage(tmp_path, "/unused", ["ssh"])


@pytest.mark.parametrize("via_parent", [False, True])
def test_symlink_escape_rejected(tmp_path, via_parent):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "fixture.py").write_text("outside")
    repo = tmp_path / "repo"
    repo.mkdir()
    if via_parent:
        (repo / "linked").symlink_to(outside, target_is_directory=True)
        name = "linked/fixture.py"
    else:
        (repo / "fixture.py").symlink_to(outside / "fixture.py")
        name = "fixture.py"
    with patch("source_snapshot.subprocess.check_output", return_value=(name + "\0").encode()):
        with pytest.raises(ValueError):
            stage(repo, "/unused", ["ssh"])


@pytest.mark.parametrize("tamper", [False, True])
def test_only_git_listed_bytes_are_transferred_and_remote_digest_is_checked(tmp_path, tamper):
    data = b'print("reviewed fixture")\n'
    (tmp_path / "fixture.py").write_bytes(data)
    (tmp_path / ".env").write_text("private fixture must not be included")
    expected = hashlib.sha256(
        json.dumps({"fixture.py": hashlib.sha256(data).hexdigest()}, sort_keys=True).encode()
    ).hexdigest()

    def command(args, **kwargs):
        if args[0] == "git":
            assert "--exclude-standard" in args
            return b"fixture.py\0"
        with tarfile.open(fileobj=kwargs["stdin"]) as archive:
            assert archive.getnames() == ["fixture.py"]
            assert archive.extractfile("fixture.py").read() == data
        return (("0" * 64 if tamper else expected) + "\n").encode()

    with patch("source_snapshot.subprocess.check_output", side_effect=command):
        if tamper:
            with pytest.raises(ValueError, match="digest mismatch"):
                stage(tmp_path, "/unused", ["ssh"])
        else:
            assert stage(tmp_path, "/unused", ["ssh"]) == expected
