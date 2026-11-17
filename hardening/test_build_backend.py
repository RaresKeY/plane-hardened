import hashlib
from pathlib import Path

import pytest

from build_backend import api_sources, verify_build_inputs
from source_snapshot import source_path


@pytest.mark.parametrize("name", ["apps/api/.env", "apps/api/.env.production", "apps/api/../private",
                                "../outside", "/outside", "apps/web/source.py"])
def test_private_or_outside_build_sources_rejected(tmp_path, name):
    with pytest.raises(ValueError):
        api_sources(tmp_path, [name])


@pytest.mark.parametrize("parent_link", [False, True])
def test_direct_and_parent_build_symlinks_rejected(tmp_path, parent_link):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "source.py").write_text("synthetic-private-input")
    repo = tmp_path / "repo"
    api = repo / "apps/api"
    api.mkdir(parents=True)
    if parent_link:
        (api / "linked").symlink_to(outside, target_is_directory=True)
        name = "apps/api/linked/source.py"
    else:
        (api / "source.py").symlink_to(outside / "source.py")
        name = "apps/api/source.py"
    with pytest.raises(ValueError):
        api_sources(repo, [name])


def test_only_reviewed_api_files_and_environment_example_are_selected(tmp_path):
    api = tmp_path / "apps/api"
    api.mkdir(parents=True)
    (api / "source.py").write_text("reviewed")
    (api / ".env.example").write_text("synthetic-example")
    (api / "not-listed.py").write_text("not selected")
    selected = api_sources(tmp_path, ["apps/api/source.py", "apps/api/.env.example"])
    assert set(selected) == {"api/source.py", "api/.env.example"}


def test_parent_symlink_cannot_include_ignored_private_file_inside_checkout(tmp_path):
    private = tmp_path / ".local"
    private.mkdir()
    (private / "source.py").write_text("synthetic-private-input")
    api = tmp_path / "apps/api"
    api.mkdir(parents=True)
    (api / "linked").symlink_to(private, target_is_directory=True)
    with pytest.raises(ValueError):
        api_sources(tmp_path, ["apps/api/linked/source.py"])


@pytest.mark.parametrize("direct", [False, True])
def test_non_api_build_helpers_cannot_alias_private_inputs(tmp_path, direct):
    private = tmp_path / ".local"
    private.mkdir()
    (private / "backend_entrypoint.py").write_text("synthetic-private-helper")
    hardening = tmp_path / "hardening"
    if direct:
        hardening.mkdir()
        (hardening / "backend_entrypoint.py").symlink_to(private / "backend_entrypoint.py")
    else:
        hardening.symlink_to(private, target_is_directory=True)
    with pytest.raises(ValueError):
        source_path(tmp_path, Path("hardening/backend_entrypoint.py"))


@pytest.mark.parametrize("change", ["tamper", "extra", "missing", "symlink"])
def test_extracted_context_rejects_content_races_and_unreviewed_entries(tmp_path, change):
    data = b"reviewed"
    (tmp_path / "input").write_bytes(data)
    manifest = {"input": hashlib.sha256(data).hexdigest()}
    verify_build_inputs(tmp_path, manifest)
    if change == "tamper":
        (tmp_path / "input").write_text("changed after hash verification")
    elif change == "extra":
        (tmp_path / "unreviewed").write_text("extra")
    elif change == "missing":
        (tmp_path / "input").unlink()
    else:
        (tmp_path / "link").symlink_to(tmp_path / "input")
    with pytest.raises(ValueError):
        verify_build_inputs(tmp_path, manifest)
