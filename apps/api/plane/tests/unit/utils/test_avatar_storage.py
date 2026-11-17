"""Avatar ingestion uses the internal storage client and preserves bounded cleanup."""

from unittest.mock import Mock

import pytest
from django.test import override_settings

from plane.authentication.adapter import base


pytestmark = pytest.mark.unit


@pytest.fixture
def avatar(monkeypatch):
    response = Mock(headers={"Content-Type": "image/png"})
    response.iter_content.return_value = iter([b"fixture-image"])
    fetch = Mock(return_value=(response, "https://cdn.fixture.invalid/avatar"))
    storage = Mock()
    storage.upload_file.return_value = True
    factory = Mock(return_value=storage)
    create = Mock(return_value=object())
    monkeypatch.setattr(base, "pinned_fetch_following_redirects", fetch)
    monkeypatch.setattr(base, "S3Storage", factory)
    monkeypatch.setattr(base.FileAsset.objects, "create", create)
    return response, fetch, storage, factory, create


def test_avatar_upload_and_metadata_use_internal_storage(avatar):
    response, fetch, storage, factory, create = avatar
    user = object()
    result = base.Adapter(request=object(), provider="gitea").download_and_upload_avatar(
        "https://cdn.fixture.invalid/avatar", user
    )
    assert result is create.return_value
    factory.assert_called_once_with(is_server=True)
    assert storage.upload_file.call_args.kwargs["file_obj"].getvalue() == b"fixture-image"
    assert storage.upload_file.call_args.kwargs["content_type"] == "image/png"
    storage.get_object_metadata.assert_called_once()
    assert create.call_args.kwargs["user"] is user
    assert fetch.call_args.kwargs["stream"] is True
    response.close.assert_called_once()


@pytest.mark.parametrize("mode", ["length", "decoded-size", "type", "read", "status", "upload"])
def test_failed_avatar_ingestion_closes_response_and_creates_no_record(avatar, mode):
    response, _fetch, storage, factory, create = avatar
    if mode == "length":
        response.headers["Content-Length"] = "9"
    elif mode == "decoded-size":
        response.iter_content.return_value = iter([b"1234", b"56789"])
    elif mode == "type":
        response.headers["Content-Type"] = "text/html"
    elif mode == "read":
        response.iter_content.side_effect = OSError("synthetic private read failure")
    elif mode == "status":
        response.raise_for_status.side_effect = RuntimeError("synthetic private status failure")
    else:
        storage.upload_file.return_value = False
    # The upload failure reaches storage; other fixtures fail before it.
    with override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=32 if mode == "upload" else 8):
        assert base.Adapter(request=object(), provider="gitea").download_and_upload_avatar(
            "https://cdn.fixture.invalid/avatar", object()
        ) is None
    response.close.assert_called_once()
    create.assert_not_called()
    if mode == "upload":
        factory.assert_called_once_with(is_server=True)
        storage.get_object_metadata.assert_not_called()
    else:
        factory.assert_not_called()
