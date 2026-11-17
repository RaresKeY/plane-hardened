"""Do not publish asset metadata for a failed remote storage copy."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from django.test import override_settings

from plane.app.views.asset import v2
from plane.bgtasks import copy_s3_object
from plane.db.models import FileAsset


pytestmark = [pytest.mark.unit, pytest.mark.django_db]


@pytest.fixture(autouse=True)
def throttle_cache():
    # These are storage/database contracts. The database-only qualification lane
    # has no broker/cache service; exercise the real throttle with local state.
    with override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}):
        yield


@pytest.fixture
def original(workspace):
    return FileAsset.objects.create(
        workspace=workspace, asset=f"{workspace.id}/source.png", is_uploaded=True,
        size=12, entity_type=FileAsset.EntityTypeContext.USER_AVATAR,
        attributes={"name": "source.png", "type": "image/png", "size": 12},
    )


@pytest.mark.parametrize("result", [None, {"CopyObjectResult": {"ETag": "fixture"}}])
def test_duplicate_endpoint_only_publishes_after_copy_success(monkeypatch, session_client, create_user,
                                                            workspace, original, result):
    before = set(FileAsset.objects.values_list("id", flat=True))

    def copy(_source, _target):
        assert set(FileAsset.objects.values_list("id", flat=True)) == before
        return result

    storage = Mock()
    storage.copy_object.side_effect = copy
    factory = Mock(return_value=storage)
    monkeypatch.setattr(v2, "S3Storage", factory)
    response = session_client.post(
        f"/api/assets/v2/workspaces/{workspace.slug}/duplicate-assets/{original.id}/",
        {"entity_type": FileAsset.EntityTypeContext.USER_AVATAR, "entity_id": str(create_user.id)},
        format="json",
    )
    factory.assert_called_once_with(is_server=True)
    storage.copy_object.assert_called_once()
    if result is None:
        assert response.status_code == 502
        assert response.data == {"error": "Could not copy the asset"}
        assert set(FileAsset.objects.values_list("id", flat=True)) == before
    else:
        assert response.status_code == 200
        duplicate = FileAsset.objects.get(pk=response.data["asset_id"])
        assert duplicate.pk not in before and duplicate.is_uploaded
        assert duplicate.workspace == workspace and duplicate.user_id == create_user.id
        assert duplicate.attributes == original.attributes


def test_unexpected_copy_error_leaves_no_new_record(monkeypatch, session_client, create_user, workspace, original):
    before = FileAsset.objects.count()
    storage = Mock()
    storage.copy_object.side_effect = RuntimeError("synthetic private storage failure")
    monkeypatch.setattr(v2, "S3Storage", Mock(return_value=storage))
    response = session_client.post(
        f"/api/assets/v2/workspaces/{workspace.slug}/duplicate-assets/{original.id}/",
        {"entity_type": FileAsset.EntityTypeContext.USER_AVATAR, "entity_id": str(create_user.id)},
        format="json",
    )
    assert response.status_code == 500
    storage.copy_object.assert_called_once()
    assert "synthetic private" not in str(response.data)
    assert FileAsset.objects.count() == before


@pytest.mark.parametrize("results", [[None], [None, {"CopyObjectResult": {"ETag": "fixture"}}]])
def test_background_copy_skips_failed_assets_without_false_uploaded_rows(monkeypatch, create_user,
                                                                       workspace, original, results):
    assets = [original]
    if len(results) > 1:
        assets.append(FileAsset.objects.create(
            workspace=workspace, asset=f"{workspace.id}/other.png", is_uploaded=True,
            size=12, entity_type=original.entity_type, attributes=original.attributes,
        ))
    initial = set(FileAsset.objects.values_list("id", flat=True))
    outcomes = dict(zip([asset.asset.name for asset in assets], results, strict=True))
    storage = Mock()
    storage.copy_object.side_effect = lambda source, _destination: outcomes[str(source)]
    monkeypatch.setattr(copy_s3_object, "S3Storage", Mock(return_value=storage))
    mapping = copy_s3_object.copy_assets(
        SimpleNamespace(workspace=workspace), create_user.id, None, [asset.id for asset in assets], create_user.id,
    )
    created = FileAsset.objects.exclude(pk__in=initial)
    assert created.count() == len(mapping) == sum(value is not None for value in results)
    assert all(asset.is_uploaded for asset in created)
    assert all(row["old_asset_id"] != str(original.id) for row in mapping)
