"""Asset copy and sibling routes must enforce the same resource boundary."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from django.test import override_settings
from django.utils import timezone

from plane.app.views.asset import v2
from plane.db.models import (
    DraftIssue, FileAsset, Issue, IssueComment, Page, Project, ProjectMember,
    ProjectPage, User, Workspace, WorkspaceMember,
)


pytestmark = [pytest.mark.unit, pytest.mark.django_db]


@pytest.fixture
def scope(monkeypatch, workspace, create_user):
    owner = User.objects.create(email="asset-owner@fixture.invalid", username="asset-owner")
    project = Project.objects.create(workspace=workspace, name="Private", identifier="PRV")
    target = Project.objects.create(workspace=workspace, name="Target", identifier="TGT")
    foreign = Workspace.objects.create(owner=owner, name="Foreign", slug="foreign-assets")
    foreign_project = Project.objects.create(workspace=foreign, name="Foreign", identifier="FRN")
    issue = Issue(name="Private issue", project=project, workspace=workspace)
    issue.save(created_by_id=owner.id)
    foreign_issue = Issue.objects.create(name="Foreign", project=foreign_project, workspace=foreign)
    comment = IssueComment.objects.create(
        issue=issue, project=project, workspace=workspace, actor=create_user,
    )
    IssueComment.objects.filter(pk=comment.pk).update(created_by_id=create_user.pk)
    draft = DraftIssue.objects.create(workspace=workspace, project=project, name="Draft")
    DraftIssue.objects.filter(pk=draft.pk).update(created_by_id=create_user.pk)
    page = Page.objects.create(workspace=workspace, owned_by=create_user, name="Page")
    ProjectPage.objects.create(project=project, page=page, workspace=workspace)
    asset = FileAsset.objects.create(
        workspace=workspace, project=project, issue=issue, is_uploaded=True,
        entity_type=FileAsset.EntityTypeContext.ISSUE_DESCRIPTION, asset=f"{workspace.id}/private.png",
        attributes={"name": "private.png", "type": "image/png", "size": 12}, size=12,
    )
    public = FileAsset.objects.create(
        workspace=workspace, is_uploaded=True, entity_type=FileAsset.EntityTypeContext.WORKSPACE_LOGO,
        asset=f"{workspace.id}/logo.png", attributes={"name": "logo.png", "type": "image/png", "size": 12},
    )
    storage = Mock()
    storage.generate_presigned_url.return_value = "https://signed.fixture.invalid/object"
    storage.generate_presigned_post.return_value = {"url": "https://signed.fixture.invalid/upload", "fields": {}}
    storage.copy_object.return_value = {"CopyObjectResult": {"ETag": "fixture"}}
    factory = Mock(return_value=storage)
    monkeypatch.setattr(v2, "S3Storage", factory)
    monkeypatch.setattr(v2.get_asset_object_metadata, "delay", Mock())
    with override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}):
        yield SimpleNamespace(
            user=create_user, owner=owner, workspace=workspace, project=project, target=target,
            foreign=foreign, foreign_project=foreign_project, issue=issue, foreign_issue=foreign_issue,
            comment=comment, draft=draft, page=page, asset=asset, public=public,
            factory=factory, storage=storage,
        )


def membership(scope, *, active=True, project=None):
    return ProjectMember.objects.create(
        member=scope.user, project=project or scope.project,
        workspace=(project or scope.project).workspace, role=15, is_active=active,
    )


def action(client, scope, operation):
    base = f"/api/assets/v2/workspaces/{scope.workspace.slug}/"
    if operation == "download":
        return client.get(base + f"download/{scope.asset.id}/")
    if operation == "detail":
        return client.get(base + f"{scope.asset.id}/")
    if operation == "check":
        return client.get(base + f"check/{scope.asset.id}/")
    if operation == "restore":
        return client.post(base + f"restore/{scope.asset.id}/")
    return client.post(base + f"duplicate-assets/{scope.asset.id}/", {
        "entity_type": "USER_AVATAR", "entity_id": str(scope.user.id),
    }, format="json")


@pytest.mark.parametrize("operation", ["download", "detail", "check", "restore", "copy"])
@pytest.mark.parametrize("access", ["missing", "inactive", "foreign", "inactive-workspace"])
def test_workspace_membership_cannot_bypass_project_boundary(session_client, scope, operation, access):
    if access == "inactive":
        membership(scope, active=False)
    elif access == "foreign":
        membership(scope, project=scope.foreign_project)
    elif access == "inactive-workspace":
        membership(scope)
        WorkspaceMember.objects.filter(workspace=scope.workspace, member=scope.user).update(is_active=False)
    if operation == "restore":
        scope.asset.deleted_at = timezone.now()
        scope.asset.is_deleted = True
        scope.asset.save(update_fields=["deleted_at", "is_deleted"])
    before = FileAsset.all_objects.count()
    response = action(session_client, scope, operation)
    if operation == "check" and access != "inactive-workspace":
        assert response.status_code == 200 and response.data == {"exists": False}
    else:
        assert response.status_code == 403
    scope.factory.assert_not_called()
    assert FileAsset.all_objects.count() == before
    scope.asset.refresh_from_db()
    if operation == "restore":
        assert scope.asset.is_deleted and scope.asset.deleted_at is not None


@pytest.mark.parametrize("operation", ["download", "detail", "check", "restore", "copy"])
def test_active_project_member_retains_valid_actions(session_client, scope, operation):
    membership(scope)
    if operation == "restore":
        scope.asset.deleted_at = timezone.now()
        scope.asset.is_deleted = True
        scope.asset.save(update_fields=["deleted_at", "is_deleted"])
    response = action(session_client, scope, operation)
    assert response.status_code == {"download": 302, "detail": 302, "check": 200,
                                    "restore": 204, "copy": 200}[operation]
    if operation == "check":
        assert response.data == {"exists": True}
    if operation == "copy":
        scope.storage.copy_object.assert_called_once()


def duplicate(client, scope, payload):
    return client.post(
        f"/api/assets/v2/workspaces/{scope.workspace.slug}/duplicate-assets/{scope.public.id}/",
        payload, format="json",
    )


@pytest.mark.parametrize("target", ["inaccessible-project", "foreign-project", "foreign-issue", "mismatched-issue",
                                    "other-user", "member-logo", "other-draft", "private-page"])
def test_copy_destination_is_authorized_before_storage_or_writes(session_client, scope, target):
    membership(scope)
    payload = {"entity_type": "ISSUE_DESCRIPTION", "entity_id": str(scope.issue.id),
               "project_id": str(scope.project.id)}
    expected = 403
    if target == "inaccessible-project":
        payload = {"entity_type": "PROJECT_COVER", "entity_id": str(scope.target.id)}
    elif target == "foreign-project":
        payload = {"entity_type": "PROJECT_COVER", "entity_id": str(scope.foreign_project.id)}
        expected = 404
    elif target == "foreign-issue":
        payload["entity_id"] = str(scope.foreign_issue.id)
        expected = 404
    elif target == "mismatched-issue":
        membership(scope, project=scope.target)
        payload["project_id"] = str(scope.target.id)
        expected = 404
    elif target == "other-user":
        payload = {"entity_type": "USER_AVATAR", "entity_id": str(scope.owner.id)}
    elif target == "member-logo":
        WorkspaceMember.objects.filter(workspace=scope.workspace, member=scope.user).update(role=15)
        payload = {"entity_type": "WORKSPACE_LOGO", "entity_id": str(scope.workspace.id)}
    elif target == "other-draft":
        DraftIssue.objects.filter(pk=scope.draft.pk).update(created_by_id=scope.owner.pk)
        payload.update(entity_type="DRAFT_ISSUE_DESCRIPTION", entity_id=str(scope.draft.id))
    elif target == "private-page":
        Page.objects.filter(pk=scope.page.pk).update(owned_by_id=scope.owner.pk, access=Page.PRIVATE_ACCESS)
        payload.update(entity_type="PAGE_DESCRIPTION", entity_id=str(scope.page.id))
    before = FileAsset.objects.count()
    response = duplicate(session_client, scope, payload)
    assert response.status_code == expected, response.data
    scope.factory.assert_not_called()
    assert FileAsset.objects.count() == before


@pytest.mark.parametrize("kind", list(FileAsset.EntityTypeContext.values))
def test_supported_target_types_produce_consistent_single_scope(session_client, scope, kind):
    membership(scope)
    targets = {"WORKSPACE_LOGO": scope.workspace.id, "PROJECT_COVER": scope.project.id,
               "USER_AVATAR": scope.user.id, "USER_COVER": scope.user.id,
               "ISSUE_ATTACHMENT": scope.issue.id, "ISSUE_DESCRIPTION": scope.issue.id,
               "COMMENT_DESCRIPTION": scope.comment.id, "PAGE_DESCRIPTION": scope.page.id,
               "DRAFT_ISSUE_DESCRIPTION": scope.draft.id, "DRAFT_ISSUE_ATTACHMENT": scope.draft.id}
    payload = {"entity_type": kind, "entity_id": str(targets[kind])}
    if kind not in ("WORKSPACE_LOGO", "PROJECT_COVER", "USER_AVATAR", "USER_COVER"):
        payload["project_id"] = str(scope.project.id)
    response = duplicate(session_client, scope, payload)
    assert response.status_code == 200, response.data
    asset = FileAsset.objects.get(pk=response.data["asset_id"])
    assert asset.workspace_id == scope.workspace.id and asset.is_uploaded
    expected_project = scope.project.id if kind not in ("WORKSPACE_LOGO", "USER_AVATAR", "USER_COVER") else None
    assert asset.project_id == expected_project
    if kind.startswith("DRAFT_ISSUE"):
        assert asset.draft_issue_id == scope.draft.id
    if kind == "WORKSPACE_LOGO":
        assert asset.workspace_id == scope.workspace.id
    scope.storage.copy_object.assert_called_once()


@pytest.mark.parametrize("key", ["project_id", "entity_id"])
@pytest.mark.parametrize("value", ["not-a-uuid", [], {}, 3])
def test_invalid_target_identifiers_return_400_before_storage(session_client, scope, key, value):
    membership(scope)
    payload = {"entity_type": "ISSUE_DESCRIPTION", "entity_id": str(scope.issue.id),
               "project_id": str(scope.project.id), key: value}
    assert duplicate(session_client, scope, payload).status_code == 400
    scope.factory.assert_not_called()


@pytest.mark.parametrize("active", [False, True])
def test_legacy_asset_inherits_its_issue_project_scope(session_client, scope, active):
    scope.asset.project = None
    scope.asset.save(update_fields=["project"])
    if active:
        membership(scope)
    response = action(session_client, scope, "download")
    assert response.status_code == (302 if active else 403)


@pytest.mark.parametrize("operation", ["patch", "delete"])
@pytest.mark.parametrize("kind", ["USER_AVATAR", "WORKSPACE_LOGO"])
def test_workspace_asset_mutation_preserves_owner_and_admin_boundaries(session_client, scope, operation, kind):
    WorkspaceMember.objects.filter(workspace=scope.workspace, member=scope.user).update(role=15)
    scope.public.entity_type = kind
    scope.public.user = scope.owner if kind == "USER_AVATAR" else None
    scope.public.save(update_fields=["entity_type", "user"])
    url = f"/api/assets/v2/workspaces/{scope.workspace.slug}/{scope.public.id}/"
    before = scope.public.attributes.copy()
    response = getattr(session_client, operation)(url, {"attributes": {"name": "changed"}}, format="json")
    assert response.status_code == 403
    scope.public.refresh_from_db()
    assert scope.public.attributes == before and not scope.public.is_deleted


def test_missing_target_entity_can_be_staged_only_in_an_accessible_project(session_client, scope):
    membership(scope)
    response = duplicate(session_client, scope, {"entity_type": "ISSUE_DESCRIPTION",
                                                 "project_id": str(scope.project.id)})
    assert response.status_code == 200, response.data
    asset = FileAsset.objects.get(pk=response.data["asset_id"])
    assert asset.project_id == scope.project.id and asset.issue_id is None


def test_missing_project_and_entity_is_rejected_for_project_content(session_client, scope):
    assert duplicate(session_client, scope, {"entity_type": "ISSUE_DESCRIPTION"}).status_code == 400
    scope.factory.assert_not_called()


@pytest.mark.parametrize("route", ["workspace", "project"])
@pytest.mark.parametrize("target", ["foreign-issue", "other-draft", "private-page", "valid", "pending"])
def test_upload_routes_validate_parent_before_presigning(session_client, scope, route, target):
    membership(scope)
    payload = {"name": "image.png", "type": "image/png", "size": 12,
               "entity_type": "ISSUE_DESCRIPTION", "entity_identifier": str(scope.issue.id)}
    expected = 200
    if target == "foreign-issue":
        payload["entity_identifier"] = str(scope.foreign_issue.id)
        expected = 404
    elif target == "other-draft":
        DraftIssue.objects.filter(pk=scope.draft.pk).update(created_by_id=scope.owner.pk)
        payload.update(entity_type="DRAFT_ISSUE_ATTACHMENT", entity_identifier=str(scope.draft.pk))
        expected = 403
    elif target == "private-page":
        Page.objects.filter(pk=scope.page.pk).update(owned_by_id=scope.owner.pk, access=Page.PRIVATE_ACCESS)
        payload.update(entity_type="PAGE_DESCRIPTION", entity_identifier=str(scope.page.pk))
        expected = 403
    elif target == "pending":
        payload.pop("entity_identifier")
        payload["project_id"] = str(scope.project.id)
    url = f"/api/assets/v2/workspaces/{scope.workspace.slug}/"
    if route == "project":
        url += f"projects/{scope.project.id}/"
    before = FileAsset.objects.count()
    response = session_client.post(url, payload, format="json")
    assert response.status_code == expected, response.data
    if expected != 200:
        scope.factory.assert_not_called()
        assert FileAsset.objects.count() == before
    else:
        asset = FileAsset.objects.get(pk=response.data["asset_id"])
        assert asset.project_id == scope.project.id
        scope.storage.generate_presigned_post.assert_called_once()


@pytest.mark.parametrize("operation", ["detail", "download", "patch", "delete"])
@pytest.mark.parametrize("boundary", ["inactive-workspace", "private-page", "valid"])
def test_project_routes_keep_resource_checks(session_client, scope, operation, boundary):
    membership(scope)
    if boundary == "inactive-workspace":
        WorkspaceMember.objects.filter(workspace=scope.workspace, member=scope.user).update(is_active=False)
    elif boundary == "private-page":
        Page.objects.filter(pk=scope.page.pk).update(owned_by_id=scope.owner.pk, access=Page.PRIVATE_ACCESS)
        scope.asset.entity_type = "PAGE_DESCRIPTION"
        scope.asset.issue = None
        scope.asset.page = scope.page
        scope.asset.save(update_fields=["entity_type", "issue", "page"])
    base = f"/api/assets/v2/workspaces/{scope.workspace.slug}/projects/{scope.project.id}/"
    url = base + (f"download/{scope.asset.id}/" if operation == "download" else f"{scope.asset.id}/")
    method = "get" if operation in ("detail", "download") else operation
    response = getattr(session_client, method)(url)
    expected = (302 if method == "get" else 204) if boundary == "valid" else 403
    assert response.status_code == expected, getattr(response, "data", None)
    if boundary != "valid":
        scope.factory.assert_not_called()
        scope.asset.refresh_from_db()
        assert not scope.asset.is_deleted


@pytest.mark.parametrize("parent", ["foreign", "mismatch", "valid"])
def test_bulk_association_validates_target_before_any_updates(session_client, scope, parent):
    membership(scope)
    target = scope.issue
    expected = 204
    if parent == "foreign":
        target = scope.foreign_issue
        expected = 404
    elif parent == "mismatch":
        target = Issue.objects.create(workspace=scope.workspace, project=scope.target, name="Other project")
        expected = 404
    asset = FileAsset.objects.create(
        workspace=scope.workspace, project=scope.project, asset="staged.png", entity_type="ISSUE_DESCRIPTION",
    )
    FileAsset.objects.filter(pk=asset.pk).update(created_by_id=scope.user.pk)
    url = f"/api/assets/v2/workspaces/{scope.workspace.slug}/projects/{scope.project.id}/{target.id}/bulk/"
    response = session_client.post(url, {"asset_ids": [str(asset.pk)]}, format="json")
    assert response.status_code == expected, getattr(response, "data", None)
    asset.refresh_from_db()
    assert asset.issue_id == (target.id if expected == 204 else None)


@pytest.mark.parametrize("kind", ["PROJECT_COVER", "PAGE_DESCRIPTION"])
def test_pre_entity_upload_stays_owned_until_association(session_client, scope, kind):
    response = session_client.post(f"/api/assets/v2/workspaces/{scope.workspace.slug}/", {
        "name": "staged.png", "type": "image/png", "size": 12, "entity_type": kind,
    }, format="json")
    assert response.status_code == 200, response.data
    asset = FileAsset.objects.get(pk=response.data["asset_id"])
    assert asset.project_id is None and asset.page_id is None
    assert asset.created_by_id == scope.user.pk
    scope.asset = asset
    asset.is_uploaded = True
    asset.save(update_fields=["is_uploaded"])
    assert action(session_client, scope, "download").status_code == 302
    FileAsset.objects.filter(pk=asset.pk).update(created_by_id=scope.owner.pk)
    assert action(session_client, scope, "download").status_code == 403


@pytest.mark.parametrize("access", ["private", "removed-link", "guest", "member", "owner-guest", "global"])
def test_page_destination_uses_page_visibility_link_and_writer_role(session_client, scope, access):
    pm = membership(scope)
    Page.objects.filter(pk=scope.page.pk).update(owned_by_id=scope.owner.pk)
    expected = 403
    payload = {"entity_type": "PAGE_DESCRIPTION", "entity_id": str(scope.page.id)}
    if access == "private":
        Page.objects.filter(pk=scope.page.pk).update(access=Page.PRIVATE_ACCESS)
    elif access == "removed-link":
        ProjectPage.objects.filter(page=scope.page).update(deleted_at=timezone.now())
    elif access in ("guest", "owner-guest"):
        pm.role = 5
        pm.save(update_fields=["role"])
        # Another user's membership must not satisfy this caller's write role.
        ProjectMember.objects.create(workspace=scope.workspace, project=scope.project, member=scope.owner, role=20)
        if access == "owner-guest":
            Page.objects.filter(pk=scope.page.pk).update(owned_by_id=scope.user.pk)
            expected = 200
    elif access == "global":
        Page.objects.filter(pk=scope.page.pk).update(is_global=True)
        ProjectPage.objects.filter(page=scope.page).update(deleted_at=timezone.now())
        expected = 200
    else:
        expected = 200
    response = duplicate(session_client, scope, payload)
    assert response.status_code == expected, response.data
    if expected != 200:
        scope.factory.assert_not_called()


@pytest.mark.parametrize("access", ["owner", "project-admin", "member"])
def test_comment_destination_preserves_author_or_admin_writes(session_client, scope, access):
    pm = membership(scope)
    WorkspaceMember.objects.filter(workspace=scope.workspace, member=scope.user).update(role=15)
    if access != "owner":
        IssueComment.objects.filter(pk=scope.comment.pk).update(created_by_id=scope.owner.pk)
    if access == "project-admin":
        pm.role = 20
        pm.save(update_fields=["role"])
    response = duplicate(session_client, scope, {"entity_type": "COMMENT_DESCRIPTION",
        "entity_id": str(scope.comment.id), "project_id": str(scope.project.id)})
    assert response.status_code == (403 if access == "member" else 200), response.data
    if access == "member":
        scope.factory.assert_not_called()


@pytest.mark.parametrize("kind", ["WORKSPACE_LOGO", "PROJECT_COVER", "USER_AVATAR", "USER_COVER", "ISSUE_DESCRIPTION"])
def test_public_static_asset_contract_remains_explicit(scope, kind):
    from rest_framework.test import APIClient

    scope.public.entity_type = kind
    scope.public.save(update_fields=["entity_type"])
    response = APIClient().get(f"/api/assets/v2/static/{scope.public.id}/")
    assert response.status_code == (400 if kind == "ISSUE_DESCRIPTION" else 302)
    if kind == "ISSUE_DESCRIPTION":
        scope.factory.assert_not_called()


@pytest.mark.parametrize("kind", ["COMMENT_DESCRIPTION", "PAGE_DESCRIPTION", "DRAFT_ISSUE_DESCRIPTION"])
@pytest.mark.parametrize("active", [False, True])
def test_parent_only_legacy_assets_keep_their_resource_boundary(session_client, scope, kind, active):
    scope.asset.project = None
    scope.asset.issue = None
    scope.asset.entity_type = kind
    scope.asset.comment = scope.comment if kind == "COMMENT_DESCRIPTION" else None
    scope.asset.page = scope.page if kind == "PAGE_DESCRIPTION" else None
    scope.asset.draft_issue = scope.draft if kind == "DRAFT_ISSUE_DESCRIPTION" else None
    scope.asset.save(update_fields=["project", "issue", "entity_type", "comment", "page", "draft_issue"])
    if active:
        membership(scope)
    response = action(session_client, scope, "download")
    assert response.status_code == (302 if active else 403)
    if not active:
        scope.factory.assert_not_called()


@pytest.mark.parametrize("order", [False, True])
def test_mixed_bulk_batch_is_validated_before_first_write(session_client, scope, order):
    membership(scope)
    assets = []
    kinds = ("ISSUE_DESCRIPTION", "COMMENT_DESCRIPTION") if order else ("COMMENT_DESCRIPTION", "ISSUE_DESCRIPTION")
    for kind in kinds:
        asset = FileAsset.objects.create(workspace=scope.workspace, project=scope.project,
                                         asset="staged.png", entity_type=kind)
        FileAsset.objects.filter(pk=asset.pk).update(created_by_id=scope.user.pk)
        assets.append(asset)
    url = f"/api/assets/v2/workspaces/{scope.workspace.slug}/projects/{scope.project.id}/{scope.issue.id}/bulk/"
    response = session_client.post(url, {"asset_ids": [str(a.pk) for a in assets]}, format="json")
    assert response.status_code == 404
    for asset in assets:
        asset.refresh_from_db()
        assert asset.issue_id is None and asset.comment_id is None


@pytest.mark.parametrize("active", [False, True])
def test_bulk_legacy_source_cannot_escape_its_original_project(session_client, scope, active):
    membership(scope, project=scope.target)
    if active:
        membership(scope)
    scope.asset.project = None
    scope.asset.save(update_fields=["project"])
    FileAsset.objects.filter(pk=scope.asset.pk).update(created_by_id=scope.user.pk)
    target = Issue.objects.create(workspace=scope.workspace, project=scope.target, name="Destination")
    url = f"/api/assets/v2/workspaces/{scope.workspace.slug}/projects/{scope.target.id}/{target.id}/bulk/"
    response = session_client.post(url, {"asset_ids": [str(scope.asset.id)]}, format="json")
    assert response.status_code == (204 if active else 403), getattr(response, "data", None)
    scope.asset.refresh_from_db()
    assert scope.asset.issue_id == (target.id if active else scope.issue.id)
    assert scope.asset.project_id == (scope.target.id if active else None)


@pytest.mark.parametrize("operation", ["get", "patch"])
@pytest.mark.parametrize("access", ["missing", "inactive", "valid"])
def test_token_asset_routes_cannot_bypass_resource_scope(api_key_client, scope, monkeypatch, operation, access):
    from plane.api.views import asset as token_assets

    monkeypatch.setattr(token_assets, "S3Storage", scope.factory)
    if access != "missing":
        membership(scope, active=access == "valid")
    url = f"/api/v1/workspaces/{scope.workspace.slug}/assets/{scope.asset.id}/"
    response = getattr(api_key_client, operation)(url, {"is_uploaded": False}, format="json")
    assert response.status_code == ((200 if operation == "get" else 204) if access == "valid" else 403)
    if access != "valid":
        scope.factory.assert_not_called()
        scope.asset.refresh_from_db()
        assert scope.asset.is_uploaded


@pytest.mark.parametrize("target", ["missing", "foreign", "invalid", "valid", "unscoped"])
def test_token_upload_project_scope_is_checked_before_storage(api_key_client, scope, monkeypatch, target):
    from plane.api.views import asset as token_assets

    monkeypatch.setattr(token_assets, "S3Storage", scope.factory)
    payload = {"name": "fixture.png", "type": "image/png", "size": 12}
    expected = {"missing": 403, "foreign": 404, "invalid": 400, "valid": 200, "unscoped": 200}[target]
    if target == "valid":
        membership(scope)
    if target != "unscoped":
        payload["project_id"] = ("bad" if target == "invalid" else
                                 str(scope.foreign_project.id if target == "foreign" else scope.project.id))
    before = FileAsset.objects.count()
    response = api_key_client.post(f"/api/v1/workspaces/{scope.workspace.slug}/assets/", payload, format="json")
    assert response.status_code == expected, response.data
    if expected != 200:
        scope.factory.assert_not_called()
        assert FileAsset.objects.count() == before


def test_token_external_id_lookup_does_not_disclose_private_asset(api_key_client, scope, monkeypatch):
    from plane.api.views import asset as token_assets

    monkeypatch.setattr(token_assets, "S3Storage", scope.factory)
    FileAsset.objects.filter(pk=scope.asset.pk).update(external_id="known", external_source="fixture")
    response = api_key_client.post(f"/api/v1/workspaces/{scope.workspace.slug}/assets/", {
        "name": "fixture.png", "type": "image/png", "size": 12,
        "external_id": "known", "external_source": "fixture",
    }, format="json")
    assert response.status_code == 403
    assert "asset_id" not in response.data
    scope.factory.assert_not_called()


@pytest.mark.parametrize("operation", ["get", "delete", "restore"])
@pytest.mark.parametrize("access", ["missing", "inactive", "valid"])
def test_legacy_file_routes_cannot_bypass_project_scope(session_client, scope, operation, access):
    if access != "missing":
        membership(scope, active=access == "valid")
    url = f"/api/workspaces/file-assets/{scope.workspace.id}/private.png/"
    response = (session_client.post(url + "restore/") if operation == "restore" else
                getattr(session_client, operation)(url))
    expected = (200 if operation == "get" else 204) if access == "valid" else 403
    assert response.status_code == expected, getattr(response, "data", None)
    scope.asset.refresh_from_db()
    assert scope.asset.is_deleted == (operation == "delete" and access == "valid")


@pytest.mark.parametrize("active", [False, True])
def test_legacy_untyped_parent_keeps_its_project_boundary(session_client, scope, active):
    scope.asset.project = None
    scope.asset.entity_type = None
    scope.asset.save(update_fields=["project", "entity_type"])
    if active:
        membership(scope)
    response = session_client.get(f"/api/workspaces/file-assets/{scope.workspace.id}/private.png/")
    assert response.status_code == (200 if active else 403), getattr(response, "data", None)


@pytest.mark.parametrize("target", ["foreign", "private", "valid", "unscoped", "static"])
def test_legacy_upload_validates_relations_before_saving(session_client, scope, tmp_path, target):
    from django.core.files.uploadedfile import SimpleUploadedFile

    membership(scope)
    payload = {"asset": SimpleUploadedFile("legacy.png", b"bounded-fixture", content_type="image/png")}
    expected = 201
    if target == "foreign":
        payload["issue"] = str(scope.foreign_issue.id)
        expected = 403
    elif target == "private":
        payload["project"] = str(scope.target.id)
        expected = 403
    elif target == "valid":
        payload["issue"] = str(scope.issue.id)
    elif target == "static":
        payload.update(entity_type="USER_AVATAR", user=str(scope.user.id), is_uploaded=True)
        expected = 400
    before = FileAsset.objects.count()
    storage = {"default": {"BACKEND": "django.core.files.storage.FileSystemStorage",
                           "OPTIONS": {"location": str(tmp_path)}}}
    with override_settings(STORAGES=storage):
        url = f"/api/workspaces/{scope.workspace.slug}/file-assets/"
        response = session_client.post(url, payload, format="multipart")
    assert response.status_code == expected, response.data
    if expected != 201:
        assert FileAsset.objects.count() == before
        assert not list(tmp_path.rglob("*.png"))


@pytest.mark.parametrize("route", ["v2", "token", "token-server"])
@pytest.mark.parametrize("has_parent", [False, True])
def test_personal_asset_mutations_cannot_launder_workspace_parents(session_client, api_key_client, scope,
                                                                route, has_parent):
    asset = FileAsset.objects.create(asset="personal.png", user=scope.user, is_uploaded=True,
                                    entity_type="USER_AVATAR", storage_metadata={"size": 12})
    if has_parent:
        FileAsset.objects.filter(pk=asset.pk).update(workspace=scope.workspace, issue=scope.issue)
    if route == "v2":
        client = session_client
        url = f"/api/assets/v2/user-assets/{asset.id}/"
    else:
        client = api_key_client
        url = f"/api/v1/assets/user-assets/{asset.id}/" + ("server/" if route == "token-server" else "")
    response = client.delete(url)
    assert response.status_code == (403 if has_parent else 204), getattr(response, "data", None)
    asset.refresh_from_db()
    assert asset.is_deleted == (not has_parent)


@pytest.mark.parametrize("foreign_parent", [False, True])
def test_legacy_personal_upload_and_collection_keep_owner_scope(session_client, scope, tmp_path, foreign_parent):
    from django.core.files.uploadedfile import SimpleUploadedFile

    payload = {"asset": SimpleUploadedFile("personal.png", b"bounded-fixture", content_type="image/png")}
    if foreign_parent:
        payload["project"] = str(scope.foreign_project.id)
    storage = {"default": {"BACKEND": "django.core.files.storage.FileSystemStorage",
                           "OPTIONS": {"location": str(tmp_path)}}}
    with override_settings(STORAGES=storage):
        response = session_client.post("/api/users/file-assets/", payload, format="multipart")
        assert response.status_code == (403 if foreign_parent else 201), response.data
        if foreign_parent:
            assert not list(tmp_path.rglob("*.png"))
        else:
            asset = FileAsset.objects.get(pk=response.data["id"])
            url = f"/api/users/file-assets/{asset.asset.name}/"
            listing = session_client.get(url)
            assert listing.status_code == 200 and len(listing.data["data"]) == 1
            assert session_client.delete(url).status_code == 204


@pytest.mark.parametrize("access", ["private-source", "private-target", "inactive-project", "inactive-workspace",
                                    "removed-link", "missing-user", "inactive-user", "foreign-target", "valid"])
def test_background_copy_rechecks_source_and_destination_authority(scope, monkeypatch, access):
    from plane.bgtasks import copy_s3_object

    membership(scope)
    source_page = Page.objects.create(workspace=scope.workspace, owned_by=scope.owner, name="Source")
    ProjectPage.objects.create(workspace=scope.workspace, project=scope.project, page=source_page)
    source = FileAsset.objects.create(workspace=scope.workspace, project=scope.project, page=source_page,
        entity_type="PAGE_DESCRIPTION", asset="source-page.png", is_uploaded=True,
        attributes={"name": "source.png", "type": "image/png", "size": 12})
    user_id = scope.user.pk
    target = scope.page
    if access == "private-source":
        Page.objects.filter(pk=source_page.pk).update(access=Page.PRIVATE_ACCESS)
    elif access == "private-target":
        Page.objects.filter(pk=target.pk).update(access=Page.PRIVATE_ACCESS, owned_by_id=scope.owner.pk)
    elif access == "inactive-project":
        ProjectMember.objects.filter(project=scope.project, member=scope.user).update(is_active=False)
    elif access == "inactive-workspace":
        WorkspaceMember.objects.filter(workspace=scope.workspace, member=scope.user).update(is_active=False)
    elif access == "removed-link":
        ProjectPage.objects.filter(page=source_page).update(deleted_at=timezone.now())
    elif access == "missing-user":
        user_id = None
    elif access == "inactive-user":
        User.objects.filter(pk=scope.user.pk).update(is_active=False)
    elif access == "foreign-target":
        target = Page.objects.create(workspace=scope.foreign, owned_by=scope.owner, name="Foreign")
    factory = Mock(return_value=scope.storage)
    monkeypatch.setattr(copy_s3_object, "S3Storage", factory)
    before = FileAsset.objects.count()
    mappings = copy_s3_object.copy_assets(target, target.id, scope.project.id, [source.pk], user_id)
    if access == "valid":
        assert len(mappings) == 1 and FileAsset.objects.count() == before + 1
        new = FileAsset.objects.get(pk=mappings[0]["new_asset_id"])
        assert new.page_id == target.id and new.project_id == scope.project.id and new.is_uploaded
        assert new.created_by_id == scope.user.pk
        factory.assert_called_once_with(is_server=True)
    else:
        assert mappings == [] and FileAsset.objects.count() == before
        factory.assert_not_called()


def test_background_copy_skips_private_objects_in_a_mixed_batch(scope, monkeypatch):
    from plane.bgtasks import copy_s3_object

    membership(scope)
    private = Page.objects.create(workspace=scope.workspace, owned_by=scope.owner,
                                   access=Page.PRIVATE_ACCESS, name="Private")
    ProjectPage.objects.create(workspace=scope.workspace, project=scope.project, page=private)
    assets = [FileAsset.objects.create(workspace=scope.workspace, project=scope.project, page=page,
                entity_type="PAGE_DESCRIPTION", asset=f"source-{page.id}.png", is_uploaded=True,
                attributes={"name": "source.png", "type": "image/png", "size": 12})
              for page in (scope.page, private)]
    monkeypatch.setattr(copy_s3_object, "S3Storage", Mock(return_value=scope.storage))
    mappings = copy_s3_object.copy_assets(scope.page, scope.page.id, scope.project.id,
                                         [asset.pk for asset in assets], scope.user.pk)
    assert len(mappings) == 1 and mappings[0]["old_asset_id"] == str(assets[0].pk)
    scope.storage.copy_object.assert_called_once()


def test_background_copy_sanitizes_object_key_names(scope, monkeypatch):
    from plane.bgtasks import copy_s3_object

    membership(scope)
    scope.asset.attributes["name"] = "../../nested/secret.png"
    scope.asset.save(update_fields=["attributes"])
    monkeypatch.setattr(copy_s3_object, "S3Storage", Mock(return_value=scope.storage))
    mappings = copy_s3_object.copy_assets(scope.issue, scope.issue.id, scope.project.id,
                                         [scope.asset.pk], scope.user.pk)
    assert len(mappings) == 1
    key = scope.storage.copy_object.call_args.args[1]
    assert key.startswith(f"{scope.workspace.id}/") and key.count("/") == 1 and key.endswith("-secret.png")


@pytest.mark.parametrize("access", ["inactive-user", "inactive-project", "private-target", "valid"])
def test_document_copy_job_checks_empty_documents_and_preserves_attribution(scope, monkeypatch, access):
    import base64
    from plane.bgtasks import copy_s3_object

    membership(scope)
    Page.objects.filter(pk=scope.page.pk).update(created_by_id=scope.owner.pk,
        description_html="<p>No assets</p>", description_binary=b"original")
    if access == "inactive-user":
        User.objects.filter(pk=scope.user.pk).update(is_active=False)
    elif access == "inactive-project":
        ProjectMember.objects.filter(member=scope.user, project=scope.project).update(is_active=False)
    elif access == "private-target":
        Page.objects.filter(pk=scope.page.pk).update(owned_by_id=scope.owner.pk, access=Page.PRIVATE_ACCESS)
    factory = Mock(return_value=scope.storage)
    sync = Mock(return_value={"description_json": {"type": "doc"},
                              "description_binary": base64.b64encode(b"converted").decode()})
    monkeypatch.setattr(copy_s3_object, "S3Storage", factory)
    monkeypatch.setattr(copy_s3_object, "sync_with_external_service", sync)
    scope.page.refresh_from_db()
    before = scope.page.updated_at
    copy_s3_object.copy_s3_objects_of_description_and_assets(
        "PAGE", scope.page.pk, scope.project.pk, scope.workspace.slug, scope.user.pk,
    )
    scope.page.refresh_from_db()
    factory.assert_not_called()
    assert scope.page.created_by_id == scope.owner.pk
    if access == "valid":
        sync.assert_called_once()
        assert bytes(scope.page.description_binary) == b"converted"
        assert scope.page.updated_by_id == scope.user.pk
    else:
        sync.assert_not_called()
        assert bytes(scope.page.description_binary) == b"original"
        assert scope.page.updated_at == before
