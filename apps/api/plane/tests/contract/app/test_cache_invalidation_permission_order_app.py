# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Contract tests: a write endpoint invalidates its cache only after the role check passes."""

from unittest.mock import patch

import pytest
from rest_framework import status

from plane.db.models import Label, Project, ProjectMember, State, WorkspaceMember
from plane.tests.factories import WorkspaceFactory

INVALIDATE = "plane.utils.cache.invalidate_cache_directly"


@pytest.fixture
def project(db, workspace, create_user):
    project = Project.objects.create(name="Cache", identifier="CCH", workspace=workspace)
    ProjectMember.objects.create(workspace=workspace, project=project, member=create_user, role=20, is_active=True)
    return project


def _project_url(workspace, project, resource):
    return f"/api/workspaces/{workspace.slug}/projects/{project.id}/{resource}/"


@pytest.mark.contract
class TestCacheInvalidationPermissionOrder:
    @pytest.mark.django_db
    @pytest.mark.parametrize(
        "resource, payload",
        [
            ("issue-labels", {"name": "Bug"}),
            ("states", {"name": "Review", "color": "#000000", "group": "started"}),
        ],
    )
    def test_denied_project_write_does_not_invalidate_cache(
        self, session_client, workspace, project, create_user, resource, payload
    ):
        # A workspace and project member: allowed into the project, but not an admin
        WorkspaceMember.objects.filter(workspace=workspace, member=create_user).update(role=15)
        ProjectMember.objects.filter(project=project, member=create_user).update(role=15)

        with patch(INVALIDATE) as invalidate:
            response = session_client.post(_project_url(workspace, project, resource), payload, format="json")

        assert response.status_code == status.HTTP_403_FORBIDDEN
        invalidate.assert_not_called()

    @pytest.mark.django_db
    def test_denied_workspace_leave_does_not_invalidate_cache(self, session_client):
        other_workspace = WorkspaceFactory()

        with patch(INVALIDATE) as invalidate:
            response = session_client.post(f"/api/workspaces/{other_workspace.slug}/members/leave/")

        assert response.status_code == status.HTTP_403_FORBIDDEN
        invalidate.assert_not_called()

    @pytest.mark.django_db
    def test_allowed_write_still_invalidates_cache(self, session_client, workspace, project):
        with patch(INVALIDATE) as invalidate:
            response = session_client.post(
                _project_url(workspace, project, "issue-labels"), {"name": "Bug"}, format="json"
            )

        assert response.status_code == status.HTTP_201_CREATED, response.data
        invalidate.assert_called_once()

    @pytest.mark.django_db
    @pytest.mark.parametrize("role", [5, 15])
    @pytest.mark.parametrize("operation", ["label-patch", "label-delete", "state-default", "state-delete"])
    def test_denied_mutations_preserve_objects_and_cache(
        self, session_client, workspace, project, create_user, role, operation
    ):
        WorkspaceMember.objects.filter(workspace=workspace, member=create_user).update(role=role)
        ProjectMember.objects.filter(project=project, member=create_user).update(role=role)
        label = Label.objects.create(name="Original", workspace=workspace, project=project)
        state = State.objects.create(
            name="Original", color="#000000", group="started", default=False, workspace=workspace, project=project
        )
        label_url = _project_url(workspace, project, f"issue-labels/{label.id}")
        state_url = _project_url(workspace, project, f"states/{state.id}")

        with patch(INVALIDATE) as invalidate:
            if operation == "label-patch":
                response = session_client.patch(label_url, {"name": "Changed"}, format="json")
            elif operation == "label-delete":
                response = session_client.delete(label_url)
            elif operation == "state-default":
                response = session_client.post(state_url + "mark-default/")
            else:
                response = session_client.delete(state_url)

        assert response.status_code == status.HTTP_403_FORBIDDEN, response.data
        invalidate.assert_not_called()
        label.refresh_from_db()
        state.refresh_from_db()
        assert label.name == state.name == "Original"
        assert label.deleted_at is None and state.deleted_at is None and not state.default

    @pytest.mark.django_db
    @pytest.mark.parametrize("operation", ["label-patch", "label-delete", "state-default", "state-delete"])
    def test_allowed_mutations_still_invalidate_cache(self, session_client, workspace, project, operation):
        label = Label.objects.create(name="Original", workspace=workspace, project=project)
        state = State.objects.create(
            name="Original", color="#000000", group="started", default=False, workspace=workspace, project=project
        )
        with patch(INVALIDATE) as invalidate:
            if operation == "label-patch":
                response = session_client.patch(
                    _project_url(workspace, project, f"issue-labels/{label.id}"), {"name": "Changed"}, format="json"
                )
            elif operation == "label-delete":
                response = session_client.delete(_project_url(workspace, project, f"issue-labels/{label.id}"))
            elif operation == "state-default":
                response = session_client.post(_project_url(workspace, project, f"states/{state.id}/mark-default"))
            else:
                response = session_client.delete(_project_url(workspace, project, f"states/{state.id}"))

        assert response.status_code in (status.HTTP_200_OK, status.HTTP_204_NO_CONTENT), response.data
        invalidate.assert_called_once()

    @pytest.mark.django_db
    def test_allowed_member_leave_still_invalidates_all_three_caches(self, session_client, workspace, create_user):
        # Ownership is a separate rule: a regular member can leave, an owner cannot.
        workspace.owner = WorkspaceFactory().owner
        workspace.save(update_fields=["owner"])
        WorkspaceMember.objects.filter(workspace=workspace, member=create_user).update(role=15)
        with patch(INVALIDATE) as invalidate:
            response = session_client.post(f"/api/workspaces/{workspace.slug}/members/leave/")

        assert response.status_code == status.HTTP_204_NO_CONTENT, response.data
        assert invalidate.call_count == 3
        assert not WorkspaceMember.objects.filter(workspace=workspace, member=create_user, is_active=True).exists()
