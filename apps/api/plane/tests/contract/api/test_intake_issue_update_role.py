# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Contract tests for who may update an intake work item through the external API.

``IntakeIssueDetailAPIEndpoint.patch`` follows the web app's rule: the work
item's creator, a project admin, or a workspace admin who is in the project.
"""

import pytest
from rest_framework import status

from plane.db.models import Intake, IntakeIssue, Issue, Project, ProjectMember, State, WorkspaceMember
from plane.tests.factories import UserFactory
from plane.tests.conftest_external import mock_celery as mock_celery

ADMIN, MEMBER = 20, 15


@pytest.fixture
def project(db, workspace):
    project = Project.objects.create(name="Intake Project", identifier="IP", workspace=workspace, intake_view=True)
    State.objects.create(
        name="Triage", color="#000000", group="triage", default=True, project=project, workspace=workspace
    )
    return project


def _join(workspace, project, user, role):
    """Give ``user`` the same role in the workspace and the project."""
    WorkspaceMember.objects.update_or_create(workspace=workspace, member=user, defaults={"role": role})
    ProjectMember.objects.create(project=project, member=user, workspace=workspace, role=role, is_active=True)


def _intake_issue(workspace, project, created_by):
    intake = Intake.objects.create(name="Intake", project=project, workspace=workspace, is_default=True)
    issue = Issue(name="Intake Issue", project=project, workspace=workspace)
    # Outside a request BaseModel.save() clears created_by unless it is passed here
    issue.save(created_by_id=created_by.id)
    IntakeIssue(intake=intake, issue=issue, project=project, workspace=workspace).save(created_by_id=created_by.id)
    return issue


def _rename(client, workspace, project, issue):
    url = f"/api/v1/workspaces/{workspace.slug}/projects/{project.id}/intake-issues/{issue.id}/"
    return client.patch(url, {"issue": {"name": "Renamed"}}, format="json")


@pytest.mark.contract
@pytest.mark.usefixtures("mock_celery")
class TestIntakeIssueUpdateRole:
    @pytest.mark.django_db
    def test_member_cannot_update_another_users_intake_issue(self, api_key_client, workspace, project, create_user):
        _join(workspace, project, create_user, MEMBER)
        issue = _intake_issue(workspace, project, created_by=UserFactory())

        response = _rename(api_key_client, workspace, project, issue)

        assert response.status_code == status.HTTP_403_FORBIDDEN, response.data
        issue.refresh_from_db()
        assert issue.name == "Intake Issue"

    @pytest.mark.django_db
    def test_member_can_update_own_intake_issue(self, api_key_client, workspace, project, create_user):
        _join(workspace, project, create_user, MEMBER)
        issue = _intake_issue(workspace, project, created_by=create_user)

        response = _rename(api_key_client, workspace, project, issue)

        assert response.status_code == status.HTTP_200_OK, response.data
        issue.refresh_from_db()
        assert issue.name == "Renamed"

    @pytest.mark.django_db
    def test_project_admin_can_update_another_users_intake_issue(self, api_key_client, workspace, project, create_user):
        # A workspace member, so the project role is what grants access
        _join(workspace, project, create_user, MEMBER)
        ProjectMember.objects.filter(project=project, member=create_user).update(role=ADMIN)
        issue = _intake_issue(workspace, project, created_by=UserFactory())

        response = _rename(api_key_client, workspace, project, issue)

        assert response.status_code == status.HTTP_200_OK, response.data
        issue.refresh_from_db()
        assert issue.name == "Renamed"

    @pytest.mark.django_db
    def test_workspace_admin_in_project_can_update_another_users_issue(
        self, api_key_client, workspace, project, create_user
    ):
        _join(workspace, project, create_user, MEMBER)
        WorkspaceMember.objects.filter(workspace=workspace, member=create_user).update(role=ADMIN)
        issue = _intake_issue(workspace, project, created_by=UserFactory())

        response = _rename(api_key_client, workspace, project, issue)

        assert response.status_code == status.HTTP_200_OK, response.data
        issue.refresh_from_db()
        assert issue.name == "Renamed"

    @pytest.mark.django_db
    @pytest.mark.parametrize("role", [5, MEMBER])
    def test_creator_can_update_own_issue(self, api_key_client, workspace, project, create_user, role):
        _join(workspace, project, create_user, role)
        issue = _intake_issue(workspace, project, created_by=create_user)

        response = _rename(api_key_client, workspace, project, issue)

        assert response.status_code == status.HTTP_200_OK, response.data
        issue.refresh_from_db()
        assert issue.name == "Renamed"

    @pytest.mark.django_db
    @pytest.mark.parametrize("project_membership", ["absent", "inactive"])
    def test_workspace_admin_still_needs_active_project_membership(
        self, api_key_client, workspace, project, create_user, project_membership
    ):
        _join(workspace, project, create_user, ADMIN)
        membership = ProjectMember.objects.filter(project=project, member=create_user)
        if project_membership == "absent":
            membership.delete()
        else:
            membership.update(is_active=False)
        issue = _intake_issue(workspace, project, created_by=UserFactory())

        response = _rename(api_key_client, workspace, project, issue)

        assert response.status_code == status.HTTP_403_FORBIDDEN, response.data
        issue.refresh_from_db()
        assert issue.name == "Intake Issue"

    @pytest.mark.django_db
    def test_inactive_workspace_admin_does_not_gain_admin_override(
        self, api_key_client, workspace, project, create_user
    ):
        _join(workspace, project, create_user, MEMBER)
        WorkspaceMember.objects.filter(workspace=workspace, member=create_user).update(role=ADMIN, is_active=False)
        issue = _intake_issue(workspace, project, created_by=UserFactory())

        response = _rename(api_key_client, workspace, project, issue)

        assert response.status_code == status.HTTP_403_FORBIDDEN, response.data
        issue.refresh_from_db()
        assert issue.name == "Intake Issue"

    @pytest.mark.django_db
    def test_admin_role_in_other_workspace_does_not_grant_access(self, api_key_client, workspace, project, create_user):
        from plane.tests.factories import WorkspaceFactory

        _join(workspace, project, create_user, MEMBER)
        other = WorkspaceFactory()
        WorkspaceMember.objects.create(workspace=other, member=create_user, role=ADMIN, is_active=True)
        issue = _intake_issue(workspace, project, created_by=UserFactory())

        response = _rename(api_key_client, workspace, project, issue)

        assert response.status_code == status.HTTP_403_FORBIDDEN, response.data
        issue.refresh_from_db()
        assert issue.name == "Intake Issue"
