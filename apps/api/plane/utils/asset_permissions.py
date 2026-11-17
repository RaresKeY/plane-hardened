"""Keep signed URLs, copies and asset mutations within their resource scope."""

from uuid import UUID

from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError

from plane.db.models import (
    DraftIssue, FileAsset, Issue, IssueComment, Page, Project, ProjectMember,
    ProjectPage, WorkspaceMember,
)


KINDS = FileAsset.EntityTypeContext
PARENTS = {
    KINDS.ISSUE_ATTACHMENT: (Issue, "issue_id"),
    KINDS.ISSUE_DESCRIPTION: (Issue, "issue_id"),
    KINDS.COMMENT_DESCRIPTION: (IssueComment, "comment_id"),
    KINDS.PAGE_DESCRIPTION: (Page, "page_id"),
    KINDS.DRAFT_ISSUE_DESCRIPTION: (DraftIssue, "draft_issue_id"),
    KINDS.DRAFT_ISSUE_ATTACHMENT: (DraftIssue, "draft_issue_id"),
}


def identifier(value):
    if value is None:
        return None
    if not isinstance(value, (str, UUID)):
        raise ValidationError("Invalid asset target identifier.")
    try:
        return UUID(str(value))
    except ValueError:
        raise ValidationError("Invalid asset target identifier.") from None


def workspace_role(user, workspace_id):
    role = WorkspaceMember.objects.filter(
        member=user, workspace_id=workspace_id, is_active=True, role__in=[5, 15, 20],
    ).values_list("role", flat=True).first()
    if role is None:
        raise PermissionDenied("You don't have access to this asset.")
    return role


def project_role(user, workspace_id, project_id):
    # Check both the resource and membership workspace: inconsistent legacy rows
    # must not turn a foreign project into a locally authorized resource.
    if not Project.objects.filter(id=project_id, workspace_id=workspace_id).exists():
        raise NotFound("Asset target not found.")
    role = ProjectMember.objects.filter(
        member=user, workspace_id=workspace_id, project_id=project_id,
        is_active=True, role__in=[5, 15, 20],
    ).values_list("role", flat=True).first()
    if role is None:
        raise PermissionDenied("You don't have access to this asset.")
    return role


def target_fields(user, workspace_id, entity_type, entity_id=None, project_id=None, *, write=True,
                  staging=False):
    """Resolve a coherent target before any storage operation or asset write.

    Editors upload before saving their parent. Only upload creation may stage an
    unassociated cover/page; existing parent IDs always require real scope checks.
    """
    if entity_type not in KINDS.values:
        raise ValidationError("Invalid asset entity type.")
    entity_id, project_id = identifier(entity_id), identifier(project_id)
    role = workspace_role(user, workspace_id)
    if entity_type in (KINDS.USER_AVATAR, KINDS.USER_COVER, KINDS.WORKSPACE_LOGO):
        if project_id is not None:
            raise ValidationError("Workspace asset cannot have a project target.")
        if entity_type == KINDS.WORKSPACE_LOGO:
            if entity_id is not None and entity_id != workspace_id:
                raise NotFound("Asset target not found.")
            if write and role != 20:
                raise PermissionDenied("Only workspace admins can change the workspace logo.")
            return {}
        if write and entity_id is not None and entity_id != user.id:
            raise PermissionDenied("You can only change your own profile assets.")
        return {"user_id": entity_id or user.id}

    if entity_type == KINDS.PROJECT_COVER:
        if project_id and entity_id and project_id != entity_id:
            raise NotFound("Asset target not found.")
        project_id = project_id or entity_id
        if project_id is None:
            if staging:
                return {"project_id": None}
            raise ValidationError("A project target is required.")
        project_role(user, workspace_id, project_id)
        return {"project_id": project_id}

    model, field = PARENTS[entity_type]
    parent = None
    if entity_id is not None:
        parent = model.objects.filter(id=entity_id, workspace_id=workspace_id).first()
        if parent is None:
            raise NotFound("Asset target not found.")
        if model is not Page:
            if project_id and parent.project_id != project_id:
                raise NotFound("Asset target not found.")
            project_id = parent.project_id
    if project_id is not None:
        member_role = project_role(user, workspace_id, project_id)
    else:
        member_role = role

    if model is Page and parent is not None:
        links = ProjectPage.objects.filter(page=parent, workspace_id=workspace_id, deleted_at__isnull=True)
        if project_id is not None:
            if not links.filter(project_id=project_id).exists():
                raise NotFound("Asset target not found.")
        elif not parent.is_global:
            roles = list(ProjectMember.objects.filter(
                member=user, workspace_id=workspace_id, is_active=True, role__in=[5, 15, 20],
                project__workspace_id=workspace_id, project_id__in=links.values("project_id"),
            ).values_list("role", flat=True))
            if not roles:
                raise PermissionDenied("You don't have access to this asset.")
            member_role = max(roles)
        if parent.owned_by_id != user.id and (
            parent.access == Page.PRIVATE_ACCESS or (write and member_role not in [15, 20])
        ):
            raise PermissionDenied("You don't have access to this asset.")
    elif model is DraftIssue and parent is not None:
        if parent.created_by_id != user.id:
            raise PermissionDenied("You don't have access to this draft asset.")
    elif model is IssueComment and parent is not None and write:
        if parent.created_by_id != user.id and member_role != 20 and role != 20:
            raise PermissionDenied("You don't have access to this comment asset.")

    if project_id is None and parent is None and not (staging and model is Page):
        raise ValidationError("An existing entity or project target is required.")
    return {"project_id": project_id, field: entity_id}


def has_asset_access(user, asset, *, write=False):
    """Authorize shared-table callers, including legacy rows without entity_type."""
    try:
        references = [(kind, field, getattr(asset, field)) for kind, (_model, field) in PARENTS.items()
                      if getattr(asset, field)]
        if asset.workspace_id is None:
            # Personal legacy uploads have no workspace. A workspace resource
            # cannot be laundered through a personal-file route or user FK.
            return (not references and asset.project_id is None
                    and asset.entity_type in (None, "", KINDS.USER_AVATAR, KINDS.USER_COVER)
                    and (asset.user_id == user.id or (asset.user_id is None and asset.created_by_id == user.id)))
        role = workspace_role(user, asset.workspace_id)
        if write and asset.user_id is not None and asset.user_id != user.id:
            return False
        # Legacy serializers accepted more than one parent. Check every stored
        # reference, not only the field named by entity_type.
        seen = set()
        for kind, field, entity_id in references:
            if field not in seen:
                target_fields(user, asset.workspace_id, kind, entity_id, asset.project_id, write=write)
                seen.add(field)
        kind = asset.entity_type
        if kind in (None, ""):
            if asset.project_id is not None:
                project_role(user, asset.workspace_id, asset.project_id)
                return True
            if references:
                return True
            return not write or asset.created_by_id == user.id or role == 20
        if kind not in KINDS.values:
            return False
        field = PARENTS.get(kind, (None, None))[1]
        entity_id = getattr(asset, field) if field else None
        if kind in (KINDS.USER_AVATAR, KINDS.USER_COVER):
            if write and asset.user_id != user.id:
                return False
            entity_id = asset.user_id
        elif kind == KINDS.WORKSPACE_LOGO:
            entity_id = asset.workspace_id
        elif kind == KINDS.PROJECT_COVER:
            entity_id = asset.project_id
        pending = not references and not entity_id and not asset.project_id
        if pending and (asset.created_by_id == user.id or (
            kind == KINDS.ISSUE_ATTACHMENT and asset.created_by_id is None and (not write or role == 20)
        )):
            return True
        target_fields(user, asset.workspace_id, kind, entity_id, asset.project_id, write=write)
        return True
    except (PermissionDenied, NotFound, ValidationError):
        return False


def require_asset_access(user, asset, *, write=False):
    if not has_asset_access(user, asset, write=write):
        raise PermissionDenied("You don't have access to this asset.")
