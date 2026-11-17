# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import uuid
import base64
import requests
from bs4 import BeautifulSoup

# Django imports
from django.conf import settings

# Module imports
from plane.db.models import FileAsset, Page, Issue, User
from plane.utils.exception_logger import log_exception
from plane.utils.asset_permissions import has_asset_access, target_fields
from plane.utils.path_validator import sanitize_filename
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from plane.settings.storage import S3Storage
from celery import shared_task
from plane.utils.url import normalize_url_path


def extract_asset_ids(html, tag):
    try:
        soup = BeautifulSoup(html, "html.parser")
        return [tag.get("src") for tag in soup.find_all(tag) if tag.get("src")]
    except Exception as e:
        log_exception(e)
        return []


def replace_asset_ids(html, tag, duplicated_assets):
    try:
        soup = BeautifulSoup(html, "html.parser")
        for mention_tag in soup.find_all(tag):
            for asset in duplicated_assets:
                if mention_tag.get("src") == asset["old_asset_id"]:
                    mention_tag["src"] = asset["new_asset_id"]
        return str(soup)
    except Exception as e:
        log_exception(e)
        return html


def update_description(entity, duplicated_assets, tag):
    updated_html = replace_asset_ids(entity.description_html, tag, duplicated_assets)
    entity.description_html = updated_html
    entity.save(disable_auto_set_user=True)
    return updated_html


# Get the description binary and description from the live server
def sync_with_external_service(entity_name, description_html):
    try:
        data = {
            "description_html": description_html,
            "variant": "rich" if entity_name == "PAGE" else "document",
        }

        live_url = settings.LIVE_URL
        if not live_url:
            return {}

        url = normalize_url_path(f"{live_url}/convert-document/")

        response = requests.post(url, json=data, headers=None, timeout=(5, 30))
        if response.status_code == 200:
            return response.json()
    except requests.RequestException as e:
        log_exception(e)
    return {}


def copy_assets(entity, entity_identifier, project_id, asset_ids, user_id):
    duplicated_assets = []
    workspace = entity.workspace
    user = User.objects.filter(id=user_id, is_active=True).first()
    if user is None:
        return []
    storage = None
    original_assets = FileAsset.objects.filter(workspace=workspace, project_id=project_id, id__in=asset_ids)

    for original_asset in original_assets:
        # The job can run after membership/ownership changed, and editor HTML
        # can contain another page's UUID. Reauthorize both sides at execution.
        if not has_asset_access(user, original_asset):
            continue
        try:
            fields = target_fields(user, workspace.id, original_asset.entity_type, entity_identifier, project_id)
        except (NotFound, PermissionDenied, ValidationError):
            continue
        if storage is None:
            storage = S3Storage(is_server=True)
        name = sanitize_filename(original_asset.attributes.get("name")) or "unnamed"
        destination_key = f"{workspace.id}/{uuid.uuid4().hex}-{name}"
        # Failed copies must not create uploaded rows or replace document asset
        # references. A successful object copy precedes each published row.
        if storage.copy_object(original_asset.asset, destination_key) is None:
            continue
        duplicated_asset = FileAsset(
            attributes={
                "name": original_asset.attributes.get("name"),
                "type": original_asset.attributes.get("type"),
                "size": original_asset.attributes.get("size"),
            },
            asset=destination_key,
            size=original_asset.size,
            workspace=workspace,
            created_by_id=user_id,
            entity_type=original_asset.entity_type,
            storage_metadata=original_asset.storage_metadata,
            is_uploaded=True,
            **fields,
        )
        duplicated_asset.save(created_by_id=user.id)
        duplicated_assets.append(
            {
                "new_asset_id": str(duplicated_asset.id),
                "old_asset_id": str(original_asset.id),
            }
        )
    return duplicated_assets


@shared_task
def copy_s3_objects_of_description_and_assets(entity_name, entity_identifier, project_id, slug, user_id):
    """
    Step 1: Extract asset ids from the description_html of the entity
    Step 2: Duplicate the assets
    Step 3: Update the description_html of the entity with the new asset ids (change the src of img tag)
    Step 4: Request the live server to generate the description_binary and description for the entity

    """
    try:
        model_class = {"PAGE": Page, "ISSUE": Issue}.get(entity_name)
        if not model_class:
            raise ValueError(f"Unsupported entity_name: {entity_name}")

        entity = model_class.objects.get(id=entity_identifier)
        user = User.objects.filter(id=user_id, is_active=True).first()
        if user is None:
            return []
        target_kind = (FileAsset.EntityTypeContext.PAGE_DESCRIPTION if entity_name == "PAGE"
                       else FileAsset.EntityTypeContext.ISSUE_DESCRIPTION)
        target_fields(user, entity.workspace_id, target_kind, entity.id, project_id)
        entity.updated_by = user
        asset_ids = extract_asset_ids(entity.description_html, "image-component")

        duplicated_assets = copy_assets(entity, entity_identifier, project_id, asset_ids, user_id)

        updated_html = update_description(entity, duplicated_assets, "image-component")

        external_data = sync_with_external_service(entity_name, updated_html)

        if external_data:
            entity.description_json = external_data.get("description_json")
            entity.description_binary = base64.b64decode(external_data.get("description_binary"))
            entity.save(disable_auto_set_user=True)

        return
    except Exception as e:
        log_exception(e)
        return []
