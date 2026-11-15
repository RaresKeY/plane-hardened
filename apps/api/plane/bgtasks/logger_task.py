# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import logging
from typing import Dict, Any

# Third party imports
from celery import shared_task

# Django imports
from plane.utils.request_logging import AUDIT_SCHEMA, activity_metadata
from plane.db.models import APIActivityLog


logger = logging.getLogger("plane.worker")


def log_to_postgres(log_data: Dict[str, Any]) -> bool:
    """
    Persist an external API request log to PostgreSQL.
    """
    try:
        APIActivityLog.objects.create(**log_data)
        return True
    except Exception:
        # Database exception strings can echo values; never serialize audit input.
        logger.warning("Could not persist API activity metadata")
        return False


@shared_task
def process_logs(log_data: Dict[str, Any], audit_schema=None, **_: Any) -> None:
    """
    Persist external API request logs to PostgreSQL.

    Old queued records can contain raw credentials. Discard them without logging
    their values, rather than reintroducing secrets after a producer upgrade.
    """
    if type(audit_schema) is not int or audit_schema != AUDIT_SCHEMA:
        logger.warning("Discarded legacy API activity payload")
        return
    metadata = activity_metadata(log_data)
    if metadata is None:
        logger.warning("Discarded invalid API activity metadata")
        return
    log_to_postgres(metadata)
