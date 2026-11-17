# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import logging
import re


def log_exception(e, warning=False):
    logger = logging.getLogger("plane.exception")
    # Exceptions can contain request bodies, credentials, URLs and database
    # values. Preserve a bounded category without rendering the object/cause.
    category = type(e).__name__
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", category) is None:
        category = "Exception"
    logger.log(logging.WARNING if warning else logging.ERROR, "Application operation failed",
               extra={"exception_type": category})
