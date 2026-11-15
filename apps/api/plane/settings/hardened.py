# Copyright (c) 2026 Plane hardened fork contributors
# SPDX-License-Identifier: AGPL-3.0-only

"""Settings for the explicit immutable fork image; migrations are a separate job."""

from .production import *  # noqa: F403,F401

# A readonly application image sends bounded logs to its container collector.
LOGGING["handlers"].pop("file", None)  # noqa: F405
LOGGING["loggers"]["plane.exception"]["handlers"] = ["console"]  # noqa: F405
DEBUG = False
SCOUT_MONITOR = False

# A missing origin list must not grant credentialed access to arbitrary sites.
# Explicit CORS_ALLOWED_ORIGINS continues to select the operator's web clients.
CORS_ALLOW_ALL_ORIGINS = False
