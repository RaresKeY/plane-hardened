# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import redis
from django.conf import settings
from plane.utils.redis_tls import redis_tls_options


def redis_instance():
    # Preserve URL credentials, database and transport parameters while enforcing
    # verified TLS for rediss, consistently with Django's cache connection pool.
    return redis.Redis.from_url(settings.REDIS_URL, db=0, **redis_tls_options(settings.REDIS_URL))
