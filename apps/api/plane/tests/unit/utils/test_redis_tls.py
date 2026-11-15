# Copyright (c) 2026 Plane hardened fork contributors
# SPDX-License-Identifier: AGPL-3.0-only

from unittest.mock import patch

import pytest
from django.conf import settings
from django.test import override_settings

from plane.utils.redis_tls import redis_tls_options


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "url", [None, "redis://localhost:6379/0", "redis://rediss-password@localhost:6379/0", "unix:///tmp/redis.sock"]
)
def test_plaintext_and_unix_transports_remain_compatible(url):
    assert redis_tls_options(url) == {}


def test_tls_requires_certificate_and_hostname_verification():
    assert redis_tls_options("rediss://user:password@redis.example:6380/2") == {
        "ssl_cert_reqs": "required",
        "ssl_check_hostname": True,
    }


@pytest.mark.parametrize(
    "query",
    [
        "ssl_cert_reqs=none",
        "ssl_cert_reqs=optional",
        "ssl_check_hostname=false",
        "ssl_check_hostname=0",
        "ssl_cert_reqs=required&ssl_cert_reqs=none",
        "ssl_cert_%72eqs=none",
        "ssl_cert_reqs=",
    ],
)
def test_url_cannot_override_verification(query):
    with pytest.raises(ValueError, match="must not be overridden") as error:
        redis_tls_options("rediss://user:private-fixture@redis.example/?" + query)
    assert "private-fixture" not in str(error.value)


def test_direct_client_preserves_url_and_enforces_checks():
    from plane.settings.redis import redis_instance

    url = "rediss://user:password@redis.example:6380/2"
    with override_settings(REDIS_URL=url):
        with patch("plane.settings.redis.redis.Redis.from_url") as factory:
            redis_instance()
    factory.assert_called_once_with(url, db=0, ssl_cert_reqs="required", ssl_check_hostname=True)


def test_cache_configuration_uses_the_shared_verified_options():
    # The restricted runner also imports common settings in a fresh rediss
    # process; this assertion covers its normal plaintext startup configuration.
    if settings.REDIS_SSL:
        assert settings.CACHES["default"]["OPTIONS"]["CONNECTION_POOL_KWARGS"] == redis_tls_options(settings.REDIS_URL)
    else:
        assert "CONNECTION_POOL_KWARGS" not in settings.CACHES["default"]["OPTIONS"]
