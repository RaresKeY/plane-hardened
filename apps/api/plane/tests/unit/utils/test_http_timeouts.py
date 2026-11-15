# Copyright (c) 2026 Plane hardened fork contributors
# SPDX-License-Identifier: AGPL-3.0-only

import logging
from unittest.mock import Mock, patch

from django.test import RequestFactory, override_settings
import pytest
import requests

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.adapter.oauth import OauthAdapter
from plane.bgtasks.copy_s3_object import sync_with_external_service


pytestmark = pytest.mark.unit


@pytest.fixture
def adapter():
    result = OauthAdapter(
        request=RequestFactory().get("/"),
        provider="github",
        client_id="fixture",
        scope="openid",
        redirect_uri="http://localhost/callback",
        auth_url="https://provider.example/authorize",
        token_url="https://provider.example/token",
        userinfo_url="https://provider.example/userinfo",
    )
    result.token_data = {"access_token": "private-synthetic-token"}
    return result


@pytest.mark.parametrize("method,verb", [("get_user_token", "post"), ("get_user_response", "get")])
def test_oauth_success_preserves_provider_response_and_bounds_request(adapter, method, verb):
    response = Mock()
    response.json.return_value = {"id": "test-user"}
    with patch("plane.authentication.adapter.oauth.requests." + verb, return_value=response) as send:
        result = getattr(adapter, method)({"code": "test-code"}) if verb == "post" else getattr(adapter, method)()
    assert result == {"id": "test-user"}
    response.raise_for_status.assert_called_once()
    assert send.call_args.kwargs["timeout"] == (5, 30)


@pytest.mark.parametrize("method,verb", [("get_user_token", "post"), ("get_user_response", "get")])
@pytest.mark.parametrize("error", [requests.ConnectTimeout, requests.ReadTimeout, requests.HTTPError])
def test_oauth_network_failure_cannot_authenticate_or_leak_request_values(adapter, method, verb, error, caplog):
    secret = "private-synthetic-token"
    with patch("plane.authentication.adapter.oauth.requests." + verb, side_effect=error(secret)):
        with caplog.at_level(logging.WARNING):
            with pytest.raises(AuthenticationException) as raised:
                if verb == "post":
                    adapter.get_user_token({"code": secret})
                else:
                    adapter.get_user_response()
    assert secret not in str(raised.value)
    assert secret not in caplog.text


@pytest.mark.parametrize("entity", ["PAGE", "ISSUE"])
def test_document_conversion_keeps_successful_service_response_and_finite_wait(entity):
    response = Mock(status_code=200)
    response.json.return_value = {"document": "converted"}
    with override_settings(LIVE_URL="http://live-fixture:3000"):
        with patch("plane.bgtasks.copy_s3_object.requests.post", return_value=response) as send:
            assert sync_with_external_service(entity, "<p>fixture</p>") == {"document": "converted"}
    assert send.call_args.kwargs["timeout"] == (5, 30)
