# Copyright (c) 2026 Plane hardened fork contributors
# SPDX-License-Identifier: AGPL-3.0-only

import copy
import json
from types import SimpleNamespace

import pytest
from hypothesis import given, settings, strategies as st

from plane.utils.request_logging import activity_metadata, safe_method, safe_route


pytestmark = pytest.mark.unit


def valid_record():
    return {
        "token_identifier": "a" * 64,
        "path": "/api/v1/workspaces/<str:slug>/projects/",
        "method": "GET",
        "response_code": 200,
        "ip_address": "127.0.0.1",
    }


@pytest.mark.parametrize("method", [None, 42, [], {}, "get", "GET\r\nInjected", "TOKEN-secret", ""])
def test_invalid_method_cannot_inject_log_content(method):
    assert safe_method(method) == "OTHER"


@pytest.mark.parametrize("route", [None, 42, "x" * 255, "api/\nsecret", "api/\rsecret"])
def test_missing_or_unsafe_resolver_uses_constant_label(route):
    assert safe_route(SimpleNamespace(resolver_match=SimpleNamespace(route=route))) == "/[unresolved]"


@pytest.mark.parametrize(
    "route,expected",
    [("", "/"), ("/api/", "/api/"), ("api/<str:slug>/", "/api/<str:slug>/"), ("a" * 254, "/" + "a" * 254)],
)
def test_normal_resolver_patterns_preserve_useful_route_label(route, expected):
    assert safe_route(SimpleNamespace(resolver_match=SimpleNamespace(route=route))) == expected


@pytest.mark.parametrize("data", [None, [], "secret", 1, True])
def test_non_mapping_record_rejected(data):
    assert activity_metadata(data) is None


@pytest.mark.parametrize(
    "token", [None, "plane_api_secret", "sha256:" + "a" * 64, "a" * 63, "a" * 65, "A" * 64, "a" * 63 + "\n", 0]
)
def test_only_current_keyed_identifier_shape_accepted(token):
    record = valid_record()
    record["token_identifier"] = token
    assert activity_metadata(record) is None


@pytest.mark.parametrize("status", [None, True, False, "200", 99, 600, -1, 200.0])
def test_invalid_status_rejected_without_type_coercion(status):
    record = valid_record()
    record["response_code"] = status
    assert activity_metadata(record) is None


@pytest.mark.parametrize("status", [100, 200, 204, 301, 403, 404, 429, 500, 599])
def test_normal_http_status_retained(status):
    record = valid_record()
    record["response_code"] = status
    assert activity_metadata(record)["response_code"] == status


@pytest.mark.parametrize("route", [None, 1, "", "not/absolute", "/" + "a" * 255, "/api/\r\nsecret"])
def test_invalid_route_at_worker_boundary_rejected(route):
    record = valid_record()
    record["path"] = route
    assert activity_metadata(record) is None


@pytest.mark.parametrize("route", [
    "/api/v1/workspaces/private-name/projects/",
    "/api/v1/workspaces/<str:slug>/projects/?token=synthetic-private",
    "/api/v1/workspaces/<str:slug>/projects/#synthetic-private",
    "/https://synthetic-private",
    "/api/synthetic-private/",
    "/api/v1/workspaces/%70rivate-name/projects/",
    "/api/v1/workspaces/<str:synthetic-private>/projects/",
])
def test_current_schema_worker_does_not_trust_queued_route_text(route):
    record = valid_record()
    record["path"] = route
    clean = activity_metadata(record)
    assert clean["path"] == "/[unresolved]"


def test_real_configured_route_retains_its_static_pattern():
    record = valid_record()
    assert activity_metadata(record)["path"] == record["path"]


@pytest.mark.parametrize("path", ["/api/items/12345678-1234-1234-1234-123456789abc/", "/legacy/items/example/", "/"])
def test_nested_path_regex_and_root_labels_match_django_resolution(path):
    from types import ModuleType
    from django.test import override_settings
    from django.urls import include, path as route, re_path, resolve

    config = ModuleType("synthetic_audit_routes")
    config.urlpatterns = [
        route("api/", include([route("items/<uuid:pk>/", lambda request: None)])),
        re_path(r"^legacy/", include([re_path(r"^items/(?P<slug>[-a-z]+)/$", lambda request: None)])),
        route("", lambda request: None),
    ]
    with override_settings(ROOT_URLCONF=config):
        match = resolve(path)
        record = valid_record()
        record["path"] = safe_route(SimpleNamespace(resolver_match=match))
        assert activity_metadata(record)["path"] == record["path"]


@settings(max_examples=150, derandomize=True)
@given(st.text(max_size=150))
def test_arbitrary_path_content_never_becomes_a_static_route(content):
    record = valid_record()
    record["path"] = "/synthetic-private-queue-marker/" + content
    clean = activity_metadata(record)
    if clean is not None:
        assert clean["path"] == "/[unresolved]"


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("::1", "::1"),
        ("2001:0db8::1", "2001:db8::1"),
        (None, None),
        ("1.2.3.4\r\nsecret", None),
        ("x" * 1000, None),
        (True, None),
        (123, None),
        ("127.0.0.1, 1.2.3.4", None),
    ],
)
def test_ip_is_normalized_or_omitted_without_echoing_input(ip, expected):
    record = valid_record()
    record["ip_address"] = ip
    assert activity_metadata(record)["ip_address"] == expected


@settings(max_examples=150, derandomize=True)
@given(st.text(max_size=2000))
def test_secret_bearing_fields_are_discarded_for_arbitrary_content(content):
    secret = "private-marker:" + content
    record = {
        **valid_record(),
        **dict.fromkeys(
            ["headers", "body", "response_body", "query_params", "user_agent", "password", "unexpected"], secret
        ),
    }
    original = copy.deepcopy(record)
    clean = activity_metadata(record)
    assert clean is not None
    assert secret not in json.dumps(clean, ensure_ascii=False)
    assert record == original


@settings(max_examples=150, derandomize=True)
@given(st.text(max_size=500))
def test_method_never_retains_unrecognized_text(method):
    result = safe_method(method)
    assert result in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "OTHER"}


@settings(max_examples=150, derandomize=True)
@given(st.one_of(st.none(), st.text(max_size=200), st.integers(), st.booleans()))
def test_untrusted_ip_never_raises_or_escapes_as_arbitrary_text(address):
    import ipaddress

    record = valid_record()
    record["ip_address"] = address
    value = activity_metadata(record)["ip_address"]
    if value is not None:
        assert str(ipaddress.ip_address(value)) == value
