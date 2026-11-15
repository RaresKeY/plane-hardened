# Copyright (c) 2026 Plane hardened fork contributors
# SPDX-License-Identifier: AGPL-3.0-only

"""Exercise secret minimization across both middleware paths and the worker sink."""

import hashlib
import hmac
import json
import logging
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponse, StreamingHttpResponse
from django.test import RequestFactory, override_settings

from plane.bgtasks.logger_task import process_logs
from plane.middleware.logger import APITokenLogMiddleware, RequestLoggerMiddleware
from plane.utils.request_logging import AUDIT_SCHEMA


SECRET = "plane_api_private-fixture-never-a-real-credential"
ROUTE = "api/v1/workspaces/<str:slug>/projects/<uuid:project_id>/issues/"
pytestmark = pytest.mark.unit


def request_with_secrets(method="POST"):
    request = RequestFactory().generic(
        method,
        "/api/v1/workspaces/private-name/?password=" + SECRET,
        data=json.dumps({"password": SECRET}),
        content_type="application/json; boundary=" + SECRET,
        HTTP_X_API_KEY=SECRET,
        HTTP_AUTHORIZATION="Bearer " + SECRET,
        HTTP_COOKIE="session=" + SECRET,
        HTTP_USER_AGENT=SECRET,
        HTTP_X_UNLISTED_SECRET=SECRET,
        HTTP_ACCEPT=SECRET,
    )
    request.user = AnonymousUser()
    request.resolver_match = SimpleNamespace(route=ROUTE)
    return request


def capture_payload(request, response=None):
    response = response if response is not None else HttpResponse(SECRET)
    middleware = APITokenLogMiddleware(lambda _: response)
    with patch("plane.middleware.logger.process_logs.apply_async") as queued:
        assert middleware(request) is response
        queued.assert_called_once()
        arguments = queued.call_args.kwargs
    assert SECRET not in json.dumps(arguments)
    return arguments["kwargs"]["log_data"], arguments


@pytest.mark.parametrize("method", ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_activity_excludes_secrets_for_normal_methods(method):
    payload, queued = capture_payload(request_with_secrets(method))
    assert payload["method"] == method
    assert payload["path"] == "/" + ROUTE
    assert payload["query_params"] == ""
    assert queued["kwargs"]["audit_schema"] == AUDIT_SCHEMA
    assert queued["argsrepr"] == "()"
    for key in ["headers", "body", "response_body", "user_agent"]:
        assert payload[key] is None


def test_unmatched_sensitive_url_is_not_logged():
    request = request_with_secrets()
    request.path = "/" + SECRET
    request.resolver_match = None
    payload, _ = capture_payload(request)
    assert payload["path"] == "/[unresolved]"


def test_streaming_response_is_not_read_or_consumed():
    consumed = []

    def content():
        consumed.append(True)
        yield SECRET.encode()

    response = StreamingHttpResponse(content())
    payload, _ = capture_payload(request_with_secrets(), response)
    assert payload["response_body"] is None
    assert consumed == []
    assert b"".join(response.streaming_content) == SECRET.encode()


def test_request_body_is_not_read_for_logging():
    original = request_with_secrets()

    class RequestWithoutReadableBody(SimpleNamespace):
        @property
        def body(self):
            raise AssertionError("Request body must remain unread")

    request = RequestWithoutReadableBody(
        headers=original.headers,
        META=original.META,
        resolver_match=original.resolver_match,
        method=original.method,
    )
    capture_payload(request)


def test_keyed_identifier_stays_compatible_and_changes_with_signing_key():
    expected = hmac.new(settings.SECRET_KEY.encode(), SECRET.encode(), hashlib.sha256).hexdigest()
    payload, _ = capture_payload(request_with_secrets())
    assert payload["token_identifier"] == expected
    with override_settings(SECRET_KEY="different-test-only-signing-key"):
        changed, _ = capture_payload(request_with_secrets())
    assert changed["token_identifier"] != expected


def test_broker_error_does_not_leak_exception_values_or_change_response(caplog):
    response = HttpResponse(b"ordinary response", status=202)
    with patch("plane.middleware.logger.process_logs.apply_async", side_effect=RuntimeError(SECRET)):
        with caplog.at_level(logging.WARNING):
            actual = APITokenLogMiddleware(lambda _: response)(request_with_secrets())
    assert actual is response
    assert actual.content == b"ordinary response"
    assert SECRET not in caplog.text
    assert "Could not queue API activity metadata" in caplog.text


def test_general_logger_excludes_query_path_arguments_and_user_agent(caplog):
    request = request_with_secrets()
    with caplog.at_level(logging.INFO, logger="plane.api.request"):
        response = RequestLoggerMiddleware(lambda _: HttpResponse(SECRET, status=201))(request)
    assert response.status_code == 201
    record = next(x for x in caplog.records if x.name == "plane.api.request")
    assert SECRET not in record.getMessage()
    assert SECRET not in json.dumps(record.__dict__, default=str)
    assert record.path == "/" + ROUTE
    assert record.user_agent is None


def test_both_middlewares_preserve_response_and_remove_secrets_together(caplog):
    response = HttpResponse(b"unchanged", status=418)
    chain = RequestLoggerMiddleware(APITokenLogMiddleware(lambda _: response))
    with patch("plane.middleware.logger.process_logs.apply_async") as queued:
        with caplog.at_level(logging.INFO, logger="plane.api.request"):
            assert chain(request_with_secrets()) is response
    assert SECRET not in json.dumps(queued.call_args.kwargs)
    for record in caplog.records:
        assert SECRET not in json.dumps(record.__dict__, default=str)


def test_health_check_keeps_existing_skip_behavior(caplog):
    request = RequestFactory().get("/")
    request.user = AnonymousUser()
    with caplog.at_level(logging.INFO, logger="plane.api.request"):
        RequestLoggerMiddleware(lambda _: HttpResponse(b"ok"))(request)
    assert not [x for x in caplog.records if x.name == "plane.api.request"]


def test_duration_uses_monotonic_clock():
    with patch("plane.middleware.logger.time.monotonic", side_effect=[100, 100.125]):
        with patch("plane.middleware.logger.api_logger.info") as logged:
            RequestLoggerMiddleware(lambda _: HttpResponse(b"ok"))(request_with_secrets())
    assert logged.call_args.kwargs["extra"]["duration_ms"] == 125


@pytest.mark.parametrize("schema", [None, 0, 2, True, "1"])
def test_legacy_schema_payload_never_reaches_database(schema, caplog):
    with patch("plane.bgtasks.logger_task.APIActivityLog.objects.create") as create:
        process_logs.run(log_data={"token_identifier": SECRET, "body": SECRET}, audit_schema=schema)
    create.assert_not_called()
    assert SECRET not in caplog.text


def test_worker_reminimizes_content_even_in_new_schema():
    payload, _ = capture_payload(request_with_secrets())
    dirty = {
        **payload,
        **dict.fromkeys(["body", "response_body", "headers", "query_params", "user_agent", "extra_field"], SECRET),
    }
    with patch("plane.bgtasks.logger_task.APIActivityLog.objects.create") as create:
        process_logs.run(log_data=dirty, audit_schema=AUDIT_SCHEMA)
    create.assert_called_once()
    assert SECRET not in json.dumps(create.call_args.kwargs)
    assert "extra_field" not in create.call_args.kwargs


def test_database_failure_is_logged_without_values(caplog):
    payload, _ = capture_payload(request_with_secrets())
    with patch("plane.bgtasks.logger_task.APIActivityLog.objects.create", side_effect=RuntimeError(SECRET)):
        process_logs.run(log_data=payload, audit_schema=AUDIT_SCHEMA)
    assert SECRET not in caplog.text
    assert "Could not persist API activity metadata" in caplog.text


@pytest.mark.django_db
def test_sanitized_record_is_persisted_with_expected_metadata():
    from plane.db.models import APIActivityLog

    payload, _ = capture_payload(request_with_secrets())
    process_logs.run(log_data=payload, audit_schema=AUDIT_SCHEMA)
    row = APIActivityLog.objects.get(token_identifier=payload["token_identifier"])
    assert row.path == "/" + ROUTE
    assert row.method == "POST"
    assert row.response_code == 200
    assert row.query_params == ""
    assert all(getattr(row, field) is None for field in ["body", "response_body", "headers", "user_agent"])


def test_logging_task_is_explicitly_imported_by_celery():
    from plane.celery import app

    assert "plane.bgtasks.logger_task" in app.conf.imports


@pytest.mark.parametrize("forwarded", [SECRET, "not-an-ip", "127.0.0.1\r\n" + SECRET, "a" * 10000])
def test_untrusted_forwarded_header_cannot_leak_into_queue_or_general_log(forwarded, caplog):
    request = request_with_secrets()
    request.META["HTTP_X_FORWARDED_FOR"] = forwarded
    with caplog.at_level(logging.INFO, logger="plane.api.request"):
        RequestLoggerMiddleware(lambda _: HttpResponse(b"ok"))(request)
    payload, _ = capture_payload(request)
    assert payload["ip_address"] is None
    record = next(x for x in caplog.records if x.name == "plane.api.request")
    assert record.remote_addr is None
    assert SECRET not in json.dumps(record.__dict__, default=str)
