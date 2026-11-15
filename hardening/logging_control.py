#!/usr/bin/env python3
"""Compare credential presence in reviewed upstream and patched log producers.

Only booleans are emitted; the marker is synthetic and never an API credential.
"""

import importlib.util
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import django
from django.http import HttpResponse
from django.test import RequestFactory


def probe(module):
    from django.contrib.auth.models import AnonymousUser

    marker = "synthetic-private-audit-marker"
    request = RequestFactory().post(
        "/private/" + marker + "/?secret=" + marker,
        {"password": marker},
        content_type="application/json",
        HTTP_X_API_KEY=marker,
        HTTP_USER_AGENT=marker,
    )
    request.user = AnonymousUser()
    request.resolver_match = SimpleNamespace(route="api/<str:slug>/")
    response = HttpResponse(marker)
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.__dict__)

    handler = Capture()
    logger = logging.getLogger("plane.api.request")
    before = logger.level
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        with patch.object(module.process_logs, "apply_async") as queued:
            module.RequestLoggerMiddleware(module.APITokenLogMiddleware(lambda _: response))(request)
        assert queued.called
        queued_content = json.dumps([queued.call_args.args, queued.call_args.kwargs], default=str)
        return {
            "general_log_contains_secret": marker in json.dumps(records, default=str),
            "queued_payload_contains_secret": marker in queued_content,
        }
    finally:
        logger.removeHandler(handler)
        logger.setLevel(before)


def main():
    django.setup()
    path = Path(__file__).parent / "fixtures/upstream_logger.py"
    spec = importlib.util.spec_from_file_location("reviewed_upstream_logger", path)
    original = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original)
    from plane.middleware import logger as hardened

    baseline = probe(original)
    patched = probe(hardened)
    assert all(baseline.values()), baseline
    assert not any(patched.values()), patched
    print(json.dumps({"upstream_positive_control": baseline, "hardened": patched, "passed": True}))


if __name__ == "__main__":
    main()
