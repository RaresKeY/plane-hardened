# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import hashlib
import hmac
import logging
import time

# Django imports
from django.conf import settings
from django.http import HttpRequest

# Third party imports
from rest_framework.request import Request

# Module imports
from plane.utils.ip_address import get_client_ip
from plane.utils.request_logging import AUDIT_SCHEMA, safe_ip, safe_method, safe_route
from plane.bgtasks.logger_task import process_logs

api_logger = logging.getLogger("plane.api.request")


class RequestLoggerMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def _should_log_route(self, request: Request | HttpRequest) -> bool:
        """
        Determines whether a route should be logged based on the request and status code.
        """
        # Don't log health checks
        if request.path == "/" and request.method == "GET":
            return False
        return True

    def __call__(self, request):
        # get the start time
        start_time = time.monotonic()

        # Get the response
        response = self.get_response(request)

        # calculate the duration
        duration = time.monotonic() - start_time

        # Check if logging is required
        log_true = self._should_log_route(request=request)

        # If logging is not required, return the response
        if not log_true:
            return response

        user_id = (
            request.user.id if getattr(request, "user") and getattr(request.user, "is_authenticated", False) else None
        )

        route = safe_route(request)
        method = safe_method(request.method)

        # Log the request information
        api_logger.info(
            "%s %s %s",
            method,
            route,
            response.status_code,
            extra={
                "path": route,
                "method": method,
                "status_code": response.status_code,
                "duration_ms": int(duration * 1000),
                "remote_addr": safe_ip(get_client_ip(request)),
                "user_agent": None,
                "user_id": user_id,
            },
        )

        # return the response
        return response


class APITokenLogMiddleware:
    """
    Middleware to log External API requests to PostgreSQL.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        self.process_request(request, response)
        return response

    def process_request(self, request, response, request_body=None):
        api_key = request.headers.get("X-Api-Key")
        if not isinstance(api_key, str) or not api_key:
            return None
        try:
            log_data = {
                "token_identifier": hmac.new(
                    settings.SECRET_KEY.encode(), api_key.encode("utf-8", errors="surrogatepass"), hashlib.sha256
                ).hexdigest(),
                "path": safe_route(request),
                "method": safe_method(request.method),
                "query_params": "",
                "headers": None,
                "body": None,
                "response_body": None,
                "response_code": response.status_code,
                "ip_address": safe_ip(get_client_ip(request=request)),
                "user_agent": None,
            }
            process_logs.apply_async(
                kwargs={"log_data": log_data, "audit_schema": AUDIT_SCHEMA},
                argsrepr="()",
                kwargsrepr="[API activity metadata]",
            )
        except Exception:
            # Broker/encoding exceptions may embed credential-bearing input.
            api_logger.warning("Could not queue API activity metadata")
        return None
