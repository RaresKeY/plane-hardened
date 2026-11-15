# Copyright (c) 2026 Plane hardened fork contributors
# SPDX-License-Identifier: AGPL-3.0-only

"""Bounded metadata shared by request logs and the asynchronous audit sink."""

import ipaddress
import re


AUDIT_SCHEMA = 1
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"})
UNRESOLVED_ROUTE = "/[unresolved]"


def safe_route(request):
    # Resolver patterns come from URL configuration, unlike credential-bearing URLs.
    match = getattr(request, "resolver_match", None)
    route = getattr(match, "route", None)
    if not isinstance(route, str) or len(route) > 254 or "\n" in route or "\r" in route:
        return UNRESOLVED_ROUTE
    return "/" + route.lstrip("/")


def safe_method(method):
    return method if isinstance(method, str) and method in METHODS else "OTHER"


def safe_ip(address):
    """Forwarded headers are untrusted text, not arbitrary log fields."""
    try:
        if not isinstance(address, str) or len(address) > 45:
            return None
        return str(ipaddress.ip_address(address.strip()))
    except ValueError:
        return None


def activity_metadata(data):
    """Discard unknown/secret fields and reject malformed new-format records."""
    if not isinstance(data, dict):
        return None
    token = data.get("token_identifier")
    route = data.get("path")
    status = data.get("response_code")
    if not isinstance(token, str) or re.fullmatch(r"[0-9a-f]{64}", token) is None:
        return None
    if not isinstance(route, str) or not route.startswith("/") or len(route) > 255 or "\n" in route or "\r" in route:
        return None
    if type(status) is not int or not 100 <= status <= 599:
        return None
    address = safe_ip(data.get("ip_address"))
    return {
        "token_identifier": token,
        "path": route,
        "method": safe_method(data.get("method")),
        "response_code": status,
        "ip_address": address,
        "query_params": "",
        "headers": None,
        "body": None,
        "response_body": None,
        "user_agent": None,
    }
