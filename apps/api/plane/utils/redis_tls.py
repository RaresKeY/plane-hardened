# Copyright (c) 2026 Plane hardened fork contributors
# SPDX-License-Identifier: AGPL-3.0-only

"""Shared fail-closed TLS settings for both Redis client paths."""

from urllib.parse import parse_qs, urlsplit


def redis_tls_options(url):
    parsed = urlsplit(url or "")
    if parsed.scheme != "rediss":
        return {}
    # redis-py gives query arguments precedence over keyword defaults. Reject
    # verification overrides so a URL cannot silently disable either check.
    query = parse_qs(parsed.query, keep_blank_values=True)
    if {"ssl_cert_reqs", "ssl_check_hostname"}.intersection(query):
        raise ValueError("Redis TLS verification options must not be overridden in the URL")
    return {"ssl_cert_reqs": "required", "ssl_check_hostname": True}
