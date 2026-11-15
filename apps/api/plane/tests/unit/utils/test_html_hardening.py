# Copyright (c) 2026 Plane hardened fork contributors
# SPDX-License-Identifier: AGPL-3.0-only

import logging
from unittest.mock import patch

from bs4 import BeautifulSoup
from hypothesis import given, settings, strategies as st
import pytest

from plane.api.serializers.issue import IssueSerializer
from plane.utils.content_validator import MAX_SIZE, validate_html_content


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "html", ["<p>Hello <strong>world</strong></p>", "<p>first</p><p>second</p>", "<p>unclosed", "plain text"]
)
def test_issue_html_is_normalized_once_by_shared_sanitizer(html):
    with patch("plane.api.serializers.issue.validate_html_content", wraps=validate_html_content) as sanitize:
        result = IssueSerializer(context={}).validate({"description_html": html})
    sanitize.assert_called_once_with(html)
    assert (
        BeautifulSoup(result["description_html"], "html.parser").get_text()
        == BeautifulSoup(html, "html.parser").get_text()
    )


@pytest.mark.parametrize("value", [None, ""])
def test_empty_description_is_accepted_without_a_parser(value):
    assert IssueSerializer(context={}).validate({"description_html": value})["description_html"] == value


@pytest.mark.parametrize(
    "payload",
    [
        '<script>alert("fixture")</script><p>visible</p>',
        '<p onclick="alert(1)">visible</p>',
        '<a href="javascript:alert(1)">visible</a>',
        '<a href="jav&#x61;script:alert(1)">visible</a>',
        "<svg><script>alert(1)</script></svg><p>visible</p>",
        '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=alert(1)>">',
    ],
)
def test_active_html_and_unsafe_protocols_do_not_survive_shared_issue_path(payload):
    result = IssueSerializer(context={}).validate({"description_html": payload})["description_html"]
    soup = BeautifulSoup(result, "html.parser")
    assert not soup.find_all(["script", "svg", "math", "iframe", "style"])
    for element in soup.find_all(True):
        assert not any(name.lower().startswith("on") for name in element.attrs)
        for name in ["href", "src"]:
            assert not str(element.get(name, "")).lower().startswith("javascript:")


def test_editor_formatting_is_preserved_while_css_network_and_positioning_are_removed():
    html = (
        '<p style="color:red;text-align:center;background-image:url(https://fixture.invalid/);position:fixed">safe</p>'
    )
    good, _, result = validate_html_content(html)
    assert good
    style = BeautifulSoup(result, "html.parser").p.get("style", "")
    assert "color" in style and "text-align" in style
    assert "url(" not in style and "background-image" not in style and "position" not in style


@pytest.mark.parametrize("html", ["x" * (MAX_SIZE + 1), "\ud800", "\udfff", 42, b"<p>bytes</p>", {}])
def test_size_unicode_and_type_fail_before_sanitizer(html):
    with patch("plane.utils.content_validator.nh3.clean") as clean:
        good, _, result = validate_html_content(html)
    assert not good and result is None
    clean.assert_not_called()


def test_removed_tag_attribute_names_and_exceptions_cannot_leak_body_values(caplog):
    secret = "private-synthetic-html-marker"
    with caplog.at_level(logging.WARNING):
        validate_html_content(f'<{secret}><p {secret}="value">content</p></{secret}>')
        with patch("plane.utils.content_validator.nh3.clean", side_effect=RuntimeError(secret)):
            assert not validate_html_content("<p>fixture</p>")[0]
    assert secret not in caplog.text
    assert "HTML sanitization failed" in caplog.text


@settings(max_examples=150, derandomize=True)
@given(st.text(max_size=1000))
def test_arbitrary_unicode_cannot_escape_as_an_uncaught_error(value):
    good, _, result = validate_html_content(value)
    assert isinstance(good, bool)
    if good and result is not None:
        assert isinstance(result, str)
