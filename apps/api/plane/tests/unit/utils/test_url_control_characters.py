"""Guard parser/DNS truncation boundaries (including CVE-2026-116566 conditions)."""

from unittest.mock import patch

import pytest

from plane.utils.url_security import _split_target, pinned_fetch


@pytest.mark.parametrize(
    "url",
    [
        "http://example.invalid\x00.attacker.invalid/",
        "http://example.invalid/\r\nsecret",
        "http://exa\tmple.invalid/",
        "http://example.invalid/\x7f",
        "http://example.invalid/%00?secret=literal\x00",
        "http://example.invalid%00.attacker.invalid/",
        "http://example.invalid%0a.attacker.invalid/",
        "http://example.invalid%20.attacker.invalid/",
    ],
)
def test_control_characters_are_rejected_before_dns_or_transport(url):
    with patch("plane.utils.url_security.resolve_and_validate") as resolve:
        with pytest.raises(ValueError) as caught:
            pinned_fetch("GET", url)
        resolve.assert_not_called()
    assert "secret" not in str(caught.value)
    assert "attacker" not in str(caught.value)


def test_encoded_query_and_path_data_are_not_misclassified_as_host_controls():
    scheme, host, port, path, auth = _split_target("https://example.invalid/my file?q=%00%0A")
    assert (scheme, host, port, path, auth) == ("https", "example.invalid", 443, "/my file?q=%00%0A", None)
