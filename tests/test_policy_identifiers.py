import pytest

from rig_sentinel.policy.identifiers import (
    is_identifier,
    is_sha256_hex,
    is_tool_id,
    server_wildcard_prefix,
    split_tool_id,
)


@pytest.mark.parametrize(
    "value",
    ["support-bot", "a", "0", "agent.v2", "x_y-z.1", "a" * 128],
)
def test_valid_identifiers(value):
    assert is_identifier(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "Support-Bot",  # uppercase
        "-bot",  # must start with letter or digit
        ".bot",
        "bot ",  # trailing space
        "bot\n",  # trailing newline
        "supрort-bot",  # Cyrillic 'р' look-alike
        "support‑bot",  # non-breaking hyphen
        "a" * 129,  # too long
        "a/b",
        "*",
        None,
        42,
        b"support-bot",
    ],
)
def test_invalid_identifiers(value):
    assert not is_identifier(value)


@pytest.mark.parametrize(
    "value",
    ["mcp://helpdesk/tickets.get", "local://tools/format", "mcp://a/b"],
)
def test_valid_tool_ids(value):
    assert is_tool_id(value)


@pytest.mark.parametrize(
    "value",
    [
        "tickets.get",  # bare name
        "send_email",  # bare name (spoofing risk)
        "MCP://helpdesk/tickets.get",
        "mcp://HELPDESK/tickets.get",
        "mcp://helpdesk/../mail/send",
        "mcp://helpdesk/tickets/get",
        "mcp://helpdesk/",
        "mcp:///tickets.get",
        "http://helpdesk/tickets.get",
        "mcp://helpdesk/tickets.get ",
        "mcp://helpdesk/tickets.get\n",
        "mcp://gmаil/send",  # Cyrillic 'а'
        "mcp://helpdesk/*",
        "",
        None,
    ],
)
def test_invalid_tool_ids(value):
    assert not is_tool_id(value)


def test_split_tool_id():
    assert split_tool_id("mcp://mail/send") == ("mcp", "mail", "send")
    with pytest.raises(ValueError):
        split_tool_id("send")


def test_server_wildcard_prefix():
    assert server_wildcard_prefix("mcp://web/*") == "mcp://web/"
    assert server_wildcard_prefix("mcp://web/fetch") is None
    assert server_wildcard_prefix("mcp://*/*") is None
    assert server_wildcard_prefix(None) is None


def test_sha256_hex():
    assert is_sha256_hex("a" * 64)
    assert not is_sha256_hex("A" * 64)
    assert not is_sha256_hex("a" * 63)
    assert not is_sha256_hex("g" * 64)
    assert not is_sha256_hex(None)
