import pytest

from rig_sentinel.policy.matching import (
    PatternError,
    parse_agent_pattern,
    parse_operation_pattern,
    parse_resource_pattern,
    parse_tool_pattern,
)
from rig_sentinel.policy.resources import parse_resource


@pytest.mark.parametrize(
    ("pattern", "resource", "expected"),
    [
        ("fs:/srv/data/**", "fs:/srv/data", True),
        ("fs:/srv/data/**", "fs:/srv/data/x/y", True),
        ("fs:/srv/data/**", "fs:/srv/database", False),  # segment boundary
        ("fs:/srv/data/**", "fs:/srv/data2/x", False),
        ("fs:/srv/data/**", "fs:/srv", False),
        ("fs:/**", "fs:/anything/at/all", True),
        ("fs:/srv/data", "fs:/srv/data", True),
        ("fs:/srv/data", "fs:/srv/data/x", False),  # exact means exact
        ("db:crm/**", "db:crm/accounts", True),
        ("db:crm/**", "db:crm", True),
        ("db:crm/**", "db:crm2/accounts", False),
        ("url:https://docs.example.com/**", "url:https://docs.example.com/a/b", True),
        ("url:https://docs.example.com/**", "url:https://docs.example.com.evil.example/a", False),
        ("url:https://docs.example.com/**", "url:http://docs.example.com/a", False),
        ("url:https://docs.example.com/**", "url:https://docs.example.com:8443/a", False),
        ("secret:vault/app/**", "secret:vault/app/key", True),
        ("secret:vault/app/**", "secret:vault/application", False),
        ("*", "shell:git", True),
        ("shell:git", "shell:gitk", False),
        ("email:customer.example.com", "email:customer.example.com", True),
        ("email:customer.example.com", "email:evil.customer.example.com", False),
        ("fs:/srv/data/**", "db:srv/data", False),  # kind must match
    ],
)
def test_resource_pattern_matching(pattern, resource, expected):
    assert parse_resource_pattern(pattern).matches(parse_resource(resource)) is expected


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("fs:/srv/data/**", "fs:/srv/data/**"),
        ("fs:/srv//data/./**", "fs:/srv/data/**"),
        ("fs:/**", "fs:/**"),
        ("url:https://Docs.Example.com/**", "url:https://docs.example.com/**"),
        ("db:crm/**", "db:crm/**"),
        ("*", "*"),
    ],
)
def test_resource_pattern_canonical(raw, canonical):
    assert parse_resource_pattern(raw).canonical == canonical


@pytest.mark.parametrize(
    "raw",
    [
        "fs:/srv/*/data",
        "fs:/srv/da*",
        "fs:/srv/**/data",
        "fs:/srv/.*",
        "fs:/srv/../etc/**",
        "shell:git/**",
        "email:example.com/**",
        "none:/**",
        "db:crm/accounts/**",
        "**",
        "",
        None,
    ],
)
def test_invalid_resource_patterns(raw):
    with pytest.raises(PatternError):
        parse_resource_pattern(raw)


def test_tool_patterns():
    assert parse_tool_pattern("*").matches("mcp://any/tool")
    server = parse_tool_pattern("mcp://web/*")
    assert server.matches("mcp://web/fetch")
    assert not server.matches("mcp://webhooks/fetch")
    assert not server.matches("local://web/fetch")
    exact = parse_tool_pattern("mcp://web/fetch")
    assert exact.matches("mcp://web/fetch")
    assert not exact.matches("mcp://web/fetch2")
    for bad in ("fetch", "mcp://*/fetch", "mcp://web/fe*", "mcp://web/**", None):
        with pytest.raises(PatternError):
            parse_tool_pattern(bad)


def test_agent_and_operation_patterns():
    assert parse_agent_pattern("*") == "*"
    assert parse_agent_pattern("support-bot") == "support-bot"
    assert parse_operation_pattern("read") == "read"
    for bad in ("Support", "bot*", "", None):
        with pytest.raises(PatternError):
            parse_agent_pattern(bad)
    for bad in ("READ", "launch", "re*", None):
        with pytest.raises(PatternError):
            parse_operation_pattern(bad)
