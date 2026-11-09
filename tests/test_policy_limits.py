"""H-3: bounded, reproducible stress tests for policy size limits and
worst-case parsing/validation/evaluation cost.

``tomllib`` is synchronous and cannot be interrupted from Python, so there is
no timeout. These tests instead check that every input within the limits
finishes, and that inputs beyond the limits are rejected *before* expensive
work. Time ceilings are deliberately generous (roughly 10x or more the
measured local cost) so they only catch algorithmic blow-ups, not slow CI
machines.
"""

from __future__ import annotations

import time

import pytest
from policy_fixtures import fixed_clock

from rig_sentinel.policy import (
    Decision,
    PolicyEngine,
    PolicyLoadError,
    PolicyValidationError,
    ReasonCode,
    load_policy_text,
)
from rig_sentinel.policy.schema import (
    MAX_POLICY_BYTES,
    MAX_RULES,
    IssueCode,
)

LOAD_CEILING_SECONDS = 30.0
EVAL_CEILING_SECONDS = 2.0  # for a single worst-case evaluation

HEADER = """\
schema_version = "rig.policy/v1"
policy_id = "limits"
policy_version = "1"

[[tools]]
id = "mcp://fs/read_file"
operations = ["read"]
resource_kind = "fs"
"""


def _rule(rule_id: str, effect: str, agents: list[str], resources: list[str]) -> str:
    def toml_list(values: list[str]) -> str:
        return "[" + ",".join(f'"{value}"' for value in values) + "]"

    return (
        f'[[rules]]\nid="{rule_id}"\neffect="{effect}"\nagents={toml_list(agents)}\n'
        f'tools=["mcp://fs/read_file"]\noperations=["read"]\nresources={toml_list(resources)}\n'
    )


def _timed(function, *args, **kwargs):
    start = time.perf_counter()
    result = function(*args, **kwargs)
    return result, time.perf_counter() - start


def _request(resource: str, agent: str = "bot") -> dict:
    return {
        "agent": {"id": agent},
        "tool": {"id": "mcp://fs/read_file"},
        "operation": "read",
        "resource": resource,
        "context": {"environment": "dev"},
    }


def test_maximum_rule_count_loads_and_evaluates():
    text = HEADER + "".join(
        _rule(f"r{i:04d}", "allow", ["bot"], [f"fs:/data/r{i:04d}/**"]) for i in range(MAX_RULES)
    )
    assert len(text.encode()) <= MAX_POLICY_BYTES
    policy, seconds = _timed(load_policy_text, text)
    assert len(policy.rules) == MAX_RULES
    assert seconds < LOAD_CEILING_SECONDS

    engine = PolicyEngine(policy, clock=fixed_clock)
    record, seconds = _timed(engine.evaluate, _request("fs:/data/r0999/x"))
    assert record.decision is Decision.ALLOW
    assert seconds < EVAL_CEILING_SECONDS


def test_one_rule_too_many_is_rejected():
    text = HEADER + "".join(
        _rule(f"r{i:04d}", "allow", ["bot"], [f"fs:/d/{i}"]) for i in range(MAX_RULES + 1)
    )
    assert len(text.encode()) <= MAX_POLICY_BYTES
    with pytest.raises(PolicyValidationError) as info:
        load_policy_text(text)
    assert IssueCode.LIMIT_EXCEEDED in info.value.codes


def test_worst_case_evaluation_scans_every_rule():
    # Every rule matches agent, tool and operation; none matches the resource,
    # so evaluation must test every resource pattern of every rule.
    patterns = [f"fs:/p/{j:02d}/**" for j in range(64)]
    rules = []
    i = 0
    while True:
        candidate = _rule(f"r{i:04d}", "allow", ["*"], patterns)
        if len((HEADER + "".join(rules) + candidate).encode()) > MAX_POLICY_BYTES:
            break
        rules.append(candidate)
        i += 1
    policy = load_policy_text(HEADER + "".join(rules))
    engine = PolicyEngine(policy, clock=fixed_clock)
    record, seconds = _timed(engine.evaluate, _request("fs:/q/x"))
    assert len(rules) > 100
    assert record.reason_code is ReasonCode.DEFAULT_DENY
    assert seconds < EVAL_CEILING_SECONDS


def test_worst_case_carve_out_analysis():
    # 500 broad allows and 500 narrow denies for *disjoint* agents: every
    # deny has every allow as a structural candidate, and every pair must be
    # checked for scope overlap (none overlaps, so the policy is valid).
    allows = [_rule(f"a{i:03d}", "allow", [f"a{i}"], ["fs:/**"]) for i in range(MAX_RULES // 2)]
    denies = [_rule(f"d{i:03d}", "deny", [f"d{i}"], [f"fs:/s/x{i}/**"]) for i in range(MAX_RULES // 2)]
    text = HEADER + "".join(allows + denies)
    assert len(text.encode()) <= MAX_POLICY_BYTES
    policy, seconds = _timed(load_policy_text, text)
    assert len(policy.rules) == MAX_RULES
    assert seconds < LOAD_CEILING_SECONDS


def test_oversize_policy_is_rejected_before_parsing():
    text = HEADER + "#" * (MAX_POLICY_BYTES - len(HEADER) + 1)
    _, seconds = _timed(pytest.raises, PolicyLoadError, load_policy_text, text)
    assert seconds < 1.0


def test_many_unknown_keys_are_rejected_with_bounded_message():
    lines = []
    size = len(HEADER)
    i = 0
    while size < MAX_POLICY_BYTES - 64:
        line = f"k{i} = 1\n"
        lines.append(line)
        size += len(line)
        i += 1
    text = HEADER.replace("[[tools]]", "".join(lines) + "\n[[tools]]", 1)
    with pytest.raises(PolicyValidationError) as info:
        load_policy_text(text)
    assert info.value.codes.count(IssueCode.UNKNOWN_FIELD) == i
    assert len(str(info.value)) < 5000  # summary lists at most 10 issues


@pytest.mark.parametrize(
    "value",
    [
        "x = " + "[" * 20_000 + "]" * 20_000,
        "x = " + "{a = " * 10_000 + "1" + "}" * 10_000,
    ],
    ids=["nested_arrays", "nested_inline_tables"],
)
def test_deep_nesting_is_rejected(value):
    with pytest.raises(PolicyLoadError):
        load_policy_text(value)


def test_huge_string_value_is_rejected():
    text = HEADER.replace(
        'policy_version = "1"', f'policy_version = "1"\ndescription = "{"x" * 200_000}"'
    )
    with pytest.raises(PolicyValidationError) as info:
        load_policy_text(text)
    assert IssueCode.LIMIT_EXCEEDED in info.value.codes


def test_request_size_limits():
    engine = PolicyEngine(load_policy_text(HEADER + _rule("r", "allow", ["bot"], ["fs:/**"])), clock=fixed_clock)
    long_ok = "fs:/" + "/".join(["a" * 200] * 10)
    assert engine.evaluate(_request(long_ok)).decision is Decision.ALLOW
    too_long = "fs:/" + "/".join(["a" * 200] * 11)
    assert engine.evaluate(_request(too_long)).reason_code is ReasonCode.INVALID_RESOURCE
    request = _request("fs:/a")
    request["context"]["labels"] = [f"l{i}" for i in range(10_000)]
    record, seconds = _timed(engine.evaluate, request)
    assert record.reason_code is ReasonCode.INVALID_REQUEST
    assert seconds < 1.0
