import copy

import pytest
from policy_fixtures import BASELINE_POLICY, minimal_policy_dict

from rig_sentinel.policy import (
    Effect,
    PolicyValidationError,
    lint_policy,
    load_policy_text,
    validate_policy,
)
from rig_sentinel.policy.schema import IssueCode, LintCode


def _rule(policy):
    return policy["rules"][0]


def _tool(policy):
    return policy["tools"][0]


def test_minimal_policy_is_valid():
    policy = validate_policy(minimal_policy_dict())
    assert policy.policy_id == "minimal"
    assert len(policy.sha256) == 64
    assert policy.rules[0].effect is Effect.ALLOW


def test_baseline_policy_is_valid():
    policy = load_policy_text(BASELINE_POLICY)
    assert [rule.rule_id for rule in policy.rules] == sorted(rule.rule_id for rule in policy.rules)


def test_defaults_section_is_optional_and_denies():
    data = minimal_policy_dict()
    del data["defaults"]
    assert validate_policy(data).defaults.decision is Effect.DENY


INVALID_CASES = [
    # --- unknown / missing fields --------------------------------------
    ("unknown root field", lambda p: p.update(enforcement="off"), IssueCode.UNKNOWN_FIELD),
    ("unknown rule field (priority)", lambda p: _rule(p).update(priority=10), IssueCode.UNKNOWN_FIELD),
    ("unknown rule field (override)", lambda p: _rule(p).update(override=True), IssueCode.UNKNOWN_FIELD),
    ("unknown tool field", lambda p: _tool(p).update(trusted=True), IssueCode.UNKNOWN_FIELD),
    ("unknown defaults field", lambda p: p["defaults"].update(fail_open=True), IssueCode.UNKNOWN_FIELD),
    ("unknown conditions field", lambda p: _rule(p).update(conditions={"time": "always"}), IssueCode.UNKNOWN_FIELD),
    ("unknown approver field", lambda p: p["approvers"][0].update(role="root"), IssueCode.UNKNOWN_FIELD),
    ("missing policy_id", lambda p: p.pop("policy_id"), IssueCode.MISSING_FIELD),
    ("missing schema_version", lambda p: p.pop("schema_version"), IssueCode.MISSING_FIELD),
    ("missing rule effect", lambda p: _rule(p).pop("effect"), IssueCode.MISSING_FIELD),
    ("missing rule resources", lambda p: _rule(p).pop("resources"), IssueCode.MISSING_FIELD),
    ("missing tool operations", lambda p: _tool(p).pop("operations"), IssueCode.MISSING_FIELD),
    # --- unsupported values --------------------------------------------
    ("schema version", lambda p: p.update(schema_version="rig.policy/v2"), IssueCode.UNSUPPORTED_SCHEMA_VERSION),
    ("effect capitalized", lambda p: _rule(p).update(effect="Allow"), IssueCode.UNSUPPORTED_VALUE),
    ("effect unknown", lambda p: _rule(p).update(effect="permit"), IssueCode.UNSUPPORTED_VALUE),
    ("default allow", lambda p: p["defaults"].update(decision="allow"), IssueCode.DEFAULT_ALLOW_FORBIDDEN),
    ("default unknown", lambda p: p["defaults"].update(decision="ignore"), IssueCode.UNSUPPORTED_VALUE),
    ("ttl zero", lambda p: p["defaults"].update(approval_ttl_seconds=0), IssueCode.INVALID_VALUE),
    ("ttl huge", lambda p: p["defaults"].update(approval_ttl_seconds=99999), IssueCode.INVALID_VALUE),
    ("ttl bool", lambda p: p["defaults"].update(approval_ttl_seconds=True), IssueCode.INVALID_TYPE),
    ("ttl string", lambda p: p["defaults"].update(approval_ttl_seconds="300"), IssueCode.INVALID_TYPE),
    ("unknown operation in rule", lambda p: _rule(p).update(operations=["launch"]), IssueCode.INVALID_PATTERN),
    ("unknown operation in tool", lambda p: _tool(p).update(operations=["launch"]), IssueCode.UNSUPPORTED_VALUE),
    ("wildcard operation in tool", lambda p: _tool(p).update(operations=["*"]), IssueCode.UNSUPPORTED_VALUE),
    ("unknown resource kind", lambda p: _tool(p).update(resource_kind="file"), IssueCode.UNSUPPORTED_VALUE),
    ("protected as string", lambda p: _tool(p).update(protected="yes"), IssueCode.INVALID_TYPE),
    ("bad manifest digest", lambda p: _tool(p).update(manifest_sha256="ABC"), IssueCode.INVALID_VALUE),
    ("unknown environment", lambda p: _rule(p).update(conditions={"environment": ["production"]}), IssueCode.UNSUPPORTED_VALUE),
    ("unknown assurance", lambda p: _rule(p).update(conditions={"min_assurance": "root"}), IssueCode.UNSUPPORTED_VALUE),
    ("conflicting labels", lambda p: _rule(p).update(conditions={"labels_all": ["x"], "labels_none": ["x"]}), IssueCode.CONFLICTING_CONDITIONS),
    # --- types -----------------------------------------------------------
    ("agents as string", lambda p: _rule(p).update(agents="notes-bot"), IssueCode.INVALID_TYPE),
    ("empty agents", lambda p: _rule(p).update(agents=[]), IssueCode.INVALID_VALUE),
    ("non-string pattern", lambda p: _rule(p).update(agents=[1]), IssueCode.INVALID_TYPE),
    ("rules not a list", lambda p: p.update(rules={"id": "x"}), IssueCode.INVALID_TYPE),
    ("rule not a table", lambda p: p.update(rules=["read-notes"]), IssueCode.INVALID_TYPE),
    ("description control char", lambda p: p.update(description="line1\nline2"), IssueCode.INVALID_VALUE),
    ("policy id uppercase", lambda p: p.update(policy_id="Minimal"), IssueCode.INVALID_VALUE),
    ("policy version spaces", lambda p: p.update(policy_version="v 1"), IssueCode.INVALID_VALUE),
    # --- duplicates and conflicts ---------------------------------------
    ("duplicate rule id", lambda p: p["rules"].append(copy.deepcopy(_rule(p))), IssueCode.DUPLICATE_ID),
    ("duplicate tool id", lambda p: p["tools"].append(copy.deepcopy(_tool(p))), IssueCode.DUPLICATE_ID),
    ("duplicate approver id", lambda p: p["approvers"].append({"id": "lead", "scopes": ["*"]}), IssueCode.DUPLICATE_ID),
    ("duplicate pattern", lambda p: _rule(p).update(agents=["notes-bot", "notes-bot"]), IssueCode.DUPLICATE_VALUE),
    ("duplicate after normalization", lambda p: _rule(p).update(resources=["fs:/srv/notes/**", "fs:/srv//notes/**"]), IssueCode.DUPLICATE_VALUE),
    ("wildcard mixed with names", lambda p: _rule(p).update(agents=["*", "notes-bot"]), IssueCode.INVALID_PATTERN),
    ("approver scope unknown rule", lambda p: p["approvers"][0].update(scopes=["no-such-rule"]), IssueCode.UNKNOWN_RULE_REFERENCE),
    # --- tool references -------------------------------------------------
    ("bare tool name", lambda p: _rule(p).update(tools=["read"]), IssueCode.INVALID_PATTERN),
    ("unregistered tool", lambda p: _rule(p).update(tools=["mcp://notes/delete"]), IssueCode.UNREGISTERED_TOOL_REFERENCE),
    ("unregistered server wildcard", lambda p: _rule(p).update(tools=["mcp://other/*"]), IssueCode.UNREGISTERED_TOOL_REFERENCE),
    ("tool id not qualified", lambda p: _tool(p).update(id="read_notes"), IssueCode.INVALID_VALUE),
    # --- resource patterns ----------------------------------------------
    ("traversal pattern", lambda p: _rule(p).update(resources=["fs:/srv/../etc/**"]), IssueCode.INVALID_PATTERN),
    ("mid-pattern glob", lambda p: _rule(p).update(resources=["fs:/srv/**/notes"]), IssueCode.INVALID_PATTERN),
    ("regex pattern", lambda p: _rule(p).update(resources=["fs:/srv/.*"]), IssueCode.INVALID_PATTERN),
    # --- approvals -------------------------------------------------------
    ("approval rule without approver", lambda p: (p.update(approvers=[]), _rule(p).update(effect="require_approval")), IssueCode.MISSING_APPROVER),
    ("default approval without * approver", lambda p: (p.update(approvers=[{"id": "lead", "scopes": ["read-notes"]}]), p["defaults"].update(decision="require_approval")), IssueCode.MISSING_APPROVER),
    # --- limits ----------------------------------------------------------
    ("too many patterns", lambda p: _rule(p).update(agents=[f"a{i}" for i in range(65)]), IssueCode.LIMIT_EXCEEDED),
    ("too many rules", lambda p: p.update(rules=[dict(_rule(p), id=f"r{i}") for i in range(1001)]), IssueCode.LIMIT_EXCEEDED),
    ("description too long", lambda p: p.update(description="x" * 1025), IssueCode.LIMIT_EXCEEDED),
]


@pytest.mark.parametrize(("label", "mutate", "code"), INVALID_CASES, ids=[c[0] for c in INVALID_CASES])
def test_invalid_policies_are_rejected(label, mutate, code):
    data = minimal_policy_dict()
    mutate(data)
    with pytest.raises(PolicyValidationError) as info:
        validate_policy(data)
    assert code in info.value.codes, info.value.issues


@pytest.mark.parametrize("root", [None, [], "policy", 1, ()])
def test_non_table_root_is_rejected(root):
    with pytest.raises(PolicyValidationError) as info:
        validate_policy(root)
    assert info.value.codes == (IssueCode.INVALID_TYPE,)


def test_all_issues_are_reported_at_once():
    data = minimal_policy_dict()
    data["unknown"] = 1
    _rule(data)["effect"] = "Allow"
    data["defaults"]["decision"] = "allow"
    with pytest.raises(PolicyValidationError) as info:
        validate_policy(data)
    assert {
        IssueCode.UNKNOWN_FIELD,
        IssueCode.UNSUPPORTED_VALUE,
        IssueCode.DEFAULT_ALLOW_FORBIDDEN,
    } <= set(info.value.codes)


def test_validation_errors_do_not_echo_values():
    secret_like = "sk-live-THIS-SHOULD-NOT-APPEAR-0123456789"
    data = minimal_policy_dict()
    data["description"] = secret_like + "\n"
    _rule(data)["agents"] = [secret_like]
    data[secret_like] = "x"
    with pytest.raises(PolicyValidationError) as info:
        validate_policy(data)
    assert secret_like not in str(info.value)
    assert all(secret_like not in str(issue) for issue in info.value.issues)


def test_input_mutation_after_validation_has_no_effect():
    data = minimal_policy_dict()
    policy = validate_policy(data)
    _rule(data)["effect"] = "deny"
    _rule(data)["agents"].append("intruder")
    data["defaults"]["decision"] = "allow"
    assert policy.rules[0].effect is Effect.ALLOW
    assert policy.rules[0].agents == ("notes-bot",)
    assert policy.defaults.decision is Effect.DENY


def test_round_trip_is_canonical():
    policy = load_policy_text(BASELINE_POLICY)
    again = validate_policy(policy.to_dict())
    assert again == policy


# --- lint (warnings, policy still loads) -------------------------------------


def _lint_codes(data):
    return {issue.code for issue in lint_policy(validate_policy(data))}


def test_lint_clean_policy():
    assert _lint_codes(minimal_policy_dict()) == set()


def test_lint_broad_allow():
    data = minimal_policy_dict()
    _rule(data).update(agents=["*"], tools=["*"])
    assert LintCode.BROAD_ALLOW in _lint_codes(data)


def test_lint_high_risk_allow():
    data = minimal_policy_dict()
    _tool(data)["operations"] = ["read", "execute"]
    _rule(data)["operations"] = ["execute"]
    assert LintCode.HIGH_RISK_ALLOW in _lint_codes(data)


def test_lint_unused_and_unprotected_tools():
    data = minimal_policy_dict()
    data["tools"].append({"id": "mcp://notes/write", "operations": ["write"], "protected": False})
    codes = _lint_codes(data)
    assert LintCode.UNUSED_TOOL in codes
    assert LintCode.UNPROTECTED_WRITE_TOOL in codes
