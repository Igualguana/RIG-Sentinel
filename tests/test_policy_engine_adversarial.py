"""Adversarial, fail-closed and boundary tests for the policy engine."""

import random
from collections.abc import Mapping

import pytest
from policy_fixtures import BASELINE_POLICY, baseline_engine, fixed_clock, make_request

from rig_sentinel.policy import (
    AgentIdentity,
    AuthorizationContext,
    AuthorizationRequest,
    Decision,
    Effect,
    Environment,
    OperationClass,
    PolicyEngine,
    ReasonCode,
    ToolIdentity,
    load_policy_text,
    parse_resource,
)
from rig_sentinel.policy import engine as engine_module
from rig_sentinel.policy.decision import FALLBACK_DENY
from rig_sentinel.policy_generator import PolicyGenerator, SecurityPolicy


def advisory_policy_examples():
    """Advisory output of the v0.1.0 scanner's PolicyGenerator."""
    advisory = SecurityPolicy(
        agent="support-bot",
        identity="EXAMPLE_IDENTITY",
        severity="HIGH",
        enforcement="advisory",
        controls=("require_human_approval",),
        reasons=("synthetic",),
    )
    return [advisory, (advisory,), PolicyGenerator().to_dict((advisory,))]


@pytest.fixture(scope="module")
def engine():
    return baseline_engine()


def _deny(record, reason):
    assert record.decision is Decision.DENY
    assert record.reason_code is reason
    assert not record.allowed
    assert record.enforced is False


# --- Missing / forged identity ----------------------------------------------


@pytest.mark.parametrize(
    "agent",
    [None, "", "   "],
)
def test_missing_identity(engine, agent):
    _deny(engine.evaluate(make_request(agent=agent)), ReasonCode.MISSING_IDENTITY)


def test_missing_agent_key(engine):
    request = make_request()
    del request["agent"]
    _deny(engine.evaluate(request), ReasonCode.MISSING_IDENTITY)


@pytest.mark.parametrize(
    "agent",
    [
        "Support-Bot",
        "support‑bot",  # non-breaking hyphen look-alike
        "supрort-bot",  # Cyrillic look-alike
        "*",
        "support-bot\n",
        "a" * 129,
    ],
)
def test_forged_or_invalid_identity(engine, agent):
    _deny(engine.evaluate(make_request(agent=agent)), ReasonCode.INVALID_IDENTITY)


def test_typed_request_without_agent(engine):
    request = AuthorizationRequest(
        agent=None,
        tool=ToolIdentity("mcp://helpdesk/tickets.get"),
        operation=OperationClass.READ,
        resource=parse_resource("db:helpdesk/tickets"),
        context=AuthorizationContext(Environment.STAGING),
    )
    _deny(engine.evaluate(request), ReasonCode.MISSING_IDENTITY)


# --- Tool spoofing ----------------------------------------------------------------


@pytest.mark.parametrize(
    "tool",
    [
        "tickets.get",
        "mcp://helpdesk/../mail/send",
        "MCP://helpdesk/tickets.get",
        "mcp://helpdesk/tickets.get ",
        "mcp://helpdesk/Tickets.get",
        "mcp://helpdesk/*",
        "*",
    ],
)
def test_spoofed_tool_ids(engine, tool):
    _deny(engine.evaluate(make_request(tool=tool)), ReasonCode.INVALID_TOOL_ID)


@pytest.mark.parametrize(
    "tool",
    ["mcp://helpdesk2/tickets.get", "local://helpdesk/tickets.get", "mcp://gmai1/send"],
)
def test_lookalike_tools_are_unknown(engine, tool):
    _deny(engine.evaluate(make_request(tool=tool)), ReasonCode.UNKNOWN_TOOL)


# --- Unknown operation / invalid resource ------------------------------------------


@pytest.mark.parametrize("operation", ["READ", "launch", "", "*", None, 1, ["read"]])
def test_unknown_operation(engine, operation):
    _deny(engine.evaluate(make_request(operation=operation)), ReasonCode.UNKNOWN_OPERATION)


@pytest.mark.parametrize(
    "resource",
    [
        "db:helpdesk/tickets/../customers",
        "db:Helpdesk/tickets",
        "db:helpdesk/tickets\n",
        "fs:/srv/workspace/../../etc/passwd",
        "url:https://docs.example.com@evil.example/",
        "*",
        "",
        None,
        ["db:helpdesk/tickets"],
    ],
)
def test_invalid_resource(engine, resource):
    _deny(engine.evaluate(make_request(resource=resource)), ReasonCode.INVALID_RESOURCE)


def test_traversal_cannot_reach_protected_directory(engine):
    record = engine.evaluate(
        make_request(
            agent="build-agent",
            tool="mcp://fs/write_file",
            operation="write",
            resource="fs:/srv/workspace/tmp/../.rig-sentinel/policy.toml",
        )
    )
    _deny(record, ReasonCode.INVALID_RESOURCE)


# --- Malformed requests -------------------------------------------------------------


@pytest.mark.parametrize("request_value", [None, "allow", 42, ["agent"], b"{}", object()])
def test_non_mapping_requests(engine, request_value):
    _deny(engine.evaluate(request_value), ReasonCode.INVALID_REQUEST)


def test_unknown_request_field(engine):
    request = make_request()
    request["override"] = "allow"
    _deny(engine.evaluate(request), ReasonCode.INVALID_REQUEST)


def test_assurance_claim_cannot_bypass_unknown_value(engine):
    request = make_request()
    request["agent"]["assurance"] = "root"
    _deny(engine.evaluate(request), ReasonCode.INVALID_IDENTITY)


# --- Engine state: missing policy, pin mismatch, tampering --------------------------


@pytest.mark.parametrize(
    "policy",
    [None, {"schema_version": "rig.policy/v1"}, BASELINE_POLICY, "policy.toml", object()],
)
def test_no_valid_policy_object_means_deny_all(policy):
    engine = PolicyEngine(policy, clock=fixed_clock)
    assert not engine.available
    assert engine.policy_sha256 is None
    _deny(engine.evaluate(make_request()), ReasonCode.POLICY_UNAVAILABLE)


def test_advisory_scanner_policies_are_never_activated():
    for advisory in advisory_policy_examples():
        engine = PolicyEngine(advisory, clock=fixed_clock)
        _deny(engine.evaluate(make_request()), ReasonCode.POLICY_UNAVAILABLE)


def test_digest_pin_mismatch_denies_everything():
    policy = load_policy_text(BASELINE_POLICY)
    engine = PolicyEngine(policy, expected_policy_sha256="0" * 64, clock=fixed_clock)
    record = engine.evaluate(make_request())
    _deny(record, ReasonCode.POLICY_DIGEST_MISMATCH)
    assert record.policy_sha256 == policy.sha256  # reports what was actually loaded


@pytest.mark.parametrize("pin", ["", "A" * 64, "zz", 123])
def test_malformed_pin_denies_everything(pin):
    engine = PolicyEngine(load_policy_text(BASELINE_POLICY), expected_policy_sha256=pin, clock=fixed_clock)
    assert engine.evaluate(make_request()).decision is Decision.DENY


def test_matching_pin_works():
    policy = load_policy_text(BASELINE_POLICY)
    engine = PolicyEngine(policy, expected_policy_sha256=policy.sha256, clock=fixed_clock)
    assert engine.evaluate(make_request()).allowed


def test_tampered_policy_object_is_rejected():
    policy = load_policy_text(BASELINE_POLICY)
    object.__setattr__(policy.defaults, "decision", Effect.ALLOW)
    engine = PolicyEngine(policy, clock=fixed_clock)
    _deny(engine.evaluate(make_request(agent="nobody")), ReasonCode.POLICY_UNAVAILABLE)


def test_forged_sha_attribute_is_ignored():
    policy = load_policy_text(BASELINE_POLICY)
    real = policy.sha256
    object.__setattr__(policy, "sha256", "0" * 64)
    engine = PolicyEngine(policy, expected_policy_sha256="0" * 64, clock=fixed_clock)
    _deny(engine.evaluate(make_request()), ReasonCode.POLICY_DIGEST_MISMATCH)
    assert PolicyEngine(policy, expected_policy_sha256=real, clock=fixed_clock).available


# --- Evaluation exceptions (fail closed) ---------------------------------------------


def test_exception_in_matcher_fails_closed(monkeypatch, engine):
    def boom(*_args, **_kwargs):
        raise RuntimeError("matcher exploded with secret sk-test-123")

    monkeypatch.setattr(engine_module, "rule_matches", boom)
    record = engine.evaluate(make_request())
    _deny(record, ReasonCode.EVALUATION_ERROR)
    assert record.error_type == "RuntimeError"
    assert "sk-test" not in str(record.to_dict())


@pytest.mark.parametrize(
    "clock",
    [
        lambda: (_ for _ in ()).throw(OSError("clock failure")),
        lambda: None,
        lambda: __import__("datetime").datetime(2026, 1, 1),  # naive
        lambda: "2026-11-09T00:00:00Z",
    ],
)
def test_bad_clock_fails_closed(clock):
    engine = PolicyEngine(load_policy_text(BASELINE_POLICY), clock=clock)
    record = engine.evaluate(make_request())
    _deny(record, ReasonCode.EVALUATION_ERROR)
    assert record.evaluated_at is None


def test_record_builder_failure_returns_fallback(monkeypatch, engine):
    def broken(*_args, **_kwargs):
        raise MemoryError

    monkeypatch.setattr(engine_module, "make_record", broken)
    assert engine.evaluate(make_request()) is FALLBACK_DENY
    assert FALLBACK_DENY.decision is Decision.DENY


def test_hostile_mapping_fails_closed(engine):
    class Hostile(Mapping):
        def __getitem__(self, key):
            raise RuntimeError("boom")

        def __iter__(self):
            return iter(["agent"])

        def __len__(self):
            return 1

    assert engine.evaluate(Hostile()).decision is Decision.DENY


def test_deeply_nested_request_fails_closed(engine):
    nested = {}
    current = nested
    for _ in range(10_000):
        current["agent"] = {}
        current = current["agent"]
    assert engine.evaluate(nested).decision is Decision.DENY


# --- Input mutation resistance ----------------------------------------------------


def test_request_mutation_after_evaluation(engine):
    request = make_request()
    record = engine.evaluate(request)
    request["agent"]["id"] = "intruder"
    request["context"]["labels"].append("x")
    assert record.decision is Decision.ALLOW
    assert engine.evaluate(make_request()).decision_digest == record.decision_digest


def test_toggling_mapping_is_read_once(engine):
    class Toggle(Mapping):
        """Returns 'read' on first access to 'operation', 'delete' afterwards."""

        def __init__(self, data):
            self._data = data
            self._reads = 0

        def __getitem__(self, key):
            if key == "operation":
                self._reads += 1
                return "read" if self._reads == 1 else "delete"
            return self._data[key]

        def __iter__(self):
            return iter(self._data)

        def __len__(self):
            return len(self._data)

    toggle = Toggle(make_request())
    record = engine.evaluate(toggle)
    assert toggle._reads == 1
    assert record.decision is Decision.ALLOW
    assert record.request_digest == engine.evaluate(make_request()).request_digest


def test_typed_request_mutated_after_construction(engine):
    request = AuthorizationRequest(
        agent=AgentIdentity("support-bot"),
        tool=ToolIdentity("mcp://helpdesk/tickets.get"),
        operation=OperationClass.READ,
        resource=parse_resource("db:helpdesk/tickets"),
        context=AuthorizationContext(Environment.STAGING),
    )
    object.__setattr__(request.agent, "agent_id", "*")
    _deny(engine.evaluate(request), ReasonCode.INVALID_IDENTITY)

    request2 = AuthorizationRequest(
        agent=AgentIdentity("build-agent"),
        tool=ToolIdentity("mcp://fs/write_file"),
        operation=OperationClass.WRITE,
        resource=parse_resource("fs:/srv/workspace/a"),
        context=AuthorizationContext(Environment.DEV),
    )
    object.__setattr__(request2.resource, "segments", ("srv", "workspace", "..", "etc"))
    _deny(engine.evaluate(request2), ReasonCode.INVALID_RESOURCE)


# --- Property-style fuzzing ------------------------------------------------------------

_POOL = {
    "agent": [None, "support-bot", "build-agent", "ops-bot", "research-bot", "x", "*", "", "Bad"],
    "assurance": ["asserted", "authenticated", "root"],
    "tool": [
        "mcp://helpdesk/tickets.get", "mcp://helpdesk/tickets.update", "mcp://mail/send",
        "mcp://fs/write_file", "mcp://shell/run", "mcp://web/fetch", "mcp://x/y", "send",
    ],
    "operation": [o.value for o in OperationClass] + ["READ", "launch"],
    "resource": [
        "db:helpdesk/tickets", "email:customer.example.com", "fs:/srv/workspace/a",
        "fs:/srv/workspace/.rig-sentinel/p", "shell:git", "url:https://docs.example.com/a",
        "url:https://evil.example/a", "fs:/a/../b", "none:",
    ],
    "environment": ["dev", "staging", "prod", "qa"],
    "labels": [[], ["untrusted_content_present"], ["other"]],
}


def test_fuzzed_requests_never_raise_and_allow_only_via_allow_rules(engine):
    rng = random.Random(1109)
    allowed = 0
    for _ in range(2500):
        request = make_request(**{key: rng.choice(values) for key, values in _POOL.items()})
        record = engine.evaluate(request)
        assert record.decision in set(Decision)
        assert record.enforced is False
        if record.decision is Decision.ALLOW:
            allowed += 1
            assert record.reason_code is ReasonCode.RULE_ALLOW
            assert record.deciding_rule_ids
            # Re-evaluation is identical.
            assert engine.evaluate(request) == record
        else:
            assert record.reason_code is not ReasonCode.RULE_ALLOW
    assert allowed > 0  # the fuzzer does reach the allow path
