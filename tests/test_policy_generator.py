
from types import SimpleNamespace

from rig_sentinel.policy_generator import PolicyGenerator


def make_report(
    privilege_findings=(),
    shared_credential_findings=(),
):
    return SimpleNamespace(
        privilege_findings=privilege_findings,
        shared_credential_findings=shared_credential_findings,
    )


def test_generates_financial_security_policy():
    finding = SimpleNamespace(
        agent="finance_agent",
        identity="STRIPE_SECRET_KEY",
        capability="financial_action",
        severity="CRITICAL",
        reason="Financial mutation capability detected.",
    )

    report = make_report(
        privilege_findings=(finding,),
    )

    policies = PolicyGenerator().generate(report)

    assert len(policies) == 1

    policy = policies[0]

    assert policy.agent == "finance_agent"
    assert policy.identity == "STRIPE_SECRET_KEY"
    assert policy.severity == "CRITICAL"
    assert policy.enforcement == "advisory"

    assert "restrict_financial_operations" in policy.controls
    assert "require_human_approval" in policy.controls
    assert "use_restricted_credential" in policy.controls


def test_generates_shared_identity_policies():
    finding = SimpleNamespace(
        identity="OPENAI_API_KEY",
        agents=("agent_a", "agent_b"),
        severity="HIGH",
    )

    report = make_report(
        shared_credential_findings=(finding,),
    )

    policies = PolicyGenerator().generate(report)

    assert len(policies) == 2

    assert {
        policy.agent
        for policy in policies
    } == {"agent_a", "agent_b"}

    for policy in policies:
        assert policy.identity == "OPENAI_API_KEY"
        assert "verify_shared_credential" in policy.controls
        assert "isolate_runtime_identity" in policy.controls
        assert policy.enforcement == "advisory"


def test_merges_controls_without_duplicates():
    privilege = SimpleNamespace(
        agent="finance_agent",
        identity="STRIPE_SECRET_KEY",
        capability="financial_action",
        severity="CRITICAL",
        reason="Financial operation detected.",
    )

    shared = SimpleNamespace(
        identity="STRIPE_SECRET_KEY",
        agents=("finance_agent", "other_agent"),
        severity="HIGH",
    )

    report = make_report(
        privilege_findings=(privilege,),
        shared_credential_findings=(shared,),
    )

    policies = PolicyGenerator().generate(report)

    assert len(policies) == 2

    finance_policy = next(
        policy
        for policy in policies
        if policy.agent == "finance_agent"
    )

    assert finance_policy.severity == "CRITICAL"
    assert "require_human_approval" in finance_policy.controls
    assert "verify_shared_credential" in finance_policy.controls

    assert len(finance_policy.controls) == len(
        set(finance_policy.controls)
    )


def test_empty_findings_generate_no_policies():
    report = make_report()

    generator = PolicyGenerator()
    policies = generator.generate(report)

    assert policies == ()

    output = generator.to_dict(policies)

    assert output["policy_count"] == 0
    assert output["policies"] == []
    assert output["enforcement"] == "advisory"


def test_policy_output_is_json_serializable():
    import json

    finding = SimpleNamespace(
        agent="finance_agent",
        identity="STRIPE_SECRET_KEY",
        capability="financial_action",
        severity="CRITICAL",
        reason="Financial mutation capability detected.",
    )

    generator = PolicyGenerator()

    policies = generator.generate(
        make_report(
            privilege_findings=(finding,),
        )
    )

    output = generator.to_dict(policies)

    encoded = json.dumps(output)
    decoded = json.loads(encoded)

    assert decoded["policy_count"] == 1

    assert decoded["policies"][0]["agent"] == (
        "finance_agent"
    )
