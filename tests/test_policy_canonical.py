import pytest
from policy_fixtures import BASELINE_POLICY, POLICY_HEADER, RULE_BLOCKS, policy_text

from rig_sentinel.policy import load_policy_text
from rig_sentinel.policy.canonical import (
    POLICY_DIGEST_DOMAIN,
    REQUEST_DIGEST_DOMAIN,
    canonical_json,
    digest,
)


def test_canonical_json_is_stable():
    assert canonical_json({"b": 1, "a": [2, "x"]}) == b'{"a":[2,"x"],"b":1}'
    assert canonical_json({"k": "é"}) == b'{"k":"\\u00e9"}'


def test_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_digest_is_domain_separated():
    value = {"a": 1}
    assert digest(POLICY_DIGEST_DOMAIN, value) != digest(REQUEST_DIGEST_DOMAIN, value)


def test_formatting_and_comments_do_not_change_digest():
    base = load_policy_text(BASELINE_POLICY).sha256
    reformatted = "# leading comment\n" + BASELINE_POLICY.replace(" = ", "   =   ").replace(
        "\n\n", "\n\n# spacer\n\n"
    )
    assert load_policy_text(reformatted).sha256 == base


def test_order_does_not_change_digest():
    base = load_policy_text(BASELINE_POLICY).sha256
    assert load_policy_text(policy_text(tuple(reversed(RULE_BLOCKS)))).sha256 == base
    swapped = BASELINE_POLICY.replace(
        'agents = ["*"]\ntools = ["*"]\noperations = ["write", "delete"]',
        'agents = ["*"]\ntools = ["*"]\noperations = ["delete", "write"]',
    )
    assert swapped != BASELINE_POLICY
    assert load_policy_text(swapped).sha256 == base


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('effect = "allow"', 'effect = "deny"'),
        ('policy_version = "2026.11.09-1"', 'policy_version = "2026.11.09-2"'),
        ("approval_ttl_seconds = 300", "approval_ttl_seconds = 301"),
        ('"db:helpdesk/tickets"', '"db:helpdesk/tickets2"'),
        ("Synthetic policy for automated tests.", "Edited description."),
    ],
)
def test_semantic_changes_change_digest(old, new):
    base = load_policy_text(BASELINE_POLICY).sha256
    changed = BASELINE_POLICY.replace(old, new, 1)
    assert changed != BASELINE_POLICY
    assert load_policy_text(changed).sha256 != base


def test_header_only_policy_has_digest():
    policy = load_policy_text(POLICY_HEADER.replace(
        'scopes = ["approve-ticket-updates", "approve-customer-mail"]', 'scopes = ["*"]'
    ))
    assert len(policy.sha256) == 64
    assert policy.rules == ()
