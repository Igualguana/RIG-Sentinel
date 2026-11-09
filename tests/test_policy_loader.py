import pytest
from policy_fixtures import BASELINE_POLICY

from rig_sentinel.policy import (
    PolicyDigestMismatchError,
    PolicyLoadError,
    PolicyValidationError,
    load_policy_bytes,
    load_policy_file,
    load_policy_text,
)
from rig_sentinel.policy.schema import MAX_POLICY_BYTES


def test_load_from_file(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_bytes(BASELINE_POLICY.encode("utf-8"))
    policy = load_policy_file(path)
    assert policy.policy_id == "acme-support-agents"
    assert load_policy_file(str(path)) == policy


def test_missing_file(tmp_path):
    with pytest.raises(PolicyLoadError):
        load_policy_file(tmp_path / "absent.toml")


@pytest.mark.parametrize(
    "text",
    [
        'schema_version = "rig.policy/v1"\npolicy_id = ',  # truncated
        "[[rules]\n",  # broken table header
        'policy_id = "a"\npolicy_id = "b"\n',  # duplicate key
        "this is not toml",
        'x = """unterminated',
    ],
)
def test_malformed_toml(text):
    with pytest.raises(PolicyLoadError) as info:
        load_policy_text(text)
    assert not isinstance(info.value, PolicyValidationError)
    assert "malformed TOML" in str(info.value)


def test_toml_native_types_are_rejected():
    text = BASELINE_POLICY.replace(
        'policy_version = "2026.11.09-1"', "policy_version = 2026-11-09"
    )
    with pytest.raises(PolicyValidationError):
        load_policy_text(text)


def test_bom_is_rejected():
    with pytest.raises(PolicyLoadError):
        load_policy_bytes(b"\xef\xbb\xbf" + BASELINE_POLICY.encode("utf-8"))


def test_invalid_utf8_is_rejected():
    with pytest.raises(PolicyLoadError):
        load_policy_bytes(BASELINE_POLICY.encode("utf-8") + b"\n# \xff\xfe\n")


def test_oversize_is_rejected(tmp_path):
    padding = "# " + "x" * 100 + "\n"
    text = BASELINE_POLICY + padding * (MAX_POLICY_BYTES // len(padding) + 1)
    with pytest.raises(PolicyLoadError):
        load_policy_text(text)
    path = tmp_path / "big.toml"
    path.write_bytes(text.encode("utf-8"))
    with pytest.raises(PolicyLoadError):
        load_policy_file(path)


def test_deep_nesting_is_rejected_cleanly():
    depth = 50_000
    text = "x = " + "[" * depth + "]" * depth + "\n"
    with pytest.raises(PolicyLoadError):
        load_policy_text(text)


@pytest.mark.parametrize("value", [None, 1, BASELINE_POLICY])
def test_load_bytes_requires_bytes(value):
    with pytest.raises(PolicyLoadError):
        load_policy_bytes(value)


def test_load_text_requires_str():
    with pytest.raises(PolicyLoadError):
        load_policy_text(BASELINE_POLICY.encode("utf-8"))


def test_digest_pinning():
    policy = load_policy_text(BASELINE_POLICY)
    assert load_policy_text(BASELINE_POLICY, expected_sha256=policy.sha256) == policy

    with pytest.raises(PolicyDigestMismatchError):
        load_policy_text(BASELINE_POLICY, expected_sha256="0" * 64)
    with pytest.raises(PolicyDigestMismatchError):
        load_policy_text(BASELINE_POLICY, expected_sha256=policy.sha256.upper())
    with pytest.raises(PolicyDigestMismatchError):
        load_policy_text(BASELINE_POLICY, expected_sha256="not-a-digest")


def test_policy_substitution_is_detected():
    original = load_policy_text(BASELINE_POLICY)
    substituted = BASELINE_POLICY.replace('decision = "deny"', 'decision = "require_approval"').replace(
        'scopes = ["approve-ticket-updates", "approve-customer-mail"]', 'scopes = ["*"]'
    )
    with pytest.raises(PolicyDigestMismatchError):
        load_policy_text(substituted, expected_sha256=original.sha256)
