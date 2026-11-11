"""Genesis B2-P1 remediation of the independent (Gemini) security review.

* H-1: ``manifest_sha256`` identifies the tool, so v3 events carry ``manifest_ref``
  (a K_ref reference in its own namespace) instead, or nothing without K_ref.
* M-1: in ``omitted`` mode, non-allowlisted labels are counted in ``omitted_labels_count``.
* Digest domain: v3 keeps the M2-B digest and MAC construction; cross-version confusion
  must stay impossible.

Each validation layer (caller schema, event, parser, builder, persistence gate) is tested on
its own, so that redundant checks cannot mask a defect. Synthetic values only.
"""

import dataclasses
import hashlib
import hmac
import json

import pytest
from audit_fixtures import FIXED_AUDIT_NOW, REF_MATERIAL, auth_key, both_keys, counter_ids, ref_key
from policy_fixtures import baseline_engine, make_request

from rig_sentinel.audit import (
    AUDIT_EVENT_SCHEMA,
    AUDIT_EVENT_SCHEMA_V3,
    AuditEnvelope,
    AuditError,
    AuditErrorCode,
    AuditEventBuilder,
    AuditKeys,
    AuthStatus,
    IdentityMode,
    MemorySink,
    PersistenceCode,
    RequestConsistency,
    check_persistable,
    envelope_from_dict,
    event_from_dict,
    event_v3_from_dict,
    keyring,
    verify_envelope_dict,
)
from rig_sentinel.audit.chain import REF_DOMAIN, pseudonym
from rig_sentinel.audit.events import CALLER_FIELDS, CALLER_V3_FIELDS
from rig_sentinel.policy.model import MAX_REQUEST_LABELS

NUL = bytes(1)
RING = keyring([auth_key()])

# Attacker-chosen manifest digest used as a canary (64 lowercase hex, valid for M1).
MANIFEST_CANARY = "5eed" + "c0de" * 15
# Independent known answer: HMAC-SHA-256(bytes 1..32, "rig.audit-ref/v1/manifest" NUL canary)[:32].
MANIFEST_REF_VECTOR = "984ca173e8f8219f847571ca4ea5af1c"
# The same canary in the tool namespace must differ.
TOOL_NAMESPACE_VECTOR = "785d4b4de901997719948472c03389f5"


def v3_builder(keys=None, **kwargs):
    return AuditEventBuilder(both_keys() if keys is None else keys, clock=lambda: FIXED_AUDIT_NOW,
                             id_factory=counter_ids(), event_schema=AUDIT_EVENT_SCHEMA_V3, **kwargs)


def v2_builder(keys=None):
    return AuditEventBuilder(both_keys() if keys is None else keys, clock=lambda: FIXED_AUDIT_NOW,
                             id_factory=counter_ids())


def omitted_keys():
    return AuditKeys(auth=auth_key())


def evaluated(**overrides):
    request = make_request(**overrides)
    return request, baseline_engine().evaluate(request)


def raw_ref(namespace, value):
    message = f"{REF_DOMAIN}/{namespace}".encode() + NUL + value.encode()
    return hmac.new(REF_MATERIAL, message, hashlib.sha256).hexdigest()[:32]


def manifest_leaks(text):
    """Any occurrence of the canary or a recognizable piece of it."""
    return [piece for piece in (MANIFEST_CANARY, MANIFEST_CANARY[:32], MANIFEST_CANARY[32:], "c0dec0dec0de")
            if piece in text]


def everything_said_about(envelope, *extra):
    parts = [envelope.canonical_bytes().decode("ascii"), repr(envelope), str(envelope),
             repr(envelope.event), repr(envelope.event.caller), json.dumps(envelope.to_dict())]
    parts.extend(repr(item) for item in extra)
    return "\n".join(parts)


# --- H-1: manifest privacy -----------------------------------------------------------


def test_manifest_ref_known_answer_vector_is_independent_of_the_implementation():
    assert raw_ref("manifest", MANIFEST_CANARY) == MANIFEST_REF_VECTOR
    assert raw_ref("tool", MANIFEST_CANARY) == TOOL_NAMESPACE_VECTOR
    assert pseudonym(ref_key(), "manifest", MANIFEST_CANARY) == MANIFEST_REF_VECTOR


def test_v3_schema_has_manifest_ref_and_no_raw_manifest_field():
    assert "manifest_ref" in CALLER_V3_FIELDS
    assert "manifest_sha256" not in CALLER_V3_FIELDS
    assert "omitted_labels_count" in CALLER_V3_FIELDS


def test_pseudonymized_mode_replaces_the_manifest_digest_with_a_keyed_reference():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    envelope = v3_builder().build_envelope(record, request)
    caller = envelope.event.caller
    assert caller.identity_mode is IdentityMode.PSEUDONYMIZED
    assert caller.manifest_ref == MANIFEST_REF_VECTOR
    assert caller.manifest_ref != caller.tool_ref
    assert caller.tool_ref == raw_ref("tool", "mcp://helpdesk/tickets.get")
    assert "manifest_sha256" not in envelope.event.to_dict()["caller"]
    assert manifest_leaks(everything_said_about(envelope)) == []


def test_tool_and_manifest_namespaces_are_distinct_for_the_same_value():
    assert pseudonym(ref_key(), "tool", MANIFEST_CANARY) != pseudonym(ref_key(), "manifest", MANIFEST_CANARY)


def test_pseudonymized_mode_without_a_manifest_has_a_null_manifest_ref():
    request, record = evaluated()
    caller = v3_builder().build(record, request).caller
    assert caller.manifest_ref is None and caller.tool_ref is not None


def test_omitted_mode_drops_the_manifest_digest_and_its_reference():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    envelope = v3_builder(omitted_keys()).build_envelope(record, request)
    caller = envelope.event.caller
    assert caller.identity_mode is IdentityMode.OMITTED
    assert caller.manifest_ref is None
    assert manifest_leaks(everything_said_about(envelope)) == []


@pytest.mark.parametrize("mode", ["pseudonymized", "omitted"])
def test_manifest_canary_never_reaches_receipts_verdicts_sinks_or_errors(mode):
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY, labels=["reviewed", "team-payroll"])
    builder = v3_builder() if mode == "pseudonymized" else v3_builder(omitted_keys())
    envelope = builder.build_envelope(record, request)
    sink = MemorySink(verify_keys=RING)
    receipt = sink.append(envelope)
    verdict = check_persistable(envelope, RING)
    assert receipt.stored and verdict.ok
    stored = b"".join(item.canonical_bytes() for item in sink.envelopes()).decode("ascii")
    errors = []
    forged = json.loads(envelope.canonical_bytes())
    forged["event"]["caller"]["manifest_sha256"] = MANIFEST_CANARY
    for parse in (lambda: envelope_from_dict(forged), lambda: event_v3_from_dict(forged["event"])):
        with pytest.raises(AuditError) as info:
            parse()
        errors.append(f"{info.value!s} {info.value!r} {info.value.args!r}")
    text = everything_said_about(envelope, receipt, verdict, builder) + stored + "\n".join(errors)
    assert manifest_leaks(text) == []


def test_forged_raw_manifest_field_is_rejected_by_the_v3_parser():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    data = json.loads(v3_builder().build_envelope(record, request).canonical_bytes())
    data["event"]["caller"]["manifest_sha256"] = MANIFEST_CANARY
    with pytest.raises(AuditError) as info:
        envelope_from_dict(data)
    assert info.value.code is AuditErrorCode.UNKNOWN_FIELD
    renamed = json.loads(v3_builder().build_envelope(record, request).canonical_bytes())
    renamed["event"]["caller"]["manifest_sha256"] = renamed["event"]["caller"].pop("manifest_ref")
    with pytest.raises(AuditError) as info:
        envelope_from_dict(renamed)
    assert info.value.code in (AuditErrorCode.UNKNOWN_FIELD, AuditErrorCode.MISSING_FIELD)


@pytest.mark.parametrize(
    "bad",
    [MANIFEST_CANARY, MANIFEST_CANARY.upper()[:32], "g" * 32, "a" * 31, "a" * 33, "", 7, True,
     type("S", (str,), {})("a" * 32)],
    ids=["raw-64-hex", "uppercase", "non-hex", "short", "long", "empty", "int", "bool", "str-subclass"],
)
def test_invalid_manifest_references_are_rejected_by_the_caller_schema(bad):
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    caller = v3_builder().build(record, request).caller
    with pytest.raises(AuditError) as info:
        dataclasses.replace(caller, manifest_ref=bad)
    assert info.value.code is AuditErrorCode.INVALID_FIELD
    assert manifest_leaks(str(info.value) + repr(info.value)) == []


def test_omitted_caller_schema_rejects_a_manifest_reference_on_its_own():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    caller = v3_builder(omitted_keys()).build(record, request).caller
    with pytest.raises(AuditError) as info:
        dataclasses.replace(caller, manifest_ref=MANIFEST_REF_VECTOR)
    assert info.value.code is AuditErrorCode.INCONSISTENT_EVENT


def test_omitted_parser_rejects_a_manifest_reference():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    data = json.loads(v3_builder(omitted_keys()).build_envelope(record, request).canonical_bytes())
    data["event"]["caller"]["manifest_ref"] = MANIFEST_REF_VECTOR
    with pytest.raises(AuditError) as info:
        event_v3_from_dict(data["event"])
    assert info.value.code is AuditErrorCode.INCONSISTENT_EVENT


def test_gate_rejects_a_sealed_v3_event_carrying_the_raw_manifest_digest():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    event = v3_builder().build(record, request)
    object.__setattr__(event.caller, "manifest_ref", MANIFEST_CANARY)  # bypasses the model
    sealed = AuditEnvelope.seal(event, auth_key())
    assert sealed.verify(RING) is AuthStatus.AUTHENTIC  # the MAC alone cannot catch this
    verdict = check_persistable(sealed, RING)
    assert verdict.code is PersistenceCode.SCHEMA_INVALID
    assert manifest_leaks(repr(verdict)) == []


def test_wrong_ref_key_gives_a_different_manifest_reference():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    from rig_sentinel.audit import AuditKey, KeyPurpose

    other = AuditKeys(ref=AuditKey.from_bytes(KeyPurpose.REF, bytes(range(70, 102))), auth=auth_key())
    assert v3_builder(other).build(record, request).caller.manifest_ref != MANIFEST_REF_VECTOR


def test_v2_manifest_representation_is_unchanged():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    caller = v2_builder().build(record, request).to_dict()["caller"]
    assert caller["manifest_sha256"] == MANIFEST_CANARY  # v2 keeps its documented readable field
    assert "manifest_ref" not in caller and "omitted_labels_count" not in caller
    assert CALLER_FIELDS == frozenset({
        "consistency", "agent_id", "assurance_claim", "tool_id", "manifest_sha256", "operation",
        "environment", "labels", "resource", "session_ref", "request_ref", "redacted_fields",
    })


def test_m1_decision_and_request_digest_are_unaffected_by_the_manifest_change():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    again = baseline_engine().evaluate(make_request(manifest_sha256=MANIFEST_CANARY))
    v3 = v3_builder().build(record, request)
    assert v3.engine.request_digest == record.request_digest == again.request_digest
    assert v3.engine.decision_ref == record.decision_digest
    assert v3.caller.consistency is RequestConsistency.CONSISTENT


# --- M-1: omitted label accounting ---------------------------------------------------


@pytest.mark.parametrize(
    "labels, readable, omitted",
    [
        ([], (), 0),
        (["reviewed"], ("reviewed",), 0),
        (["team-payroll"], (), 1),
        (["reviewed", "team-payroll", "untrusted_content_present", "zz-other"],
         ("reviewed", "untrusted_content_present"), 2),
    ],
    ids=["none", "approved-only", "one", "mixed"],
)
def test_omitted_mode_counts_every_non_allowlisted_label(labels, readable, omitted):
    request, record = evaluated(labels=labels)
    caller = v3_builder(omitted_keys()).build(record, request).caller
    assert caller.readable_labels == readable
    assert caller.omitted_labels_count == omitted  # zero, not absent, when nothing is omitted
    assert type(caller.omitted_labels_count) is int
    assert caller.label_refs is None


def test_maximum_valid_count_under_the_m1_request_contract():
    assert MAX_REQUEST_LABELS == 32
    others = [f"label-{i:02d}" for i in range(MAX_REQUEST_LABELS)]
    request, record = evaluated(labels=others)
    caller = v3_builder(omitted_keys()).build(record, request).caller
    assert caller.consistency is RequestConsistency.CONSISTENT
    assert caller.omitted_labels_count == MAX_REQUEST_LABELS
    mixed = ["reviewed", "untrusted_content_present"] + others[:MAX_REQUEST_LABELS - 2]
    request, record = evaluated(labels=mixed)
    caller = v3_builder(omitted_keys()).build(record, request).caller
    assert len(caller.readable_labels) + caller.omitted_labels_count == MAX_REQUEST_LABELS


def test_narrowed_allowlist_counts_approved_labels_that_are_not_readable():
    request, record = evaluated(labels=["reviewed", "untrusted_content_present"])
    caller = v3_builder(omitted_keys(), readable_labels=frozenset({"reviewed"})).build(record, request).caller
    assert caller.readable_labels == ("reviewed",) and caller.omitted_labels_count == 1


@pytest.mark.parametrize("count", [33, 50])
def test_more_than_max_request_labels_is_rejected_upstream_not_counted(count):
    labels = [f"label-{i:02d}" for i in range(count)]
    request, record = evaluated(labels=labels)
    assert record.reason_code.value == "INVALID_REQUEST"
    for keys in (omitted_keys(), both_keys()):
        caller = v3_builder(keys).build(record, request).caller
        assert caller.consistency is RequestConsistency.INVALID_REQUEST
        assert caller.omitted_labels_count is None  # rejected by validation, not omitted for privacy
        assert caller.readable_labels is None and caller.label_refs is None


def test_pseudonymized_mode_has_no_omission_count():
    request, record = evaluated(labels=["reviewed", "team-payroll"])
    caller = v3_builder().build(record, request).caller
    assert caller.omitted_labels_count is None
    assert caller.label_refs == (raw_ref("label", "team-payroll"),)


def _consistent_callers():
    request, record = evaluated(labels=["reviewed", "team-payroll"])
    return v3_builder(omitted_keys()).build(record, request).caller, v3_builder().build(record, request).caller


@pytest.mark.parametrize(
    "bad",
    [-1, True, False, 1.0, "1", None, 33, 10**6, type("I", (int,), {})(1)],
    ids=["negative", "true", "false", "float", "string", "null", "above-max", "huge", "int-subclass"],
)
def test_caller_schema_rejects_malformed_counts_in_omitted_mode(bad):
    omitted, _pseudonymized = _consistent_callers()
    with pytest.raises(AuditError) as info:
        dataclasses.replace(omitted, omitted_labels_count=bad)
    assert info.value.code in (AuditErrorCode.INVALID_FIELD, AuditErrorCode.INCONSISTENT_EVENT)


def test_caller_schema_rejects_a_count_above_the_labels_left_by_readable_labels():
    omitted, _pseudonymized = _consistent_callers()
    assert omitted.readable_labels == ("reviewed",)
    assert dataclasses.replace(omitted, omitted_labels_count=MAX_REQUEST_LABELS - 1).omitted_labels_count == 31
    with pytest.raises(AuditError) as info:
        dataclasses.replace(omitted, omitted_labels_count=MAX_REQUEST_LABELS)
    assert info.value.code is AuditErrorCode.LIMIT_EXCEEDED


def test_pseudonymized_caller_schema_bounds_readable_plus_referenced_labels():
    _omitted, pseudonymized = _consistent_callers()
    assert pseudonymized.readable_labels == ("reviewed",)
    refs = tuple(f"{i:032x}" for i in range(MAX_REQUEST_LABELS))
    assert len(dataclasses.replace(pseudonymized, label_refs=refs[:31]).label_refs) == 31
    with pytest.raises(AuditError) as info:
        dataclasses.replace(pseudonymized, label_refs=refs)
    assert info.value.code is AuditErrorCode.LIMIT_EXCEEDED


@pytest.mark.parametrize("count", [0, 1])
def test_caller_schema_rejects_any_count_in_pseudonymized_mode(count):
    _omitted, pseudonymized = _consistent_callers()
    with pytest.raises(AuditError) as info:
        dataclasses.replace(pseudonymized, omitted_labels_count=count)
    assert info.value.code is AuditErrorCode.INCONSISTENT_EVENT


@pytest.mark.parametrize("consistency", [RequestConsistency.MISMATCH, RequestConsistency.INVALID_REQUEST,
                                         RequestConsistency.NOT_APPLICABLE])
def test_caller_schema_rejects_a_count_for_non_consistent_requests(consistency):
    request, record = evaluated(resource="fs:/a/../b")
    caller = v3_builder(omitted_keys()).build(record, request).caller
    assert caller.omitted_labels_count is None
    with pytest.raises(AuditError) as info:
        dataclasses.replace(caller, consistency=consistency, omitted_labels_count=0)
    assert info.value.code is AuditErrorCode.INCONSISTENT_EVENT


@pytest.mark.parametrize(
    "bad",
    [-1, True, 1.0, "1", None, 33, 2**64],
    ids=["negative", "bool", "float", "string", "null", "above-max", "huge"],
)
def test_parser_rejects_malformed_counts(bad):
    request, record = evaluated(labels=["reviewed", "team-payroll"])
    data = json.loads(v3_builder(omitted_keys()).build_envelope(record, request).canonical_bytes())
    assert data["event"]["caller"]["omitted_labels_count"] == 1
    data["event"]["caller"]["omitted_labels_count"] = bad
    with pytest.raises(AuditError):
        event_v3_from_dict(data["event"])
    assert verify_envelope_dict(data, RING) is not AuthStatus.AUTHENTIC


def test_parser_requires_the_count_field():
    request, record = evaluated(labels=["team-payroll"])
    data = json.loads(v3_builder(omitted_keys()).build_envelope(record, request).canonical_bytes())
    del data["event"]["caller"]["omitted_labels_count"]
    with pytest.raises(AuditError) as info:
        event_v3_from_dict(data["event"])
    assert info.value.code is AuditErrorCode.MISSING_FIELD


def test_count_cannot_be_changed_without_k_auth():
    request, record = evaluated(labels=["team-payroll"])
    data = json.loads(v3_builder(omitted_keys()).build_envelope(record, request).canonical_bytes())
    data["event"]["caller"]["omitted_labels_count"] = 0  # well-formed but forged
    assert envelope_from_dict(data).verify(RING) in (AuthStatus.DIGEST_MISMATCH, AuthStatus.MAC_MISMATCH)


def test_gate_rejects_a_sealed_event_with_a_malformed_count():
    request, record = evaluated(labels=["team-payroll"])
    for bad in (-1, True, 99):
        event = v3_builder(omitted_keys()).build(record, request)
        object.__setattr__(event.caller, "omitted_labels_count", bad)
        sealed = AuditEnvelope.seal(event, auth_key())
        assert check_persistable(sealed, RING).code is PersistenceCode.SCHEMA_INVALID


def test_gate_accepts_counts_in_omitted_mode_and_null_in_pseudonymized_mode():
    request, record = evaluated(labels=["reviewed", "team-payroll"])
    for keys in (omitted_keys(), both_keys()):
        assert check_persistable(v3_builder(keys).build_envelope(record, request), RING).ok


def test_v2_redacted_fields_are_unchanged_by_label_accounting():
    request, record = evaluated(labels=["reviewed", "team-payroll"])
    for keys in (both_keys(), omitted_keys()):
        caller = v2_builder(keys).build(record, request).caller
        assert caller.labels == ("reviewed", "team-payroll") and caller.redacted_fields == 0
    credential_like = "sk-" + "a1b2c3"
    request, record = evaluated(labels=["reviewed", credential_like])
    assert v2_builder().build(record, request).caller.redacted_fields == 1


# --- Digest domain: retained, and cross-version confusion stays impossible -----------


def test_v3_retains_the_m2b_digest_domain():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    envelope = v3_builder().build_envelope(record, request)
    body = envelope.event.canonical_bytes()
    assert envelope.event_digest == hashlib.sha256(b"rig.audit-event/v2" + NUL + body).hexdigest()


@pytest.mark.parametrize("keys", ["both", "omitted"])
def test_relabelling_a_sealed_v3_event_as_v2_never_verifies_or_parses(keys):
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY, labels=["team-payroll"])
    envelope = v3_builder(both_keys() if keys == "both" else omitted_keys()).build_envelope(record, request)
    data = json.loads(envelope.canonical_bytes())
    data["event"]["schema_version"] = AUDIT_EVENT_SCHEMA
    with pytest.raises(AuditError):
        event_from_dict(data["event"])
    assert verify_envelope_dict(data, RING) is AuthStatus.SCHEMA_INVALID


def test_relabelling_a_sealed_v2_event_as_v3_never_verifies_or_parses():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    data = json.loads(v2_builder().build_envelope(record, request).canonical_bytes())
    data["event"]["schema_version"] = AUDIT_EVENT_SCHEMA_V3
    with pytest.raises(AuditError):
        event_v3_from_dict(data["event"])
    assert verify_envelope_dict(data, RING) is AuthStatus.SCHEMA_INVALID


def test_v2_and_v3_events_for_one_decision_never_share_a_digest_or_mac():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    v2 = v2_builder().build_envelope(record, request)
    v3 = v3_builder().build_envelope(record, request)
    assert v2.event_digest != v3.event_digest and v2.auth.mac != v3.auth.mac


def test_v2_parser_rejects_the_new_v3_fields():
    request, record = evaluated(manifest_sha256=MANIFEST_CANARY)
    data = json.loads(v2_builder().build_envelope(record, request).canonical_bytes())["event"]
    for field, value in (("manifest_ref", MANIFEST_REF_VECTOR), ("omitted_labels_count", 0)):
        bad = json.loads(json.dumps(data))
        bad["caller"][field] = value
        with pytest.raises(AuditError) as info:
            event_from_dict(bad)
        assert info.value.code is AuditErrorCode.UNKNOWN_FIELD
