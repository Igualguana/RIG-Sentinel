"""Genesis B2-P2-B1: privacy-safe audit projection (pure core).

Covers the approved P2-A final architecture: ``rig.audit-projection/v1`` inside
``rig.audit-envelope/v2``, the derived engine-reference key K_eref, keyed request,
decision and approval-binding references, keyed approver references, explicit
projection profiles, downgrade prevention, verification of the sealed v3 source,
and authentication of the projected envelope.

Each layer (keys, references, schema classes, parser, projector, envelope
verification) is tested on its own so that redundant checks cannot mask a defect.
Synthetic values only; known-answer vectors are recomputed with ``hmac``/``hashlib``.
"""

import base64
import builtins
import dataclasses
import hashlib
import hmac
import io
import json
import pickle
import socket

import pytest
from audit_fixtures import (
    AUTH_MATERIAL,
    FIXED_AUDIT_NOW,
    REF_MATERIAL,
    auth_key,
    both_keys,
    counter_ids,
    ref_key,
)
from policy_fixtures import POLICY_HEADER, RULE_BLOCKS, fixed_clock, make_request

from rig_sentinel.audit import (
    AUDIT_ENVELOPE_SCHEMA,
    AUDIT_ENVELOPE_SCHEMA_V2,
    AUDIT_EVENT_SCHEMA,
    AUDIT_EVENT_SCHEMA_V3,
    AUDIT_PROJECTION_SCHEMA,
    ENGINE_REF_DOMAIN,
    PROJECTION_DIGEST_DOMAIN,
    PROJECTION_MAC_DOMAIN,
    PROJECTOR_VERSION,
    AuditEnvelope,
    AuditError,
    AuditErrorCode,
    AuditEventBuilder,
    AuditEventV3,
    AuditKey,
    AuditKeys,
    AuthStatus,
    KeyPurpose,
    MemorySink,
    PersistenceCode,
    ProjectionApproval,
    ProjectionEngine,
    ProjectionEnvelope,
    ProjectionEvent,
    ProjectionMeta,
    ProjectionProfile,
    RedactionMode,
    RequestConsistency,
    check_persistable,
    compute_projection_digest,
    compute_projection_mac,
    derive_engine_ref_key,
    engine_reference,
    envelope_from_dict,
    event_v3_from_dict,
    keyring,
    project,
    projection_envelope_from_dict,
    projection_from_dict,
    verify_envelope_dict,
    verify_projection_envelope_dict,
)
from rig_sentinel.audit.chain import pseudonym
from rig_sentinel.policy import PolicyEngine, load_policy_text
from rig_sentinel.policy.canonical import canonical_json
from rig_sentinel.policy.schema import MAX_APPROVERS

NUL = bytes(1)
RING = keyring([auth_key()])
OTHER_REF = AuditKey.from_bytes(KeyPurpose.REF, bytes(range(70, 102)))
OTHER_AUTH = AuditKey.from_bytes(KeyPurpose.AUTH, bytes(range(110, 142)))

# Independent known-answer vectors (P2-A final architecture, section 4.4).
KAT_K_EREF = "4300c17aa021315340f7f3640f8b1c32387dffed8c8ef5c27eba7cdbd7355957"
KAT_ENGINE_REF_KEY_ID = "fe233c8b2a12f4470ca82e02dac62d17"
KAT_REQUEST_REF = "9df2c6e667a1d3b9e3895a5bb1375572"
KAT_DECISION_REF = "c9dfa171be53348564746de7742eaf2c"
KAT_BINDING_REF = "df3a61677fc8dc642a08b953a5513bc2"
KAT_SAME_VALUE_DECISION_DOMAIN = "1fbf9e695b34eb3b310198b0b13ec820"
KAT_SAME_VALUE_BINDING_DOMAIN = "ca0746e42308d50a32d8b01f3ff23398"
KAT_P1_REQUEST_NAMESPACE = "b13a491423f718e41c6fd72bff49f237"
KAT_APPROVER_ONCALL = "787eda050f2b94cb3ec60e842a016b4d"
KAT_APPROVER_SECURITY = "e861757eed4dd57d5d2b307ec77def33"
KAT_SAMPLE_DIGEST = "ecd5415f19434b20abdb365c53799635aa552a8e040f37d249338390c721693a"
KAT_SAMPLE_MAC = "30b051f8b4d69097c5613e28fc57f665c25283da420f61aecd06464555118e9f"

APPROVAL_REQUEST = dict(tool="mcp://helpdesk/tickets.update", operation="database_write",
                        resource="db:helpdesk/tickets")


# --- helpers ---------------------------------------------------------------------------


def raw_k_eref():
    return hmac.new(REF_MATERIAL, b"rig.audit-key-derive/v1" + NUL + b"engine-ref", hashlib.sha256).digest()


def raw_engine_ref(kind, value):
    message = f"rig.audit-engine-ref/v1/{kind}".encode() + NUL + value.encode()
    return hmac.new(raw_k_eref(), message, hashlib.sha256).hexdigest()[:32]


def raw_approver_ref(approver_id, material=REF_MATERIAL):
    message = b"rig.audit-ref/v1/approver" + NUL + approver_id.encode()
    return hmac.new(material, message, hashlib.sha256).hexdigest()[:32]


def engine_with_approvers(count=0, prefix="canary-approver"):
    blocks = "".join(f'\n[[approvers]]\nid = "{prefix}-{i:02d}"\nscopes = ["*"]\n' for i in range(count))
    text = POLICY_HEADER + blocks + "\n" + "\n".join(RULE_BLOCKS)
    return PolicyEngine(load_policy_text(text), clock=fixed_clock)


def evaluated(engine=None, **overrides):
    request = make_request(**overrides)
    return request, (engine or engine_with_approvers()).evaluate(request)


def v3_envelope(keys=None, engine=None, **overrides):
    request, record = evaluated(engine, **overrides)
    builder = AuditEventBuilder(both_keys() if keys is None else keys, clock=lambda: FIXED_AUDIT_NOW,
                                id_factory=counter_ids(), event_schema=AUDIT_EVENT_SCHEMA_V3)
    return builder.build_envelope(record, request)


def omitted_source(**overrides):
    return v3_envelope(AuditKeys(auth=auth_key()), **overrides)


def keyed(envelope=None, keys=None):
    return project(v3_envelope() if envelope is None else envelope, both_keys() if keys is None else keys)


def unlinked(envelope=None):
    return project(omitted_source() if envelope is None else envelope, AuditKeys(auth=auth_key()),
                   profile=ProjectionProfile.UNLINKED)


def forms(value):
    """Every encoding of a sensitive hex value that must never be persisted."""
    out = {value, value.upper(), value[:32], value[32:], value[:16], value[-16:]}
    if len(value) == 64:
        raw = bytes.fromhex(value)
        out |= {base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode().rstrip("=")}
    out.add(base64.b64encode(value.encode()).decode())
    return out


def said(*items):
    parts = []
    for item in items:
        parts.append(repr(item))
        parts.append(str(item))
        if hasattr(item, "canonical_bytes"):
            parts.append(item.canonical_bytes().decode("ascii"))
    return "\n".join(parts)


def source_secrets(source):
    engine = source.event.engine
    values = [engine.decision_ref, source.event_digest, source.auth.mac]
    if engine.request_digest is not None:
        values.append(engine.request_digest)
    if engine.approval is not None:
        values.append(engine.approval.request_binding_sha256)
    return values


def assert_no_leak(text, source, extra_plain=()):
    for secret in source_secrets(source):
        for form in forms(secret):
            assert form not in text, "leaked a source digest or MAC"
    for plain in extra_plain:
        assert plain not in text


def raises(code, fn, *args, **kwargs):
    with pytest.raises(AuditError) as info:
        fn(*args, **kwargs)
    assert info.value.code is code, info.value.code
    assert info.value.__context__ is None and info.value.__cause__ is None
    return info.value


def envelope_dict(projection_envelope):
    return json.loads(projection_envelope.canonical_bytes())


# --- K_eref and references --------------------------------------------------------------


def test_known_answer_vectors_are_independent_of_the_implementation():
    assert raw_k_eref().hex() == KAT_K_EREF
    k_eref_id = hashlib.sha256(b"rig.audit-key-id/v1" + NUL + b"engine-ref" + NUL + raw_k_eref()).hexdigest()[:32]
    assert k_eref_id == KAT_ENGINE_REF_KEY_ID
    assert raw_engine_ref("request-digest", "a1" * 32) == KAT_REQUEST_REF
    assert raw_engine_ref("decision-digest", "b2" * 32) == KAT_DECISION_REF
    assert raw_engine_ref("approval-binding", "c3" * 32) == KAT_BINDING_REF
    assert raw_approver_ref("oncall-lead") == KAT_APPROVER_ONCALL
    assert raw_approver_ref("security-officer") == KAT_APPROVER_SECURITY


def test_implementation_matches_the_known_answer_vectors():
    k_eref = derive_engine_ref_key(ref_key())
    assert k_eref.purpose is KeyPurpose.ENGINE_REF
    assert k_eref.key_id == KAT_ENGINE_REF_KEY_ID
    assert engine_reference(k_eref, "request-digest", "a1" * 32) == KAT_REQUEST_REF
    assert engine_reference(k_eref, "decision-digest", "b2" * 32) == KAT_DECISION_REF
    assert engine_reference(k_eref, "approval-binding", "c3" * 32) == KAT_BINDING_REF
    assert engine_reference(k_eref, "decision-digest", "a1" * 32) == KAT_SAME_VALUE_DECISION_DOMAIN
    assert engine_reference(k_eref, "approval-binding", "a1" * 32) == KAT_SAME_VALUE_BINDING_DOMAIN
    assert pseudonym(ref_key(), "request", "a1" * 32) == KAT_P1_REQUEST_NAMESPACE
    assert pseudonym(ref_key(), "approver", "oncall-lead") == KAT_APPROVER_ONCALL
    sample = {"schema_version": AUDIT_PROJECTION_SCHEMA, "x": 1}
    assert compute_projection_digest(sample) == KAT_SAMPLE_DIGEST
    assert compute_projection_mac(auth_key(), sample) == KAT_SAMPLE_MAC


def test_domain_constants_are_the_approved_strings():
    assert AUDIT_PROJECTION_SCHEMA == "rig.audit-projection/v1"
    assert AUDIT_ENVELOPE_SCHEMA_V2 == "rig.audit-envelope/v2"
    assert PROJECTION_DIGEST_DOMAIN == "rig.audit-projection/v1"
    assert PROJECTION_MAC_DOMAIN == "rig.audit-projection-mac/v1"
    assert ENGINE_REF_DOMAIN == "rig.audit-engine-ref/v1"
    assert PROJECTOR_VERSION == "genesis-b2-p2"


def test_the_same_value_gives_unrelated_references_in_every_domain():
    k_eref = derive_engine_ref_key(ref_key())
    value = "a1" * 32
    refs = {engine_reference(k_eref, kind, value) for kind in ("request-digest", "decision-digest", "approval-binding")}
    refs.add(pseudonym(ref_key(), "request", value))
    assert len(refs) == 4


def test_engine_ref_keys_cannot_be_built_from_raw_bytes():
    raises(AuditErrorCode.KEY_INVALID, AuditKey, KeyPurpose.ENGINE_REF, bytes(range(1, 33)))
    raises(AuditErrorCode.KEY_INVALID, AuditKey.from_bytes, KeyPurpose.ENGINE_REF, bytes(range(1, 33)))
    raises(AuditErrorCode.KEY_INVALID, AuditKey.generate, KeyPurpose.ENGINE_REF)


@pytest.mark.parametrize("bad", [auth_key(), None, b"x" * 32, "ref"], ids=["auth-key", "none", "bytes", "str"])
def test_engine_ref_key_derives_only_from_a_ref_key(bad):
    with pytest.raises(AuditError) as info:
        derive_engine_ref_key(bad)
    assert info.value.code in (AuditErrorCode.KEY_PURPOSE_MISMATCH, AuditErrorCode.KEY_INVALID)


def test_key_purposes_cannot_be_confused():
    k_eref = derive_engine_ref_key(ref_key())
    raises(AuditErrorCode.KEY_PURPOSE_MISMATCH, engine_reference, ref_key(), "request-digest", "a1" * 32)
    raises(AuditErrorCode.KEY_PURPOSE_MISMATCH, engine_reference, auth_key(), "request-digest", "a1" * 32)
    raises(AuditErrorCode.KEY_PURPOSE_MISMATCH, pseudonym, k_eref, "agent", "support-bot")
    raises(AuditErrorCode.KEY_PURPOSE_MISMATCH, AuditKeys, ref=k_eref)
    raises(AuditErrorCode.KEY_PURPOSE_MISMATCH, AuditKeys, auth=k_eref)
    raises(AuditErrorCode.KEY_PURPOSE_MISMATCH, keyring, [k_eref])
    raises(AuditErrorCode.KEY_PURPOSE_MISMATCH, compute_projection_mac, k_eref, {"x": 1})


def test_engine_ref_key_never_exposes_material():
    k_eref = derive_engine_ref_key(ref_key())
    text = repr(k_eref) + str(k_eref)
    assert KAT_K_EREF not in text and KAT_ENGINE_REF_KEY_ID in text
    with pytest.raises(TypeError):
        pickle.dumps(k_eref)
    with pytest.raises(AttributeError):
        k_eref._material = b"x"  # noqa: SLF001 - immutability check


@pytest.mark.parametrize(
    "kind, value",
    [("request", "a1" * 32), ("agent", "a1" * 32), ("", "a1" * 32), ("request-digest", "A1" * 32),
     ("request-digest", "a1" * 16), ("request-digest", "support-bot"), ("request-digest", None),
     (None, "a1" * 32), ("request-digest", type("S", (str,), {})("a1" * 32))],
    ids=["p1-namespace", "agent", "empty", "uppercase", "short", "plain", "none", "kind-none", "str-subclass"],
)
def test_engine_reference_accepts_only_approved_kinds_and_sha256_values(kind, value):
    raises(AuditErrorCode.INVALID_FIELD, engine_reference, derive_engine_ref_key(ref_key()), kind, value)


# --- Keyed projection content -----------------------------------------------------------


def test_keyed_projection_replaces_every_unkeyed_engine_digest():
    source = v3_envelope(**APPROVAL_REQUEST)
    projected = keyed(source)
    assert type(projected) is ProjectionEnvelope and type(projected.projection) is ProjectionEvent
    engine = projected.projection.engine
    src = source.event.engine
    assert engine.request_ref == raw_engine_ref("request-digest", src.request_digest)
    assert engine.decision_ref_keyed == raw_engine_ref("decision-digest", src.decision_ref)
    assert engine.approval.binding_ref == raw_engine_ref("approval-binding", src.approval.request_binding_sha256)
    assert engine.engine_ref_key_id == KAT_ENGINE_REF_KEY_ID
    assert engine.approval.eligible_approver_refs == (raw_approver_ref("oncall-lead"),)
    assert engine.approval.eligible_approver_count == 1
    assert projected.projection.projection.engine_ref_mode is ProjectionProfile.KEYED
    assert projected.projection.projection.projector_version == PROJECTOR_VERSION
    assert projected.projection.projection.source_schema == AUDIT_EVENT_SCHEMA_V3


def test_audit_and_caller_sections_are_copied_unchanged():
    source = v3_envelope(labels=["reviewed", "team-payroll"])
    projected = keyed(source)
    assert projected.projection.audit == source.event.audit
    assert projected.projection.caller == source.event.caller
    copied = ("decision", "reason_code", "protected", "enforced", "record_schema", "engine_version",
              "evaluated_at", "policy_id", "policy_version", "policy_sha256", "deciding_rule_ids",
              "deciding_rule_count", "matched_rule_ids", "matched_rule_count", "error_class")
    for name in copied:
        assert getattr(projected.projection.engine, name) == getattr(source.event.engine, name), name


def test_serialized_projection_has_exactly_the_approved_fields():
    data = envelope_dict(keyed(v3_envelope(**APPROVAL_REQUEST)))
    assert set(data) == {"envelope_schema", "projection", "projection_digest", "auth"}
    assert data["envelope_schema"] == AUDIT_ENVELOPE_SCHEMA_V2
    projection = data["projection"]
    assert set(projection) == {"schema_version", "audit", "engine", "caller", "projection"}
    assert projection["schema_version"] == AUDIT_PROJECTION_SCHEMA
    assert set(projection["engine"]) == {
        "decision", "reason_code", "protected", "enforced", "record_schema", "engine_version",
        "evaluated_at", "policy_id", "policy_version", "policy_sha256", "deciding_rule_ids",
        "deciding_rule_count", "matched_rule_ids", "matched_rule_count", "approval", "error_class",
        "request_ref", "decision_ref_keyed", "engine_ref_key_id",
    }
    assert set(projection["engine"]["approval"]) == {
        "eligible_approver_refs", "eligible_approver_count", "binding_ref", "ttl_seconds"}
    assert set(projection["projection"]) == {"projector_version", "source_schema", "engine_ref_mode"}


FORBIDDEN_KEYS = ("request_digest", "decision_ref", "decision_digest", "request_binding_sha256",
                  "eligible_approvers", "event_digest", "source_ref", "agent_id", "tool_id",
                  "manifest_sha256", "labels", "redacted_fields")


def _all_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _all_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _all_keys(item)


@pytest.mark.parametrize("profile", ["keyed", "unlinked"])
def test_no_forbidden_key_exists_at_any_depth(profile):
    if profile == "keyed":
        projected = keyed(v3_envelope(**APPROVAL_REQUEST))
    else:
        projected = unlinked(omitted_source(**APPROVAL_REQUEST))
    keys = set(_all_keys(envelope_dict(projected)))
    assert keys.isdisjoint(FORBIDDEN_KEYS)


@pytest.mark.parametrize("profile", ["keyed", "unlinked"])
def test_source_digests_and_mac_never_appear_in_any_surface(profile):
    if profile == "keyed":
        source = v3_envelope(session_id=None, request_id=None, **APPROVAL_REQUEST)
        projected = keyed(source)
    else:
        source = omitted_source(session_id=None, request_id=None, **APPROVAL_REQUEST)
        projected = unlinked(source)
    receipt = MemorySink().append(projected)  # refused, but its receipt is still a surface
    text = said(projected, projected.projection, projected.projection.engine, receipt)
    text += json.dumps(envelope_dict(projected))
    assert_no_leak(text, source, extra_plain=("support-bot", "helpdesk", "oncall-lead"))


def test_only_expected_64_hex_values_remain_in_a_keyed_projection():
    # Privacy oracle: no unkeyed digest of the request (in any domain) survives.
    source = v3_envelope(session_id=None, request_id=None, **APPROVAL_REQUEST)
    projected = keyed(source)
    text = projected.canonical_bytes().decode("ascii")
    import re

    found = set(re.findall(r"[0-9a-f]{64}", text))
    assert found == {source.event.engine.policy_sha256, projected.projection_digest, projected.auth.mac}


# --- Approver contract ------------------------------------------------------------------


def test_many_approvers_keep_count_and_32_keyed_references():
    engine = engine_with_approvers(40)
    source = v3_envelope(engine=engine, **APPROVAL_REQUEST)
    raw_ids = sorted([f"canary-approver-{i:02d}" for i in range(40)] + ["oncall-lead"])
    assert source.event.engine.approval.eligible_approvers == tuple(raw_ids[:32])
    approval = keyed(source).projection.engine.approval
    assert approval.eligible_approver_count == 41  # truncation shown by count > len(refs)
    assert len(approval.eligible_approver_refs) == 32
    assert approval.eligible_approver_refs == tuple(sorted(raw_approver_ref(i) for i in raw_ids[:32]))
    assert list(approval.eligible_approver_refs) == sorted(approval.eligible_approver_refs)


def test_maximum_policy_approver_count_is_accepted():
    source = v3_envelope(engine=engine_with_approvers(MAX_APPROVERS - 1), **APPROVAL_REQUEST)
    approval = keyed(source).projection.engine.approval
    assert approval.eligible_approver_count == MAX_APPROVERS == 100
    assert len(approval.eligible_approver_refs) == 32


@pytest.mark.parametrize("profile", ["keyed", "unlinked"])
def test_raw_approver_canaries_never_appear(profile):
    engine = engine_with_approvers(40)
    if profile == "keyed":
        source = v3_envelope(engine=engine, **APPROVAL_REQUEST)
        projected = keyed(source)
    else:
        source = omitted_source(engine=engine, **APPROVAL_REQUEST)
        projected = unlinked(source)
    text = said(projected, projected.projection.engine.approval) + json.dumps(envelope_dict(projected))
    assert "canary-approver" not in text and "oncall-lead" not in text
    for i in range(40):
        assert f"approver-{i:02d}" not in text


def test_unlinked_projection_keeps_only_the_approver_count():
    approval = unlinked(omitted_source(engine=engine_with_approvers(5), **APPROVAL_REQUEST)).projection.engine.approval
    assert approval.eligible_approver_refs is None and approval.binding_ref is None
    assert approval.eligible_approver_count == 6


def _approval(**changes):
    approval = keyed(v3_envelope(**APPROVAL_REQUEST)).projection.engine.approval
    return dataclasses.replace(approval, **changes)


@pytest.mark.parametrize(
    "changes, code",
    [
        (dict(eligible_approver_refs=("a" * 32, "a" * 32), eligible_approver_count=2), AuditErrorCode.INVALID_FIELD),
        (dict(eligible_approver_refs=("b" * 32, "a" * 32), eligible_approver_count=2), AuditErrorCode.INVALID_FIELD),
        (dict(eligible_approver_refs=tuple(f"{i:032x}" for i in range(33)), eligible_approver_count=33),
         AuditErrorCode.LIMIT_EXCEEDED),
        (dict(eligible_approver_refs=("a" * 64,)), AuditErrorCode.INVALID_FIELD),
        (dict(eligible_approver_refs=["a" * 32]), AuditErrorCode.INVALID_FIELD),
        (dict(eligible_approver_count=101), AuditErrorCode.INVALID_FIELD),
        (dict(eligible_approver_count=True), AuditErrorCode.INVALID_FIELD),
        (dict(eligible_approver_count=-1), AuditErrorCode.INVALID_FIELD),
        (dict(eligible_approver_count=type("I", (int,), {})(1)), AuditErrorCode.INVALID_FIELD),
        (dict(eligible_approver_count=2), AuditErrorCode.INCONSISTENT_EVENT),  # len != min(count, 32)
        (dict(eligible_approver_count=0), AuditErrorCode.INCONSISTENT_EVENT),
        (dict(binding_ref=None), AuditErrorCode.INCONSISTENT_EVENT),
        (dict(eligible_approver_refs=None), AuditErrorCode.INCONSISTENT_EVENT),
        (dict(binding_ref="c3" * 32), AuditErrorCode.INVALID_FIELD),
        (dict(ttl_seconds=5), AuditErrorCode.INVALID_FIELD),
    ],
    ids=["duplicate", "unsorted", "33-refs", "64-hex-ref", "list", "count-101", "count-bool", "count-negative",
         "count-int-subclass", "count-too-high-for-refs", "count-zero-with-ref", "binding-missing",
         "refs-missing", "binding-64-hex", "ttl"],
)
def test_approval_schema_layer_rejects_bad_contracts(changes, code):
    raises(code, _approval, **changes)


def _sealed_v3_with_approval(**approval_changes):
    """A key holder seals a v3 event whose approval block is valid for v3 but not for projection."""
    source = v3_envelope(**APPROVAL_REQUEST)
    event = source.event
    approval = dataclasses.replace(event.engine.approval, **approval_changes)
    engine = dataclasses.replace(event.engine, approval=approval)
    return AuditEnvelope.seal(dataclasses.replace(event, engine=engine), auth_key())


def test_projector_rejects_source_approver_count_above_the_m1_limit():
    sealed = _sealed_v3_with_approval(eligible_approver_count=MAX_APPROVERS + 1)
    raises(AuditErrorCode.LIMIT_EXCEEDED, keyed, sealed)


def test_projector_rejects_source_with_unexplained_approver_truncation():
    sealed = _sealed_v3_with_approval(eligible_approver_count=5)  # 1 retained id, count 5: not min(5, 32)
    raises(AuditErrorCode.INCONSISTENT_EVENT, keyed, sealed)


def test_duplicate_source_approvers_cannot_reach_the_projector():
    source = v3_envelope(**APPROVAL_REQUEST)
    data = json.loads(source.canonical_bytes())
    data["event"]["engine"]["approval"]["eligible_approvers"] = ["oncall-lead", "oncall-lead"]
    data["event"]["engine"]["approval"]["eligible_approver_count"] = 2
    with pytest.raises(AuditError):
        envelope_from_dict(data)


# --- Profiles and downgrade prevention ----------------------------------------------------


@pytest.mark.parametrize("keys", ["with-ref", "without-ref"])
def test_scoped_source_is_never_projected_unlinked(keys):
    source = v3_envelope()
    supplied = both_keys() if keys == "with-ref" else AuditKeys(auth=auth_key())
    error = raises(AuditErrorCode.INCONSISTENT_EVENT, project, source, supplied, profile=ProjectionProfile.UNLINKED)
    assert error.path == "projection.engine_ref_mode"


def test_tampered_redaction_mode_cannot_steer_the_profile():
    source = v3_envelope()
    object.__setattr__(source.event.audit, "redaction_mode", RedactionMode.NO_REF_KEY)  # after sealing
    with pytest.raises(AuditError) as info:
        project(source, AuditKeys(auth=auth_key()), profile=ProjectionProfile.UNLINKED)
    assert info.value.code in (AuditErrorCode.INVALID_ENVELOPE, AuditErrorCode.DIGEST_MISMATCH)


def test_keyed_profile_never_falls_back_to_unlinked():
    raises(AuditErrorCode.REF_KEY_REQUIRED, project, v3_envelope(), AuditKeys(auth=auth_key()))
    raises(AuditErrorCode.REF_KEY_REQUIRED, project, omitted_source(), both_keys())
    raises(AuditErrorCode.REF_KEY_REQUIRED, project, omitted_source(), AuditKeys(auth=auth_key()))


def test_keyed_is_the_default_profile_and_unlinked_requires_explicit_opt_in():
    projected = project(v3_envelope(), both_keys())
    assert projected.projection.projection.engine_ref_mode is ProjectionProfile.KEYED
    raises(AuditErrorCode.REF_KEY_REQUIRED, project, omitted_source(), AuditKeys(auth=auth_key()))


@pytest.mark.parametrize(
    "profile",
    ["unlinked", "keyed", None, 0, type("S", (str,), {})("unlinked"), RedactionMode.NO_REF_KEY],
    ids=["str-unlinked", "str-keyed", "none", "int", "str-subclass", "other-enum"],
)
def test_profile_must_be_the_exact_enum(profile):
    error = raises(AuditErrorCode.INVALID_FIELD, project, v3_envelope(), both_keys(), profile=profile)
    assert error.path == "profile"


def test_unlinked_projection_has_no_engine_references():
    source = omitted_source(**APPROVAL_REQUEST)
    projection = unlinked(source).projection
    assert projection.projection.engine_ref_mode is ProjectionProfile.UNLINKED
    engine = projection.engine
    assert (engine.request_ref, engine.decision_ref_keyed, engine.engine_ref_key_id) == (None, None, None)
    assert projection.audit.redaction_mode is RedactionMode.NO_REF_KEY and projection.audit.ref_key_id is None


# --- Keys and epochs ------------------------------------------------------------------------


def test_wrong_ref_key_epoch_is_refused():
    source = v3_envelope()
    raises(AuditErrorCode.REF_KEY_EPOCH_MISMATCH, project, source, AuditKeys(ref=OTHER_REF, auth=auth_key()))


@pytest.mark.parametrize("keys", [None, both_keys, "keys", {"ref": 1}], ids=["none", "class", "str", "dict"])
def test_keys_must_be_audit_keys(keys):
    raises(AuditErrorCode.KEY_INVALID, project, v3_envelope(), keys)


def test_k_auth_is_required():
    error = raises(AuditErrorCode.KEY_INVALID, project, v3_envelope(), AuditKeys(ref=ref_key()))
    assert error.path == "keys.auth"


def test_source_must_be_sealed_with_the_supplied_k_auth():
    source = v3_envelope(AuditKeys(ref=ref_key(), auth=OTHER_AUTH))
    raises(AuditErrorCode.AUTHENTICATION_FAILED, keyed, source)


def test_k_ref_and_k_auth_must_be_independent():
    with pytest.raises(AuditError) as info:
        AuditKeys(ref=AuditKey.from_bytes(KeyPurpose.REF, AUTH_MATERIAL), auth=auth_key())
    assert info.value.code is AuditErrorCode.KEYS_NOT_INDEPENDENT


# --- Tampered or wrong sources ----------------------------------------------------------------


def test_unsealed_source_is_refused():
    source = v3_envelope(AuditKeys(ref=ref_key()))
    raises(AuditErrorCode.UNAUTHENTICATED_REJECTED, keyed, source)


def test_forged_source_mac_is_refused():
    source = v3_envelope()
    forged = dataclasses.replace(source, auth=dataclasses.replace(source.auth, mac="0" * 64))
    raises(AuditErrorCode.AUTHENTICATION_FAILED, keyed, forged)


def test_source_digest_mismatch_is_refused():
    source = v3_envelope()
    raises(AuditErrorCode.DIGEST_MISMATCH, keyed, dataclasses.replace(source, event_digest="0" * 64))


def test_source_mutated_after_sealing_is_refused():
    source = v3_envelope()
    object.__setattr__(source.event.engine, "request_digest", "d4" * 32)
    raises(AuditErrorCode.DIGEST_MISMATCH, keyed, source)


def test_key_holder_sealing_a_malformed_v3_event_is_refused():
    source = v3_envelope()
    object.__setattr__(source.event.caller, "agent_ref", "support-bot")  # plaintext, bypasses the model
    sealed = AuditEnvelope.seal(source.event, auth_key())
    assert sealed.verify(RING) is AuthStatus.AUTHENTIC
    error = raises(AuditErrorCode.INVALID_ENVELOPE, keyed, sealed)
    assert "support-bot" not in str(error) + repr(error)


def test_v3_labels_outside_the_allowlist_are_refused():
    source = v3_envelope(labels=["reviewed"])
    object.__setattr__(source.event.caller, "readable_labels", ("team-payroll",))
    sealed = AuditEnvelope.seal(source.event, auth_key())
    with pytest.raises(AuditError) as info:
        keyed(sealed)
    assert info.value.code in (AuditErrorCode.INVALID_ENVELOPE, AuditErrorCode.INVALID_FIELD)


def test_v2_source_is_refused():
    request, record = evaluated()
    v2 = AuditEventBuilder(both_keys(), clock=lambda: FIXED_AUDIT_NOW, id_factory=counter_ids()).build_envelope(
        record, request)
    assert v2.event.to_dict()["schema_version"] == AUDIT_EVENT_SCHEMA
    raises(AuditErrorCode.UNSUPPORTED_SCHEMA, keyed, v2)


def test_non_envelopes_and_look_alikes_are_refused():
    source = v3_envelope()

    class Subclass(AuditEnvelope):
        pass

    subclass = Subclass(event=source.event, event_digest=source.event_digest, auth=source.auth)

    class LookAlike:
        event = source.event
        event_digest = source.event_digest
        auth = source.auth
        verify = staticmethod(source.verify)
        canonical_bytes = staticmethod(source.canonical_bytes)

    for bad in (None, {}, json.loads(source.canonical_bytes()), subclass, LookAlike(), keyed(source)):
        raises(AuditErrorCode.INVALID_ENVELOPE, project, bad, both_keys())


def test_invalid_requests_project_without_a_request_reference():
    # M1 rejected the request, so the v3 source has no request_digest (v3 rule for invalid_request).
    source = v3_envelope(resource="fs:/a/../b")
    assert source.event.caller.consistency is RequestConsistency.INVALID_REQUEST
    assert source.event.engine.request_digest is None
    engine = keyed(source).projection.engine
    assert engine.request_ref is None and engine.decision_ref_keyed is not None


def test_request_reference_presence_mirrors_the_v3_consistency_rule():
    event = keyed(v3_envelope()).projection
    assert event.caller.consistency is RequestConsistency.CONSISTENT
    engine = dataclasses.replace(event.engine, request_ref=None)
    raises(AuditErrorCode.INCONSISTENT_EVENT, dataclasses.replace, event, engine=engine)
    invalid = keyed(v3_envelope(resource="fs:/a/../b")).projection
    not_applicable = dataclasses.replace(invalid.caller, consistency=RequestConsistency.NOT_APPLICABLE)
    with_ref = dataclasses.replace(invalid.engine, request_ref="a" * 32)
    raises(AuditErrorCode.INCONSISTENT_EVENT, dataclasses.replace, invalid, caller=not_applicable, engine=with_ref)


# --- Schema layer: coupling rules ---------------------------------------------------------------


def _keyed_event():
    return keyed(v3_envelope(**APPROVAL_REQUEST)).projection


def _unlinked_event():
    return unlinked(omitted_source(**APPROVAL_REQUEST)).projection


def test_projection_mode_must_match_the_redaction_mode():
    event = _keyed_event()
    meta = dataclasses.replace(event.projection, engine_ref_mode=ProjectionProfile.UNLINKED)
    error = raises(AuditErrorCode.INCONSISTENT_EVENT, dataclasses.replace, event, projection=meta)
    assert error.path == "projection.engine_ref_mode"
    unlinked_event = _unlinked_event()
    meta = dataclasses.replace(unlinked_event.projection, engine_ref_mode=ProjectionProfile.KEYED)
    error = raises(AuditErrorCode.INCONSISTENT_EVENT, dataclasses.replace, unlinked_event, projection=meta)
    assert error.path == "projection.engine_ref_mode"


def test_projection_is_built_from_the_reparsed_source_bytes_not_the_in_memory_object():
    source = v3_envelope(labels=["reviewed"])
    # Same canonical bytes (list(tuple) == list(list)), different in-memory type.
    object.__setattr__(source.event.caller, "readable_labels", ["reviewed"])
    assert source.verify(RING) is AuthStatus.AUTHENTIC
    caller = keyed(source).projection.caller
    assert type(caller.readable_labels) is tuple and caller.readable_labels == ("reviewed",)
    assert caller is not source.event.caller
    assert caller == event_v3_from_dict(json.loads(source.canonical_bytes())["event"]).caller


@pytest.mark.parametrize("field", ["request_ref", "decision_ref_keyed", "engine_ref_key_id"])
def test_keyed_projection_requires_engine_references(field):
    event = _keyed_event()
    engine = dataclasses.replace(event.engine, **{field: None})
    raises(AuditErrorCode.INCONSISTENT_EVENT, dataclasses.replace, event, engine=engine)


@pytest.mark.parametrize("field", ["request_ref", "decision_ref_keyed", "engine_ref_key_id"])
def test_unlinked_projection_rejects_engine_references(field):
    event = _unlinked_event()
    engine = dataclasses.replace(event.engine, **{field: "a" * 32})
    raises(AuditErrorCode.INCONSISTENT_EVENT, dataclasses.replace, event, engine=engine)


def test_unlinked_projection_rejects_approver_references():
    event = _unlinked_event()
    approval = dataclasses.replace(event.engine.approval, eligible_approver_refs=("a" * 32,),
                                   binding_ref="b" * 32, eligible_approver_count=1)
    engine = dataclasses.replace(event.engine, approval=approval)
    raises(AuditErrorCode.INCONSISTENT_EVENT, dataclasses.replace, event, engine=engine)


def test_keyed_projection_rejects_missing_approver_references():
    event = _keyed_event()
    approval = dataclasses.replace(event.engine.approval, eligible_approver_refs=None, binding_ref=None)
    engine = dataclasses.replace(event.engine, approval=approval)
    raises(AuditErrorCode.INCONSISTENT_EVENT, dataclasses.replace, event, engine=engine)


def test_approval_block_exists_exactly_for_require_approval():
    event = _keyed_event()
    from rig_sentinel.policy.model import Decision

    raises(AuditErrorCode.INCONSISTENT_EVENT, dataclasses.replace, event.engine, decision=Decision.ALLOW)
    raises(AuditErrorCode.INCONSISTENT_EVENT, dataclasses.replace, event.engine, approval=None)


def test_request_reference_follows_request_consistency():
    event = keyed(v3_envelope()).projection
    caller = dataclasses.replace(event.caller, consistency=RequestConsistency.NOT_APPLICABLE,
                                 **{name: None for name in (
                                     "agent_ref", "assurance_claim", "tool_ref", "manifest_ref", "operation",
                                     "environment", "readable_labels", "label_refs", "resource",
                                     "session_ref", "request_ref")})
    raises(AuditErrorCode.INCONSISTENT_EVENT, dataclasses.replace, event, caller=caller)


def test_engine_rejects_enforced_true_and_raw_digest_shapes():
    engine = _keyed_event().engine
    raises(AuditErrorCode.INVALID_FIELD, dataclasses.replace, engine, enforced=True)
    for field in ("request_ref", "decision_ref_keyed", "engine_ref_key_id"):
        raises(AuditErrorCode.INVALID_FIELD, dataclasses.replace, engine, **{field: "a" * 64})
        raises(AuditErrorCode.INVALID_FIELD, dataclasses.replace, engine, **{field: "A" * 32})


@pytest.mark.parametrize(
    "changes",
    [dict(projector_version="genesis-b2-p3"), dict(source_schema=AUDIT_EVENT_SCHEMA),
     dict(projector_version=type("S", (str,), {})(PROJECTOR_VERSION))],
    ids=["version", "source-schema", "str-subclass"],
)
def test_projection_metadata_constants_are_exact(changes):
    raises(AuditErrorCode.UNSUPPORTED_SCHEMA, dataclasses.replace, _keyed_event().projection, **changes)


def test_sections_must_be_exact_types():
    event = _keyed_event()
    raises(AuditErrorCode.INVALID_FIELD, dataclasses.replace, event, engine=event.engine.to_dict())
    raises(AuditErrorCode.INVALID_FIELD, dataclasses.replace, event, caller=None)


# --- Parser: round trips, cross-schema confusion and nested metadata -----------------------


@pytest.mark.parametrize("profile", ["keyed", "unlinked"])
def test_round_trip_is_byte_identical_and_authentic(profile):
    projected = keyed(v3_envelope(**APPROVAL_REQUEST)) if profile == "keyed" else unlinked()
    raw = projected.canonical_bytes()
    assert raw == canonical_json(projected.to_dict()) and raw.isascii()
    rebuilt = projection_envelope_from_dict(json.loads(raw))
    assert type(rebuilt) is ProjectionEnvelope and rebuilt.canonical_bytes() == raw and rebuilt == projected
    assert rebuilt.verify(RING) is AuthStatus.AUTHENTIC
    assert verify_projection_envelope_dict(json.loads(raw), RING) is AuthStatus.AUTHENTIC
    event = projection_from_dict(json.loads(raw)["projection"])
    assert event == projected.projection


def test_projection_digest_and_mac_use_their_own_domains():
    projected = keyed()
    body = projected.projection.canonical_bytes()
    assert projected.projection_digest == hashlib.sha256(b"rig.audit-projection/v1" + NUL + body).hexdigest()
    key_id = auth_key().key_id
    expected = hmac.new(AUTH_MATERIAL, b"rig.audit-projection-mac/v1" + NUL + key_id.encode() + NUL + body,
                        hashlib.sha256).hexdigest()
    assert projected.auth.mac == expected and projected.auth.key_id == key_id
    v1_digest = hashlib.sha256(b"rig.audit-event/v2" + NUL + body).hexdigest()
    assert projected.projection_digest != v1_digest


def test_envelope_v1_and_v2_never_accept_each_other():
    projected = envelope_dict(keyed())
    source = json.loads(v3_envelope().canonical_bytes())
    raises(AuditErrorCode.UNKNOWN_FIELD, envelope_from_dict, projected)
    assert verify_envelope_dict(projected, RING) is AuthStatus.SCHEMA_INVALID
    raises(AuditErrorCode.UNKNOWN_FIELD, projection_envelope_from_dict, source)
    assert verify_projection_envelope_dict(source, RING) is AuthStatus.SCHEMA_INVALID


def test_relabelled_schemas_are_rejected_both_ways():
    projection = envelope_dict(keyed())["projection"]
    relabelled = dict(projection, schema_version=AUDIT_EVENT_SCHEMA_V3)
    raises(AuditErrorCode.UNSUPPORTED_SCHEMA, projection_from_dict, relabelled)
    with pytest.raises(AuditError):
        event_v3_from_dict(dict(projection, schema_version=AUDIT_EVENT_SCHEMA_V3))
    v3 = json.loads(v3_envelope().canonical_bytes())["event"]
    with pytest.raises(AuditError):
        projection_from_dict(dict(v3, schema_version=AUDIT_PROJECTION_SCHEMA))
    data = envelope_dict(keyed())
    data["envelope_schema"] = AUDIT_ENVELOPE_SCHEMA
    raises(AuditErrorCode.UNSUPPORTED_SCHEMA, projection_envelope_from_dict, data)


def _inject(path, key, value):
    data = envelope_dict(keyed(v3_envelope(**APPROVAL_REQUEST)))
    target = data
    for step in path:
        target = target[step]
    target[key] = value
    return data


@pytest.mark.parametrize(
    "path",
    [(), ("projection",), ("projection", "audit"), ("projection", "engine"),
     ("projection", "engine", "approval"), ("projection", "caller"), ("projection", "caller", "resource"),
     ("projection", "projection"), ("auth",)],
    ids=["envelope", "projection", "audit", "engine", "approval", "caller", "resource", "meta", "auth"],
)
@pytest.mark.parametrize("key", ["request_digest", "eligible_approvers", "event_digest", "source_ref", "metadata"])
def test_unknown_or_forbidden_nested_keys_are_rejected(path, key):
    data = _inject(path, key, "a1" * 32)
    raises(AuditErrorCode.UNKNOWN_FIELD, projection_envelope_from_dict, data)
    assert verify_projection_envelope_dict(data, RING) is AuthStatus.SCHEMA_INVALID


@pytest.mark.parametrize(
    "path, key, value, code",
    [
        (("projection", "engine"), "request_ref", {"nested": "a" * 32}, AuditErrorCode.INVALID_FIELD),
        (("projection", "engine"), "decision_ref_keyed", "a" * 64, AuditErrorCode.INVALID_FIELD),
        (("projection", "engine", "approval"), "eligible_approver_refs", ["a" * 32] * 2, AuditErrorCode.INVALID_FIELD),
        (("projection", "engine", "approval"), "eligible_approver_refs", "a" * 32, AuditErrorCode.INVALID_FIELD),
        (("projection", "engine", "approval"), "eligible_approver_count", True, AuditErrorCode.INVALID_FIELD),
        (("projection", "engine", "approval"), "eligible_approver_count", 1.0, AuditErrorCode.INVALID_FIELD),
        (("projection", "projection"), "engine_ref_mode", "KEYED", AuditErrorCode.INVALID_FIELD),
        (("projection", "projection"), "engine_ref_mode", None, AuditErrorCode.INVALID_FIELD),
        ((), "auth", None, AuditErrorCode.INVALID_FIELD),
        ((), "projection_digest", "A" * 64, AuditErrorCode.INVALID_FIELD),
    ],
    ids=["nested-object", "64-hex", "duplicate-refs", "refs-string", "count-bool", "count-float",
         "mode-case", "mode-null", "auth-null", "digest-uppercase"],
)
def test_malformed_nested_values_are_rejected(path, key, value, code):
    raises(code, projection_envelope_from_dict, _inject(path, key, value))


@pytest.mark.parametrize("missing", ["engine_ref_key_id", "request_ref", "approval"])
def test_missing_fields_are_rejected(missing):
    data = envelope_dict(keyed(v3_envelope(**APPROVAL_REQUEST)))
    del data["projection"]["engine"][missing]
    raises(AuditErrorCode.MISSING_FIELD, projection_envelope_from_dict, data)


@pytest.mark.parametrize("bad", [None, [], "x", 7, {"envelope_schema": AUDIT_ENVELOPE_SCHEMA_V2}])
def test_hostile_top_level_values_are_rejected(bad):
    with pytest.raises(AuditError):
        projection_envelope_from_dict(bad)
    assert verify_projection_envelope_dict(bad, RING) is AuthStatus.SCHEMA_INVALID


# --- Projected-envelope authenticity ---------------------------------------------------------


def test_projection_verification_needs_only_k_auth():
    projected = keyed()
    assert projected.verify(RING) is AuthStatus.AUTHENTIC
    assert projected.verify(keyring([OTHER_AUTH])) is AuthStatus.UNKNOWN_KEY


def test_forged_projection_mac_and_digest_are_detected():
    projected = keyed()
    forged = dataclasses.replace(projected, auth=dataclasses.replace(projected.auth, mac="0" * 64))
    assert forged.verify(RING) is AuthStatus.MAC_MISMATCH
    assert dataclasses.replace(projected, projection_digest="0" * 64).verify(RING) is AuthStatus.DIGEST_MISMATCH


def test_modified_serialized_projection_never_verifies():
    data = envelope_dict(keyed())
    data["projection"]["engine"]["decision_ref_keyed"] = "f" * 32
    assert verify_projection_envelope_dict(data, RING) is AuthStatus.DIGEST_MISMATCH


def test_key_holder_sealing_a_raw_digest_is_caught_by_the_closed_parser():
    source = v3_envelope()
    projected = keyed(source)
    object.__setattr__(projected.projection.engine, "request_ref", source.event.engine.request_digest)
    sealed = ProjectionEnvelope.seal(projected.projection, auth_key())
    assert sealed.verify(RING) is AuthStatus.AUTHENTIC  # the MAC alone cannot catch this
    assert verify_projection_envelope_dict(json.loads(sealed.canonical_bytes()), RING) is AuthStatus.SCHEMA_INVALID


def test_seal_requires_an_auth_key_and_an_exact_projection_event():
    event = keyed().projection
    for bad in (None, ref_key(), derive_engine_ref_key(ref_key())):
        with pytest.raises(AuditError):
            ProjectionEnvelope.seal(event, bad)
    raises(AuditErrorCode.INVALID_FIELD, ProjectionEnvelope.seal, event.to_dict(), auth_key())
    raises(AuditErrorCode.INVALID_FIELD, ProjectionEnvelope, projection=event, projection_digest="a" * 64, auth=None)


# --- Compatibility -------------------------------------------------------------------------------


def test_existing_p1_gate_and_memory_sink_refuse_projections():
    projected = keyed()
    assert check_persistable(projected, RING).code is PersistenceCode.NOT_AN_ENVELOPE
    receipt = MemorySink(verify_keys=RING).append(projected)
    assert not receipt.stored and receipt.error_code is AuditErrorCode.INVALID_ENVELOPE


def test_projection_leaves_the_source_envelope_unchanged():
    source = v3_envelope(**APPROVAL_REQUEST)
    before = source.canonical_bytes()
    keyed(source)
    assert source.canonical_bytes() == before and source.verify(RING) is AuthStatus.AUTHENTIC
    assert check_persistable(source, RING).ok  # P1 behaviour unchanged


def test_projection_classes_are_exported_types():
    for kind in (ProjectionEvent, ProjectionEngine, ProjectionApproval, ProjectionMeta, ProjectionEnvelope):
        assert dataclasses.is_dataclass(kind)
    assert type(keyed().projection.caller) is type(v3_envelope().event.caller)


def test_errors_are_value_free_and_raised_outside_handlers():
    source = v3_envelope(session_id=None, request_id=None, **APPROVAL_REQUEST)
    errors = []
    for call in (
        lambda: project(source, AuditKeys(ref=OTHER_REF, auth=auth_key())),
        lambda: project(source, both_keys(), profile=ProjectionProfile.UNLINKED),
        lambda: project(dataclasses.replace(source, event_digest="0" * 64), both_keys()),
    ):
        with pytest.raises(AuditError) as info:
            call()
        assert info.value.__context__ is None and info.value.__cause__ is None
        errors.append(f"{info.value!s} {info.value!r} {info.value.args!r}")
    assert_no_leak("\n".join(errors), source, extra_plain=("support-bot", "oncall-lead"))


def test_project_and_verify_perform_no_file_or_network_io(monkeypatch):
    source = v3_envelope(**APPROVAL_REQUEST)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("I/O attempted")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(io, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    projected = keyed(source)
    assert projected.verify(RING) is AuthStatus.AUTHENTIC
    assert verify_projection_envelope_dict(json.loads(projected.canonical_bytes()), RING) is AuthStatus.AUTHENTIC
    unlinked()


def test_v3_source_type_identity_is_preserved():
    assert type(v3_envelope().event) is AuditEventV3
