"""Genesis B2-P1 privacy hardening: audit event schema v3, identity modes, readable-label
allowlist and the persistence privacy gate.

Conventions: values named ``attacker_*`` or built from ``CANARY`` are attacker-controlled
inputs; values named ``expected_*`` are the pseudonymized outputs the tests require.
Synthetic values only.
"""

import builtins
import dataclasses
import hashlib
import hmac
import io
import json
import socket

import pytest
from audit_fixtures import (
    AUTH_MATERIAL,
    CANARY,
    FIXED_AUDIT_NOW,
    REF_MATERIAL,
    auth_key,
    both_keys,
    counter_ids,
    ref_key,
)
from policy_fixtures import baseline_engine, make_request

from rig_sentinel.audit import (
    APPROVED_READABLE_LABELS,
    AUDIT_EVENT_SCHEMA,
    AUDIT_EVENT_SCHEMA_V3,
    AuditEnvelope,
    AuditError,
    AuditErrorCode,
    AuditEvent,
    AuditEventBuilder,
    AuditEventV3,
    AuditKey,
    AuditKeys,
    AuthStatus,
    IdentityMode,
    KeyPurpose,
    MemorySink,
    PersistenceCode,
    RedactionMode,
    RequestConsistency,
    check_persistable,
    envelope_from_dict,
    event_from_dict,
    event_v3_from_dict,
    keyring,
    verify_envelope_dict,
)
from rig_sentinel.audit.chain import MAC_DOMAIN, REF_DOMAIN, pseudonym
from rig_sentinel.policy.canonical import canonical_json

NUL = bytes(1)
RING = keyring([auth_key()])


def v3_builder(keys=None, **kwargs):
    return AuditEventBuilder(
        both_keys() if keys is None else keys,
        clock=lambda: FIXED_AUDIT_NOW,
        id_factory=counter_ids(),
        event_schema=AUDIT_EVENT_SCHEMA_V3,
        **kwargs,
    )


def v2_builder(keys=None):
    return AuditEventBuilder(both_keys() if keys is None else keys, clock=lambda: FIXED_AUDIT_NOW,
                             id_factory=counter_ids())


def evaluated(**overrides):
    request = make_request(**overrides)
    return request, baseline_engine().evaluate(request)


def all_text(envelope, *extra):
    parts = [envelope.canonical_bytes().decode("ascii"), repr(envelope), str(envelope)]
    parts.extend(repr(item) for item in extra)
    return "\n".join(parts)


def expected_ref(namespace, value, material=REF_MATERIAL):
    message = f"{REF_DOMAIN}/{namespace}".encode() + NUL + value.encode()
    return hmac.new(material, message, hashlib.sha256).hexdigest()[:32]


# --- Schema selection and v2 compatibility ------------------------------------------


def test_v2_remains_the_default_and_is_unchanged():
    request, record = evaluated(labels=["reviewed"])
    default = AuditEventBuilder(both_keys(), clock=lambda: FIXED_AUDIT_NOW, id_factory=counter_ids())
    explicit = AuditEventBuilder(both_keys(), clock=lambda: FIXED_AUDIT_NOW, id_factory=counter_ids(),
                                 event_schema=AUDIT_EVENT_SCHEMA)
    a, b = default.build(record, request), explicit.build(record, request)
    assert type(a) is AuditEvent and a.to_dict() == b.to_dict()
    assert a.to_dict()["schema_version"] == "rig.audit-event/v2"
    assert a.caller.agent_id == "support-bot"  # v2 keeps its documented readable fields


def test_v3_is_selected_explicitly():
    request, record = evaluated()
    event = v3_builder().build(record, request)
    assert type(event) is AuditEventV3
    assert event.to_dict()["schema_version"] == AUDIT_EVENT_SCHEMA_V3 == "rig.audit-event/v3"


@pytest.mark.parametrize("bad", ["rig.audit-event/v4", "rig.audit-event/v1", "", "v3", None, 3,
                                 type("S", (str,), {})("rig.audit-event/v3")])
def test_unsupported_builder_schemas_are_rejected(bad):
    with pytest.raises(AuditError) as info:
        AuditEventBuilder(both_keys(), event_schema=bad)
    assert info.value.code is AuditErrorCode.UNSUPPORTED_SCHEMA


def test_v2_and_v3_parsers_never_accept_each_other():
    request, record = evaluated()
    v2 = json.loads(v2_builder().build_envelope(record, request).canonical_bytes())["event"]
    v3 = json.loads(v3_builder().build_envelope(record, request).canonical_bytes())["event"]
    with pytest.raises(AuditError) as info:
        event_from_dict(v3)
    assert info.value.code is AuditErrorCode.UNSUPPORTED_SCHEMA
    with pytest.raises(AuditError) as info:
        event_v3_from_dict(v2)
    assert info.value.code is AuditErrorCode.UNSUPPORTED_SCHEMA


@pytest.mark.parametrize("direction", ["v2 body labelled v3", "v3 body labelled v2"])
def test_schema_confusion_is_rejected(direction):
    request, record = evaluated()
    if direction == "v2 body labelled v3":
        data = json.loads(v2_builder().build_envelope(record, request).canonical_bytes())
        data["event"]["schema_version"] = AUDIT_EVENT_SCHEMA_V3
    else:
        data = json.loads(v3_builder().build_envelope(record, request).canonical_bytes())
        data["event"]["schema_version"] = AUDIT_EVENT_SCHEMA
    with pytest.raises(AuditError):
        envelope_from_dict(data)
    assert verify_envelope_dict(data, RING) is AuthStatus.SCHEMA_INVALID


def test_envelope_round_trip_dispatches_on_the_event_version():
    request, record = evaluated()
    for build in (v2_builder(), v3_builder()):
        envelope = build.build_envelope(record, request)
        rebuilt = envelope_from_dict(json.loads(envelope.canonical_bytes()))
        assert type(rebuilt.event) is type(envelope.event)
        assert rebuilt == envelope and rebuilt.verify(RING) is AuthStatus.AUTHENTIC


def test_v3_envelope_uses_the_unchanged_m2b_authentication_contract():
    request, record = evaluated()
    envelope = v3_builder().build_envelope(record, request)
    body = canonical_json(envelope.event.to_dict())
    expected_digest = hashlib.sha256(b"rig.audit-event/v2" + NUL + body).hexdigest()
    key_id = auth_key().key_id
    expected_mac = hmac.new(AUTH_MATERIAL, MAC_DOMAIN.encode() + NUL + key_id.encode() + NUL + body,
                            hashlib.sha256).hexdigest()
    assert envelope.event_digest == expected_digest
    assert envelope.auth.mac == expected_mac and envelope.auth.key_id == key_id


@pytest.mark.parametrize("field", ["agent_id", "tool_id", "labels", "raw_request", "prompt"])
def test_v3_caller_rejects_plaintext_and_unknown_fields(field):
    request, record = evaluated()
    data = json.loads(v3_builder().build_envelope(record, request).canonical_bytes())
    data["event"]["caller"][field] = "support-bot"
    with pytest.raises(AuditError) as info:
        envelope_from_dict(data)
    assert info.value.code is AuditErrorCode.UNKNOWN_FIELD


def test_memory_sink_v2_behavior_is_unchanged_and_accepts_v3():
    request, record = evaluated()
    sink = MemorySink(verify_keys=RING)
    v2 = v2_builder().build_envelope(record, request)
    v3 = AuditEventBuilder(both_keys(), event_schema=AUDIT_EVENT_SCHEMA_V3).build_envelope(record, request)
    assert sink.append(v2).stored and sink.append(v3).stored
    stored = sink.envelopes()
    assert type(stored[0].event) is AuditEvent and type(stored[1].event) is AuditEventV3
    assert stored[0] == v2 and stored[1] == v3


# --- identity_mode -------------------------------------------------------------------


def test_pseudonymized_mode_uses_keyed_references():
    attacker_labels = ["reviewed", "team-payroll"]
    request, record = evaluated(labels=attacker_labels)
    event = v3_builder().build(record, request)
    caller = event.caller
    assert caller.identity_mode is IdentityMode.PSEUDONYMIZED
    assert event.audit.redaction_mode is RedactionMode.SCOPED
    assert caller.agent_ref == expected_ref("agent", "support-bot")
    assert caller.tool_ref == expected_ref("tool", "mcp://helpdesk/tickets.get")
    assert caller.readable_labels == ("reviewed",)
    assert caller.label_refs == (expected_ref("label", "team-payroll"),)
    text = event.canonical_bytes().decode()
    for plaintext in ('"support-bot"', "mcp://helpdesk/tickets.get", "team-payroll"):
        assert plaintext not in text


def test_omitted_mode_without_ref_key_has_no_identity_material():
    request, record = evaluated(labels=["reviewed", "team-payroll"], session_id="s-1", request_id="r-1")
    event = v3_builder(AuditKeys(auth=auth_key())).build(record, request)
    caller = event.caller
    assert caller.identity_mode is IdentityMode.OMITTED
    assert event.audit.redaction_mode is RedactionMode.NO_REF_KEY and event.audit.ref_key_id is None
    assert caller.agent_ref is None and caller.tool_ref is None and caller.label_refs is None
    assert caller.readable_labels == ("reviewed",)  # approved vocabulary only
    assert caller.session_ref is None and caller.request_ref is None
    assert caller.resource.authority_ref is None and caller.resource.resource_ref is None
    text = event.canonical_bytes().decode()
    for plaintext in ("support-bot", "helpdesk", "team-payroll", '"s-1"', '"r-1"'):
        assert plaintext not in text


def test_non_consistent_requests_carry_no_identity_fields():
    request, record = evaluated(resource="fs:/a/../b")
    caller = v3_builder().build(record, request).caller
    assert caller.consistency is RequestConsistency.INVALID_REQUEST
    assert (caller.agent_ref, caller.tool_ref, caller.label_refs, caller.readable_labels) == (None,) * 4
    assert caller.identity_mode is IdentityMode.PSEUDONYMIZED  # follows key availability, not content


INVALID_COMBINATIONS = {
    "pseudonymized without ref key": dict(audit_mode=RedactionMode.NO_REF_KEY, identity=IdentityMode.PSEUDONYMIZED),
    "omitted with ref key": dict(audit_mode=RedactionMode.SCOPED, identity=IdentityMode.OMITTED),
    "omitted with agent ref": dict(caller={"identity_mode": IdentityMode.OMITTED, "agent_ref": "a" * 32}),
    "omitted with label refs": dict(caller={"identity_mode": IdentityMode.OMITTED, "label_refs": ()}),
    "pseudonymized missing agent ref": dict(caller={"agent_ref": None}),
    "pseudonymized missing tool ref": dict(caller={"tool_ref": None}),
    "pseudonymized missing label refs": dict(caller={"label_refs": None}),
    "plaintext in agent ref": dict(caller={"agent_ref": "support-bot"}),
    "uppercase hex ref": dict(caller={"tool_ref": "A" * 32}),
    "unsorted label refs": dict(caller={"label_refs": ("b" * 32, "a" * 32)}),
    "duplicate label refs": dict(caller={"label_refs": ("a" * 32, "a" * 32)}),
    "unapproved readable label": dict(caller={"readable_labels": ("team-payroll",)}),
    "too many label refs": dict(caller={"label_refs": tuple(f"{i:032x}" for i in range(33))}),
    "identity mode as string": dict(caller={"identity_mode": "pseudonymized"}),
}


@pytest.mark.parametrize("change", INVALID_COMBINATIONS.values(), ids=INVALID_COMBINATIONS.keys())
def test_invalid_identity_combinations_are_rejected(change):
    request, record = evaluated(labels=["reviewed"])
    event = v3_builder().build(record, request)
    with pytest.raises(AuditError):
        if "caller" in change:
            dataclasses.replace(event, caller=dataclasses.replace(event.caller, **change["caller"]))
        else:
            audit = dataclasses.replace(event.audit, redaction_mode=change["audit_mode"],
                                        ref_key_id=None if change["audit_mode"] is RedactionMode.NO_REF_KEY
                                        else ref_key().key_id)
            caller = dataclasses.replace(event.caller, identity_mode=change["identity"])
            dataclasses.replace(event, audit=audit, caller=caller)


# Each layer is tested on its own, with inputs that every other layer accepts, so that
# removing any single check is detected (see the P1 mutation report).

def _omitted_and_scoped_events():
    request, record = evaluated(labels=["reviewed", "team-payroll"])
    omitted = v3_builder(AuditKeys(auth=auth_key())).build(record, request)
    scoped = v3_builder().build(record, request)
    return omitted, scoped


def test_identity_mode_must_follow_the_redaction_mode():
    omitted, scoped = _omitted_and_scoped_events()
    # A fully valid omitted caller placed in a scoped (K_ref) event.
    with pytest.raises(AuditError) as info:
        dataclasses.replace(scoped, caller=omitted.caller)
    assert info.value.code is AuditErrorCode.INCONSISTENT_EVENT


def test_no_ref_key_event_rejects_keyed_resource_references():
    omitted, scoped = _omitted_and_scoped_events()
    assert scoped.caller.resource.resource_ref is not None
    caller = dataclasses.replace(omitted.caller, resource=scoped.caller.resource)  # valid caller on its own
    with pytest.raises(AuditError) as info:
        dataclasses.replace(omitted, caller=caller)
    assert info.value.code is AuditErrorCode.INCONSISTENT_EVENT


@pytest.mark.parametrize("field", ["agent_ref", "tool_ref", "session_ref", "request_ref"])
def test_omitted_caller_section_rejects_any_reference_on_its_own(field):
    omitted, _scoped = _omitted_and_scoped_events()
    with pytest.raises(AuditError) as info:
        dataclasses.replace(omitted.caller, **{field: "a" * 32})
    assert info.value.code is AuditErrorCode.INCONSISTENT_EVENT


def test_omitted_caller_section_rejects_label_refs_on_its_own():
    omitted, _scoped = _omitted_and_scoped_events()
    with pytest.raises(AuditError) as info:
        dataclasses.replace(omitted.caller, label_refs=("a" * 32,))
    assert info.value.code is AuditErrorCode.INCONSISTENT_EVENT


@pytest.mark.parametrize("consistency", [RequestConsistency.MISMATCH, RequestConsistency.INVALID_REQUEST,
                                         RequestConsistency.NOT_APPLICABLE])
def test_non_consistent_caller_section_rejects_claims_on_its_own(consistency):
    _omitted, scoped = _omitted_and_scoped_events()
    with pytest.raises(AuditError) as info:
        dataclasses.replace(scoped.caller, consistency=consistency)
    assert info.value.code is AuditErrorCode.INCONSISTENT_EVENT


def test_envelopes_accept_only_the_exact_event_types():
    _omitted, scoped = _omitted_and_scoped_events()

    class EventSubclass(AuditEventV3):
        pass

    lookalike = EventSubclass(audit=scoped.audit, engine=scoped.engine, caller=scoped.caller)
    for bad in (lookalike, scoped.to_dict(), None):
        with pytest.raises(AuditError):
            AuditEnvelope.seal(bad, auth_key())
    sealed = AuditEnvelope.seal(scoped, auth_key())
    with pytest.raises(AuditError):
        dataclasses.replace(sealed, event=lookalike)


# --- Cryptography --------------------------------------------------------------------

AGENT_VECTOR = "support-bot"


def test_reference_known_answer_vectors():
    assert pseudonym(ref_key(), "agent", AGENT_VECTOR) == expected_ref("agent", AGENT_VECTOR)
    assert pseudonym(ref_key(), "tool", "mcp://helpdesk/tickets.get") == expected_ref(
        "tool", "mcp://helpdesk/tickets.get")
    assert pseudonym(ref_key(), "label", "team-payroll") == expected_ref("label", "team-payroll")
    # Pinned value computed with raw hmac (key bytes 1..32), independently of rig_sentinel.
    assert expected_ref("agent", AGENT_VECTOR) == "05441c7d39a0fae95eada0100e7bc697"


def test_reference_domains_are_not_interchangeable():
    value = "reviewed"
    refs = {pseudonym(ref_key(), ns, value) for ns in ("agent", "tool", "label", "session", "request")}
    assert len(refs) == 5


def test_references_are_deterministic_within_an_epoch_and_change_across_epochs():
    request, record = evaluated()
    first = v3_builder().build(record, request).caller.agent_ref
    again = v3_builder().build(record, request).caller.agent_ref
    rotated_keys = AuditKeys(ref=AuditKey.from_bytes(KeyPurpose.REF, bytes(range(150, 182))), auth=auth_key())
    rotated = v3_builder(rotated_keys).build(record, request).caller.agent_ref
    assert first == again and first != rotated
    assert rotated == expected_ref("agent", "support-bot", bytes(range(150, 182)))


def test_references_are_never_unkeyed_hashes():
    request, record = evaluated()
    caller = v3_builder().build(record, request).caller
    for value, ref in (("support-bot", caller.agent_ref), ("mcp://helpdesk/tickets.get", caller.tool_ref)):
        unkeyed = {hashlib.sha256(value.encode()).hexdigest()[:32],
                   hashlib.sha256(f"{REF_DOMAIN}/agent".encode() + NUL + value.encode()).hexdigest()[:32],
                   hashlib.sha256(f"{REF_DOMAIN}/tool".encode() + NUL + value.encode()).hexdigest()[:32]}
        assert ref not in unkeyed


def test_wrong_ref_key_gives_different_references():
    request, record = evaluated()
    wrong = AuditKeys(ref=AuditKey.from_bytes(KeyPurpose.REF, bytes(range(200, 232))), auth=auth_key())
    assert v3_builder(wrong).build(record, request).caller.agent_ref != expected_ref("agent", "support-bot")


# --- Readable-label allowlist ----------------------------------------------------------


def test_approved_vocabulary_is_exactly_the_documented_policy_labels():
    assert APPROVED_READABLE_LABELS == frozenset({"reviewed", "untrusted_content_present"})


MISLEADING_LABELS = ["reviewed.", "reviewed-", "reviewedx", "xreviewed", "re-viewed", "untrusted_content",
                     "untrusted_content_present.v2", "reviewed" + "-" + "sk-short1"]


@pytest.mark.parametrize("attacker_label", MISLEADING_LABELS)
def test_misleading_labels_are_pseudonymized_not_readable(attacker_label):
    request, record = evaluated(labels=[attacker_label])
    caller = v3_builder().build(record, request).caller
    assert caller.readable_labels == ()
    assert caller.label_refs == (expected_ref("label", attacker_label),)
    assert attacker_label not in v3_builder().build_envelope(record, request).canonical_bytes().decode()


def test_operator_can_narrow_but_not_extend_the_allowlist():
    request, record = evaluated(labels=["reviewed", "untrusted_content_present"])
    caller = v3_builder(readable_labels=frozenset({"reviewed"})).build(record, request).caller
    assert caller.readable_labels == ("reviewed",)
    assert caller.label_refs == (expected_ref("label", "untrusted_content_present"),)
    with pytest.raises(AuditError) as info:
        v3_builder(readable_labels=frozenset({"reviewed", "team-payroll"}))
    assert info.value.code is AuditErrorCode.INVALID_FIELD
    assert "team-payroll" not in str(info.value)


class _HostileLabels:
    def __iter__(self):
        raise RuntimeError("hostile labels " + CANARY)


@pytest.mark.parametrize(
    "bad",
    [_HostileLabels(), ["reviewed"], {"reviewed": 1}, frozenset({1}),
     frozenset({type("S", (str,), {})("reviewed")}), "reviewed"],
    ids=["raising", "list", "dict", "non-str", "str-subclass", "string"],
)
def test_malformed_allowlist_containers_are_rejected_cleanly(bad):
    with pytest.raises(AuditError) as info:
        v3_builder(readable_labels=bad)
    assert info.value.code is AuditErrorCode.INVALID_FIELD
    assert info.value.__context__ is None and CANARY not in str(info.value)


def test_none_allowlist_means_the_approved_set_and_empty_set_means_no_readable_labels():
    request, record = evaluated(labels=["reviewed", "untrusted_content_present"])
    default = v3_builder(readable_labels=None).build(record, request).caller
    assert default.readable_labels == ("reviewed", "untrusted_content_present")
    assert default.label_refs == ()
    empty = v3_builder(readable_labels=frozenset()).build(record, request).caller
    assert empty.readable_labels == ()
    assert empty.label_refs == tuple(sorted(
        expected_ref("label", label) for label in ("reviewed", "untrusted_content_present")))


@pytest.mark.parametrize("attacker_label", ["r" + chr(0xE9) + "viewed", "review" + chr(0x0435) + "d",
                                            "reviewed" + chr(0x200B), "reviewed%20", "cmV2aWV3ZWQ="])
def test_unicode_and_encoded_labels_never_become_readable(attacker_label):
    request, record = evaluated(labels=[attacker_label])
    envelope = v3_builder().build_envelope(record, request)
    caller = envelope.event.caller
    raw = envelope.canonical_bytes().decode("ascii")
    assert attacker_label not in raw
    assert caller.readable_labels in (None, ())  # M1 rejects most; the rest are pseudonymized


# --- Canaries (attacker-controlled) -------------------------------------------------

ATTACKER_REQUESTS = {
    "agent canary": {"agent": CANARY},
    "email-like agent": {"agent": "john.doe-at-example.com"},
    "patient-style agent": {"agent": "patient-12345"},
    "short secret label": {"labels": ["pw-hunter2"]},
    "canary label": {"labels": [CANARY]},
    "internal mcp tool": {"tool": "mcp://internal-payroll/get-salary"},
    "canary tool server": {"tool": "mcp://" + CANARY + "/x"},
    "canary session": {"session_id": CANARY},
    "canary resource path": {"resource": "url:https://app.example.com/reset/" + CANARY},
}
SECRET_PARTS = {
    "agent canary": [CANARY], "email-like agent": ["john.doe"], "patient-style agent": ["patient-12345"],
    "short secret label": ["hunter2"], "canary label": [CANARY], "internal mcp tool": ["internal-payroll", "get-salary"],
    "canary tool server": [CANARY], "canary session": [CANARY], "canary resource path": [CANARY],
}


@pytest.mark.parametrize("name", ATTACKER_REQUESTS)
@pytest.mark.parametrize("mode", ["pseudonymized", "omitted"])
def test_privacy_canaries_never_appear_in_v3_outputs(name, mode):
    request, record = evaluated(**ATTACKER_REQUESTS[name])
    keys = both_keys() if mode == "pseudonymized" else AuditKeys(auth=auth_key())
    envelope = v3_builder(keys).build_envelope(record, request)
    sink = MemorySink(verify_keys=RING)
    receipt = sink.append(envelope)
    verdict = check_persistable(envelope, RING)
    text = all_text(envelope, receipt, sink, sink.canonical_records(), verdict)
    for secret in SECRET_PARTS[name]:
        assert secret not in text


# --- Persistence privacy gate ----------------------------------------------------------


def test_gate_accepts_authenticated_v3_events():
    request, record = evaluated(labels=["reviewed"])
    for keys in (both_keys(), AuditKeys(auth=auth_key())):
        verdict = check_persistable(v3_builder(keys).build_envelope(record, request), RING)
        assert verdict.ok and verdict.code is PersistenceCode.OK


def test_gate_rejects_v2_events():
    request, record = evaluated()
    verdict = check_persistable(v2_builder().build_envelope(record, request), RING)
    assert not verdict.ok and verdict.code is PersistenceCode.V2_EVENT_NOT_PERSISTABLE


def test_gate_requires_authentication_and_never_downgrades():
    request, record = evaluated()
    unauthenticated = v3_builder(AuditKeys(ref=ref_key())).build_envelope(record, request)
    assert check_persistable(unauthenticated, RING).code is PersistenceCode.NOT_AUTHENTICATED
    good = v3_builder().build_envelope(record, request)
    other_ring = keyring([AuditKey.from_bytes(KeyPurpose.AUTH, bytes(range(99, 131)))])
    assert check_persistable(good, other_ring).code is PersistenceCode.UNKNOWN_KEY
    forged = dataclasses.replace(good, auth=dataclasses.replace(good.auth, mac="0" * 64))
    assert check_persistable(forged, RING).code is PersistenceCode.AUTHENTICATION_FAILED
    broken = dataclasses.replace(good, event_digest="0" * 64)
    assert check_persistable(broken, RING).code is PersistenceCode.DIGEST_MISMATCH
    for bad_ring in (None, {}, {"x": "not a key"}, [auth_key()]):
        assert not check_persistable(good, bad_ring).ok


def test_gate_rejects_a_key_holder_sealing_a_malformed_v3_event():
    # Even a holder of K_auth cannot get plaintext past the gate by bypassing the model.
    request, record = evaluated()
    event = v3_builder().build(record, request)
    object.__setattr__(event.caller, "agent_ref", "attacker.plain.text")  # bypasses __post_init__
    sealed = AuditEnvelope.seal(event, auth_key())
    assert sealed.verify(RING) is AuthStatus.AUTHENTIC  # the MAC alone cannot catch this
    verdict = check_persistable(sealed, RING)
    assert verdict.code is PersistenceCode.SCHEMA_INVALID
    assert "attacker.plain.text" not in repr(verdict)


def test_gate_enforces_a_narrower_persistence_allowlist():
    request, record = evaluated(labels=["reviewed", "untrusted_content_present"])
    envelope = v3_builder().build_envelope(record, request)
    assert check_persistable(envelope, RING).ok
    verdict = check_persistable(envelope, RING, readable_labels=frozenset({"reviewed"}))
    assert verdict.code is PersistenceCode.LABEL_NOT_ALLOWED


@pytest.mark.parametrize(
    "bad",
    [frozenset({"team-payroll"}), {"reviewed", "team-payroll"}, frozenset({1}),
     frozenset({type("S", (str,), {})("reviewed")}), ["reviewed"], "reviewed", {"reviewed": 1}],
    ids=["unapproved", "extension", "non-str", "str-subclass", "list", "string", "dict"],
)
def test_gate_rejects_an_allowlist_that_is_not_a_subset_of_the_approved_set(bad):
    request, record = evaluated(labels=["reviewed"])
    envelope = v3_builder().build_envelope(record, request)
    verdict = check_persistable(envelope, RING, readable_labels=bad)
    assert not verdict.ok and verdict.code is PersistenceCode.CONFIGURATION_INVALID


def test_gate_never_modifies_the_envelope_and_never_raises_on_hostile_input():
    request, record = evaluated()
    envelope = v3_builder().build_envelope(record, request)
    before = envelope.canonical_bytes()
    check_persistable(envelope, RING)
    assert envelope.canonical_bytes() == before

    class Subclass(AuditEnvelope):
        pass

    hostile = object.__new__(Subclass)
    subclass = Subclass(event=envelope.event, event_digest=envelope.event_digest, auth=envelope.auth)
    assert subclass.verify(RING) is AuthStatus.AUTHENTIC

    class LookAlike:
        event = envelope.event
        event_digest = envelope.event_digest
        auth = envelope.auth
        verify = staticmethod(envelope.verify)
        canonical_bytes = staticmethod(envelope.canonical_bytes)
        to_dict = staticmethod(envelope.to_dict)

    for value in (None, {}, "envelope", hostile, subclass, LookAlike(), json.loads(before)):
        verdict = check_persistable(value, RING)
        assert not verdict.ok and verdict.code is PersistenceCode.NOT_AN_ENVELOPE


def test_gate_verdict_has_no_provenance_or_storage_claims():
    request, record = evaluated()
    verdict = check_persistable(v3_builder().build_envelope(record, request), RING)
    text = repr(verdict).lower()
    for word in ("stored", "persisted", "saved", "provenance", "executed", "enforced"):
        assert word not in text


# --- Hostile objects and limits --------------------------------------------------------


def test_hostile_request_mapping_yields_no_identity_fields():
    hostile = type("Leak" + CANARY, (Exception,), {})

    class Raising(dict):
        def __getitem__(self, key):
            raise hostile(CANARY)

        def __iter__(self):
            raise hostile(CANARY)

    request = Raising()
    record = baseline_engine().evaluate(request)
    envelope = v3_builder().build_envelope(record, request)
    assert envelope.event.caller.consistency is RequestConsistency.INVALID_REQUEST
    assert CANARY not in all_text(envelope)


def test_maximum_labels_fit_within_limits():
    labels = sorted(f"label-{i:02d}-" + "x" * 110 for i in range(32))
    request, record = evaluated(labels=labels)
    envelope = v3_builder().build_envelope(record, request)
    assert len(envelope.event.caller.label_refs) == 32
    assert check_persistable(envelope, RING).ok


def test_v3_build_seal_and_gate_perform_no_io(monkeypatch):
    request, record = evaluated(labels=["reviewed"])
    build = v3_builder()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("I/O attempted")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(io, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    envelope = build.build_envelope(record, request)
    assert check_persistable(envelope, RING).ok
