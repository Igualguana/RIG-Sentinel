"""Genesis B2-P2-C: projection persistence gate, fidelity verification, compatibility alias.

The gate decides whether a projection envelope may be handed to a future persistent sink;
it performs no I/O and its result does not authorize writing through any other sink.
Fidelity verification compares an authentic projection with an original M1 DecisionRecord;
it proves neither execution, enforcement nor ``PolicyEngine`` provenance.
Synthetic values only.
"""

import base64
import builtins
import dataclasses
import hashlib
import hmac
import io
import itertools
import json
import socket
from collections.abc import Mapping

import pytest
from audit_fixtures import FIXED_AUDIT_NOW, REF_MATERIAL, auth_key, both_keys, ref_key
from policy_fixtures import POLICY_HEADER, RULE_BLOCKS, fixed_clock, make_request

from rig_sentinel.audit import (
    AUDIT_EVENT_SCHEMA_V3,
    AuditEnvelope,
    AuditEventBuilder,
    AuditKey,
    AuditKeys,
    FidelityResult,
    KeyPurpose,
    PersistenceCode,
    ProjectionEnvelope,
    ProjectionEpoch,
    ProjectionGateCode,
    ProjectionGateResult,
    ProjectionProfile,
    ValidatedProjection,
    check_persistable,
    check_projection_persistable,
    check_v3_projection_source,
    compute_projection_digest,
    compute_projection_mac,
    keyring,
    project,
    verify_projection_fidelity,
)
from rig_sentinel.audit.events import AuthTag
from rig_sentinel.audit.projection import _persisted_privacy_violation
from rig_sentinel.policy import PolicyEngine, load_policy_text
from rig_sentinel.policy.decision import DecisionRecord, make_record

NUL = bytes(1)
RING = keyring([auth_key()])
OTHER_REF = AuditKey.from_bytes(KeyPurpose.REF, bytes(range(70, 102)))
OTHER_AUTH = AuditKey.from_bytes(KeyPurpose.AUTH, bytes(range(110, 142)))
CANARY = "zq-" + "canary-" + "9b2c"
APPROVAL_REQUEST = dict(tool="mcp://helpdesk/tickets.update", operation="database_write",
                        resource="db:helpdesk/tickets")


# --- helpers ------------------------------------------------------------------------------


def engine_for(approvers=0, policy=True):
    if not policy:
        return PolicyEngine(None, clock=fixed_clock)
    blocks = "".join(f'\n[[approvers]]\nid = "canary-approver-{i:02d}"\nscopes = ["*"]\n' for i in range(approvers))
    return PolicyEngine(load_policy_text(POLICY_HEADER + blocks + "\n" + "\n".join(RULE_BLOCKS)), clock=fixed_clock)


def evaluate(engine=None, **overrides):
    request = make_request(**overrides)
    return request, (engine or engine_for()).evaluate(request)


def seal_v3(record, request, keys=None):
    ids = itertools.count(1)
    builder = AuditEventBuilder(both_keys() if keys is None else keys, clock=lambda: FIXED_AUDIT_NOW,
                                id_factory=lambda: f"{next(ids):032x}", event_schema=AUDIT_EVENT_SCHEMA_V3)
    return builder.build_envelope(record, request)


def keyed_case(engine=None, **overrides):
    request, record = evaluate(engine, **overrides)
    return project(seal_v3(record, request), both_keys()), record


def unlinked_case(engine=None, **overrides):
    request, record = evaluate(engine, **overrides)
    keys = AuditKeys(auth=auth_key())
    return project(seal_v3(record, request, keys), keys, profile=ProjectionProfile.UNLINKED), record


def reissue(record, **changes):
    """A self-consistent record with changed fields (decision_digest recomputed)."""
    fields = {f.name: getattr(record, f.name) for f in dataclasses.fields(DecisionRecord)
              if f.init and f.name != "decision_digest"}
    fields.update(changes)
    return make_record(**fields)


def reseal(envelope, **engine_changes):
    """A K_auth holder re-seals a projection with changed engine fields (model-valid values)."""
    event = envelope.projection
    engine = dataclasses.replace(event.engine, **engine_changes)
    return ProjectionEnvelope.seal(dataclasses.replace(event, engine=engine), auth_key())


def raw_approver_ref(approver_id):
    return hmac.new(REF_MATERIAL, b"rig.audit-ref/v1/approver" + NUL + approver_id.encode(),
                    hashlib.sha256).hexdigest()[:32]


def gate(envelope, keys=RING, **kwargs):
    return check_projection_persistable(envelope, keys, **kwargs)


# --- Gate: acceptance -----------------------------------------------------------------------


@pytest.mark.parametrize("profile", ["keyed", "unlinked"])
def test_gate_accepts_authentic_projections_and_issues_a_byte_stable_representation(profile):
    envelope, _record = keyed_case(**APPROVAL_REQUEST) if profile == "keyed" else unlinked_case(**APPROVAL_REQUEST)
    result = gate(envelope)
    assert type(result) is ProjectionGateResult
    assert result.ok and result.code is ProjectionGateCode.OK
    validated = result.validated
    assert type(validated) is ValidatedProjection
    assert type(validated.canonical) is bytes and validated.canonical == envelope.canonical_bytes()
    assert validated.projection_digest == envelope.projection_digest
    assert validated.auth_key_id == auth_key().key_id
    assert validated.event_id == envelope.projection.audit.event_id
    assert validated.engine_ref_mode is envelope.projection.projection.engine_ref_mode
    assert validated.ref_key_id == envelope.projection.audit.ref_key_id
    assert validated.engine_ref_key_id == envelope.projection.engine.engine_ref_key_id
    assert compute_projection_digest(json.loads(validated.canonical)["projection"]) == validated.projection_digest


def test_gate_results_are_immutable_and_cannot_be_forged():
    result = gate(keyed_case()[0])
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.ok = False
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.validated.canonical = b"x"
    with pytest.raises(Exception):  # noqa: B017 - only the gate may issue a validated projection
        ValidatedProjection(canonical=b"{}", projection_digest="a" * 64, auth_key_id="b" * 32, event_id="c" * 32,
                            engine_ref_mode=ProjectionProfile.KEYED, ref_key_id="d" * 32, engine_ref_key_id="e" * 32)
    with pytest.raises(Exception):  # noqa: B017
        ProjectionGateResult(ok=True, code=ProjectionGateCode.SCHEMA_INVALID, validated=None)
    with pytest.raises(Exception):  # noqa: B017
        ProjectionGateResult(ok=False, code=ProjectionGateCode.OK, validated=None)


def test_gate_result_repr_has_no_content_or_storage_claims():
    envelope, _ = keyed_case(**APPROVAL_REQUEST)
    text = repr(gate(envelope)).lower()
    assert envelope.projection.engine.decision_ref_keyed not in text
    for word in ("stored", "persisted", "saved", "written", "provenance", "executed", "enforced"):
        assert word not in text


# --- Gate: rejection --------------------------------------------------------------------------


def test_gate_rejects_v1_envelopes_by_event_version():
    request, record = evaluate()
    v3 = seal_v3(record, request)
    v2 = AuditEventBuilder(both_keys(), clock=lambda: FIXED_AUDIT_NOW,
                           id_factory=lambda: "a" * 32).build_envelope(record, request)
    assert gate(v3).code is ProjectionGateCode.V3_EVENT_NOT_PERSISTABLE
    assert gate(v2).code is ProjectionGateCode.V2_EVENT_NOT_PERSISTABLE
    assert not gate(v3).ok and gate(v3).validated is None


class _MappingLookAlike(Mapping):
    def __init__(self, data):
        self._data = data

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)


def test_gate_rejects_raw_dicts_mappings_and_look_alikes():
    envelope = keyed_case()[0]
    data = json.loads(envelope.canonical_bytes())

    class Subclass(ProjectionEnvelope):
        pass

    subclass = Subclass(projection=envelope.projection, projection_digest=envelope.projection_digest,
                        auth=envelope.auth)

    class LookAlike:
        projection = envelope.projection
        projection_digest = envelope.projection_digest
        auth = envelope.auth
        canonical_bytes = staticmethod(envelope.canonical_bytes)
        verify = staticmethod(envelope.verify)

    for bad in (data, _MappingLookAlike(data), subclass, LookAlike(), None, "envelope", envelope.canonical_bytes()):
        result = gate(bad)
        assert result.code is ProjectionGateCode.NOT_A_PROJECTION and result.validated is None


@pytest.mark.parametrize(
    "keys",
    [None, [auth_key()], _MappingLookAlike(RING), type("Ring", (dict,), {})(RING), {"x" * 32: auth_key()},
     {auth_key().key_id: ref_key()}, {auth_key().key_id: "key"}, {1: auth_key()}],
    ids=["none", "list", "mapping", "dict-subclass", "wrong-id", "ref-key", "str-value", "int-id"],
)
def test_gate_rejects_invalid_keyrings(keys):
    assert gate(keyed_case()[0], keys).code is ProjectionGateCode.KEYRING_INVALID


def test_gate_requires_the_correct_k_auth():
    envelope = keyed_case()[0]
    assert gate(envelope, {}).code is ProjectionGateCode.UNKNOWN_KEY
    assert gate(envelope, keyring([OTHER_AUTH])).code is ProjectionGateCode.UNKNOWN_KEY
    forged = dataclasses.replace(envelope, auth=AuthTag(envelope.auth.algorithm, envelope.auth.key_id, "0" * 64))
    assert gate(forged).code is ProjectionGateCode.AUTHENTICATION_FAILED
    assert gate(dataclasses.replace(envelope, projection_digest="0" * 64)).code is ProjectionGateCode.DIGEST_MISMATCH


def test_gate_rejects_content_changed_after_sealing():
    envelope = keyed_case()[0]
    object.__setattr__(envelope.projection.engine, "decision_ref_keyed", "f" * 32)
    assert gate(envelope).code is ProjectionGateCode.DIGEST_MISMATCH


def test_gate_rejects_a_key_holder_sealing_a_raw_digest():
    request, record = evaluate()
    envelope = project(seal_v3(record, request), both_keys())
    object.__setattr__(envelope.projection.engine, "request_ref", record.request_digest)  # bypasses the model
    sealed = ProjectionEnvelope.seal(envelope.projection, auth_key())
    assert sealed.verify(RING).value == "authentic"  # the MAC alone cannot catch this
    assert gate(sealed).code is ProjectionGateCode.SCHEMA_INVALID


class _Hostile:
    """Raises its exception wherever the serializers touch it (``.value`` or ``.to_dict()``)."""

    def __init__(self, exc):
        self._exc = exc

    @property
    def value(self):
        raise self._exc

    def to_dict(self):
        raise self._exc


def test_gate_contains_hostile_objects_without_echoing_values():
    envelope = keyed_case()[0]
    object.__setattr__(envelope.projection.engine, "decision", _Hostile(RuntimeError("hostile " + CANARY)))
    result = gate(envelope)
    assert result.code is ProjectionGateCode.SCHEMA_INVALID and CANARY not in repr(result)


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
def test_gate_lets_base_exceptions_propagate(kind):
    envelope = keyed_case()[0]
    raised = kind("hostile")
    object.__setattr__(envelope.projection.engine, "decision", _Hostile(raised))
    with pytest.raises(kind) as info:
        gate(envelope)
    assert info.value is raised


def test_gate_never_modifies_the_envelope():
    envelope = keyed_case(**APPROVAL_REQUEST)[0]
    before = envelope.canonical_bytes()
    gate(envelope)
    gate(envelope, expected_epoch=ProjectionEpoch.keyed(OTHER_REF))
    assert envelope.canonical_bytes() == before and envelope.verify(RING).value == "authentic"


# --- Gate: profile, epoch and label configuration ---------------------------------------------


def test_gate_enforces_the_expected_key_epoch():
    keyed = keyed_case()[0]
    unlinked = unlinked_case()[0]
    assert gate(keyed, expected_epoch=ProjectionEpoch.keyed(ref_key())).ok
    assert gate(keyed, expected_epoch=ProjectionEpoch.keyed(OTHER_REF)).code is ProjectionGateCode.EPOCH_MISMATCH
    assert gate(keyed, expected_epoch=ProjectionEpoch.unlinked()).code is ProjectionGateCode.EPOCH_MISMATCH
    assert gate(unlinked, expected_epoch=ProjectionEpoch.unlinked()).ok
    assert gate(unlinked, expected_epoch=ProjectionEpoch.keyed(ref_key())).code is ProjectionGateCode.EPOCH_MISMATCH


def test_projection_epoch_values_are_derived_and_validated():
    epoch = ProjectionEpoch.keyed(ref_key())
    assert epoch.engine_ref_mode is ProjectionProfile.KEYED
    assert epoch.ref_key_id == ref_key().key_id
    assert epoch.engine_ref_key_id == "fe233c8b2a12f4470ca82e02dac62d17"  # P2-A known-answer vector
    unlinked = ProjectionEpoch.unlinked()
    assert (unlinked.engine_ref_mode, unlinked.ref_key_id, unlinked.engine_ref_key_id) == (
        ProjectionProfile.UNLINKED, None, None)
    for bad in (dict(engine_ref_mode=ProjectionProfile.KEYED, ref_key_id=None, engine_ref_key_id=None),
                dict(engine_ref_mode=ProjectionProfile.UNLINKED, ref_key_id="a" * 32, engine_ref_key_id=None),
                dict(engine_ref_mode="keyed", ref_key_id="a" * 32, engine_ref_key_id="b" * 32),
                dict(engine_ref_mode=ProjectionProfile.KEYED, ref_key_id="A" * 32, engine_ref_key_id="b" * 32)):
        with pytest.raises(Exception):  # noqa: B017
            ProjectionEpoch(**bad)
    with pytest.raises(Exception):  # noqa: B017
        ProjectionEpoch.keyed(auth_key())


@pytest.mark.parametrize("epoch", ["keyed", {"ref_key_id": "a" * 32}, 1], ids=["str", "dict", "int"])
def test_gate_rejects_invalid_epoch_configuration(epoch):
    assert gate(keyed_case()[0], expected_epoch=epoch).code is ProjectionGateCode.CONFIGURATION_INVALID


def test_gate_enforces_a_narrower_label_allowlist():
    envelope = keyed_case(labels=["reviewed", "untrusted_content_present"])[0]
    assert gate(envelope).ok
    assert gate(envelope, readable_labels=frozenset({"reviewed"})).code is ProjectionGateCode.LABEL_NOT_ALLOWED
    for bad in (frozenset({"team-payroll"}), ["reviewed"], "reviewed", frozenset({1})):
        assert gate(envelope, readable_labels=bad).code is ProjectionGateCode.CONFIGURATION_INVALID


# --- Gate: deep privacy scan (layer tested on its own) ---------------------------------------


def _valid_tree():
    return json.loads(keyed_case(**APPROVAL_REQUEST)[0].canonical_bytes())


def test_privacy_scan_accepts_the_three_permitted_64_hex_positions():
    assert _persisted_privacy_violation(_valid_tree()) is None


@pytest.mark.parametrize("key", ["request_digest", "decision_ref", "decision_digest", "request_binding_sha256",
                                 "eligible_approvers", "event_digest", "source_ref", "agent_id", "tool_id",
                                 "manifest_sha256", "labels", "redacted_fields"])
@pytest.mark.parametrize("where", [(), ("projection",), ("projection", "engine"), ("projection", "engine", "approval"),
                                   ("projection", "caller", "resource"), ("auth",)],
                         ids=["top", "projection", "engine", "approval", "resource", "auth"])
def test_privacy_scan_rejects_forbidden_keys_at_any_depth(key, where):
    tree = _valid_tree()
    target = tree
    for step in where:
        target = target[step]
    target[key] = None
    assert _persisted_privacy_violation(tree) is not None


def test_privacy_scan_rejects_forbidden_keys_inside_lists_and_unknown_objects():
    tree = _valid_tree()
    tree["projection"]["engine"]["deciding_rule_ids"] = [{"nested": [{"request_digest": "x"}]}]
    assert _persisted_privacy_violation(tree) is not None


@pytest.mark.parametrize("path", [("projection", "engine", "request_ref"), ("projection", "engine", "decision_ref_keyed"),
                                  ("projection", "caller", "agent_ref"), ("projection", "audit", "event_id"),
                                  ("projection", "engine", "approval", "binding_ref")])
@pytest.mark.parametrize("value", ["a1" * 32, "A1" * 32], ids=["lower", "upper"])
def test_privacy_scan_rejects_64_hex_outside_the_permitted_positions(path, value):
    tree = _valid_tree()
    target = tree
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = value
    assert _persisted_privacy_violation(tree) is not None


@pytest.mark.parametrize("field", ["deciding_rule_ids", "matched_rule_ids", "policy_id"])
def test_gate_refuses_a_64_hex_value_hidden_in_a_readable_identifier(field):
    # Identifier fields accept any identifier, so the closed schema alone would let a 64-hex value
    # (for example a smuggled unkeyed digest) through. The deep scan refuses it.
    envelope, _record = keyed_case()
    hidden = "a1" * 32
    value = (hidden,) if field != "policy_id" else hidden
    changes = {field: value}
    if field != "policy_id":
        changes[field.replace("_ids", "_count")] = 1
    forged = reseal(envelope, **changes)
    assert forged.verify(RING).value == "authentic"
    assert gate(forged).code is ProjectionGateCode.FORBIDDEN_FIELD


def test_privacy_scan_rejects_64_hex_inside_approver_lists():
    tree = _valid_tree()
    tree["projection"]["engine"]["approval"]["eligible_approver_refs"] = ["a1" * 32]
    assert _persisted_privacy_violation(tree) is not None


# --- Gate: deep canaries --------------------------------------------------------------------


def _forms(value):
    out = {value, value.upper(), value[:32], value[32:]}
    out.add(base64.b64encode(bytes.fromhex(value)).decode())
    return out


@pytest.mark.parametrize("profile", ["keyed", "unlinked"])
def test_validated_bytes_contain_no_raw_identifier_digest_or_source_authenticator(profile):
    engine = engine_for(40)
    request = make_request(tool="mcp://helpdesk/tickets.update", operation="database_write",
                           resource="db:helpdesk/tickets", labels=["reviewed", "canary-label-x"],
                           manifest_sha256="5eed" + "c0de" * 15, session_id=None, request_id=None)
    record = engine.evaluate(request)
    assert record.approval is not None  # REQUIRE_APPROVAL: binding and 41 approver ids in play
    keys = both_keys() if profile == "keyed" else AuditKeys(auth=auth_key())
    source = seal_v3(record, request, keys)
    chosen = ProjectionProfile.KEYED if profile == "keyed" else ProjectionProfile.UNLINKED
    result = gate(project(source, keys, profile=chosen))
    assert result.ok
    text = result.validated.canonical.decode("ascii") + repr(result)
    for plain in ("support-bot", "canary-label-x", "canary-approver", "oncall-lead", "helpdesk"):
        assert plain not in text
    secrets_ = [record.request_digest, record.decision_digest, record.approval.request_binding_sha256,
                source.event_digest, source.auth.mac, "5eed" + "c0de" * 15]
    for secret in secrets_:
        for form in _forms(secret):
            assert form not in text


# --- Fidelity ----------------------------------------------------------------------------------


def test_fidelity_result_has_exactly_three_values():
    assert [member.value for member in FidelityResult] == ["MATCH", "MISMATCH", "NOT_VERIFIABLE"]


@pytest.mark.parametrize(
    "case",
    ["allow", "deny", "approval-1", "approval-41", "approval-100", "invalid-request", "not-applicable"],
)
def test_fidelity_match_for_the_original_record(case):
    if case == "allow":
        envelope, record = keyed_case()
    elif case == "deny":
        envelope, record = keyed_case(agent="other-bot")
    elif case.startswith("approval"):
        envelope, record = keyed_case(engine_for(int(case.split("-")[1]) - 1), **APPROVAL_REQUEST)
    elif case == "invalid-request":
        envelope, record = keyed_case(resource="fs:/a/../b")
    else:
        envelope, record = keyed_case(engine_for(policy=False))
    assert verify_projection_fidelity(envelope, record, both_keys()) is FidelityResult.MATCH


def test_fidelity_uses_the_v3_approver_selection_not_hmac_sorted_selection():
    envelope, record = keyed_case(engine_for(99), **APPROVAL_REQUEST)
    raw = sorted(record.approval.eligible_approvers)
    assert len(raw) == 100
    correct = tuple(sorted(raw_approver_ref(i) for i in raw[:min(len(raw), 32)]))
    wrong = tuple(sorted(raw_approver_ref(i) for i in raw)[:32])
    assert envelope.projection.engine.approval.eligible_approver_refs == correct != wrong
    assert verify_projection_fidelity(envelope, record, both_keys()) is FidelityResult.MATCH
    forged = reseal(envelope, approval=dataclasses.replace(envelope.projection.engine.approval,
                                                           eligible_approver_refs=wrong))
    assert verify_projection_fidelity(forged, record, both_keys()) is FidelityResult.MISMATCH


def test_fidelity_mismatch_for_a_different_record():
    envelope, record = keyed_case()
    _other_request, other = evaluate(agent="other-bot")
    assert verify_projection_fidelity(envelope, other, both_keys()) is FidelityResult.MISMATCH
    later = reissue(record, evaluated_at="2026-11-09T15:04:06.000000Z")
    assert verify_projection_fidelity(envelope, later, both_keys()) is FidelityResult.MISMATCH


@pytest.mark.parametrize(
    "changes",
    [dict(policy_version="2026.11.10-1"), dict(protected=False), dict(matched_rule_ids=("read-tickets", "zz-extra")),
     dict(error_type="ValueError")],
    ids=["policy-version", "protected", "matched-rules", "error-type"],
)
def test_fidelity_mismatch_for_any_changed_engine_field(changes):
    envelope, record = keyed_case()
    assert verify_projection_fidelity(envelope, reissue(record, **changes), both_keys()) is FidelityResult.MISMATCH


def test_fidelity_mismatch_for_changed_approval_evidence():
    envelope, record = keyed_case(engine_for(5), **APPROVAL_REQUEST)
    approval = record.approval
    fewer = dataclasses.replace(approval, eligible_approvers=approval.eligible_approvers[1:])
    assert verify_projection_fidelity(envelope, reissue(record, approval=fewer), both_keys()) is FidelityResult.MISMATCH
    rebound = dataclasses.replace(approval, request_binding_sha256="c3" * 32)
    assert verify_projection_fidelity(envelope, reissue(record, approval=rebound), both_keys()) is FidelityResult.MISMATCH


@pytest.mark.parametrize(
    "field, value",
    [("decision_ref_keyed", "f" * 32), ("request_ref", "e" * 32), ("engine_ref_key_id", "d" * 32),
     ("policy_version", "2026.11.10-1")],
)
def test_fidelity_mismatch_for_a_key_holder_forged_projection(field, value):
    envelope, record = keyed_case()
    forged = reseal(envelope, **{field: value})
    assert forged.verify(RING).value == "authentic"
    assert verify_projection_fidelity(forged, record, both_keys()) is FidelityResult.MISMATCH


def test_fidelity_mismatch_when_only_the_approval_binding_reference_is_forged():
    envelope, record = keyed_case(engine_for(5), **APPROVAL_REQUEST)
    approval = dataclasses.replace(envelope.projection.engine.approval, binding_ref="b" * 32)
    forged = reseal(envelope, approval=approval)
    assert forged.verify(RING).value == "authentic"
    assert verify_projection_fidelity(forged, record, both_keys()) is FidelityResult.MISMATCH


def test_fidelity_refuses_unlinked_projections_even_if_they_claim_an_epoch(monkeypatch):
    # Layer isolation: with model validation disabled (test-local), an unlinked projection that
    # carries a ref_key_id must still be NOT_VERIFIABLE because of the explicit unlinked refusal.
    from rig_sentinel.audit import ProjectionEvent

    envelope, record = unlinked_case(**APPROVAL_REQUEST)
    monkeypatch.setattr(ProjectionEvent, "__post_init__", lambda self: None)
    object.__setattr__(envelope.projection.audit, "ref_key_id", ref_key().key_id)
    claimed = ProjectionEnvelope.seal(envelope.projection, auth_key())
    assert verify_projection_fidelity(claimed, record, both_keys()) is FidelityResult.NOT_VERIFIABLE


def test_fidelity_mismatch_for_forged_approver_count():
    envelope, record = keyed_case(engine_for(40), **APPROVAL_REQUEST)
    approval = dataclasses.replace(envelope.projection.engine.approval, eligible_approver_count=40)
    assert verify_projection_fidelity(reseal(envelope, approval=approval), record, both_keys()) is FidelityResult.MISMATCH


def test_fidelity_not_verifiable_for_unlinked_projections():
    envelope, record = unlinked_case(**APPROVAL_REQUEST)
    assert verify_projection_fidelity(envelope, record, both_keys()) is FidelityResult.NOT_VERIFIABLE
    assert verify_projection_fidelity(envelope, record, AuditKeys(auth=auth_key())) is FidelityResult.NOT_VERIFIABLE


@pytest.mark.parametrize(
    "keys",
    [AuditKeys(auth=auth_key()), AuditKeys(ref=OTHER_REF, auth=auth_key()), AuditKeys(ref=ref_key()),
     AuditKeys(ref=ref_key(), auth=OTHER_AUTH), None, {"ref": ref_key()}],
    ids=["missing-k-ref", "wrong-epoch", "missing-k-auth", "wrong-k-auth", "none", "dict"],
)
def test_fidelity_not_verifiable_without_the_right_keys(keys):
    envelope, record = keyed_case()
    assert verify_projection_fidelity(envelope, record, keys) is FidelityResult.NOT_VERIFIABLE


def test_fidelity_not_verifiable_when_integrity_fails():
    envelope, record = keyed_case()
    tampered = dataclasses.replace(envelope, projection_digest="0" * 64)
    assert verify_projection_fidelity(tampered, record, both_keys()) is FidelityResult.NOT_VERIFIABLE
    request, _ = evaluate()
    v3 = seal_v3(record, request)
    for bad in (v3, json.loads(envelope.canonical_bytes()), None):
        assert verify_projection_fidelity(bad, record, both_keys()) is FidelityResult.NOT_VERIFIABLE


class _HostileRecord(DecisionRecord):
    pass


def test_fidelity_not_verifiable_for_incomplete_or_invalid_evidence():
    envelope, record = keyed_case()
    inconsistent = dataclasses.replace(record)
    object.__setattr__(inconsistent, "decision_digest", "0" * 64)  # no longer self-consistent
    hostile = dataclasses.replace(record)
    object.__setattr__(hostile, "approval", _Hostile(RuntimeError(CANARY)))
    for evidence in (None, record.to_dict(), "record", inconsistent, hostile):
        assert verify_projection_fidelity(envelope, evidence, both_keys()) is FidelityResult.NOT_VERIFIABLE


def test_fidelity_contains_a_hostile_projection_object():
    envelope, record = keyed_case()
    object.__setattr__(envelope.projection.engine, "decision", _Hostile(RuntimeError("hostile " + CANARY)))
    assert verify_projection_fidelity(envelope, record, both_keys()) is FidelityResult.NOT_VERIFIABLE


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
def test_fidelity_lets_base_exceptions_propagate(kind):
    envelope, record = keyed_case()
    raised = kind("hostile")
    hostile = dataclasses.replace(record)
    object.__setattr__(hostile, "approval", _Hostile(raised))
    with pytest.raises(kind) as info:
        verify_projection_fidelity(envelope, hostile, both_keys())
    assert info.value is raised


def test_fidelity_never_modifies_inputs():
    envelope, record = keyed_case(engine_for(5), **APPROVAL_REQUEST)
    before_envelope, before_record = envelope.canonical_bytes(), json.dumps(record.to_dict(), sort_keys=True)
    verify_projection_fidelity(envelope, record, both_keys())
    assert envelope.canonical_bytes() == before_envelope
    assert json.dumps(record.to_dict(), sort_keys=True) == before_record


# --- Compatibility -----------------------------------------------------------------------------


def test_check_v3_projection_source_is_an_alias_of_check_persistable():
    assert check_v3_projection_source is check_persistable
    request, record = evaluate()
    v3 = seal_v3(record, request)
    assert check_v3_projection_source(v3, RING).code is PersistenceCode.OK
    assert check_persistable(project(v3, both_keys()), RING).code is PersistenceCode.NOT_AN_ENVELOPE


def test_projection_mac_and_digest_helpers_are_unchanged():
    envelope = keyed_case()[0]
    body = envelope.projection.to_dict()
    assert compute_projection_digest(body) == envelope.projection_digest
    assert compute_projection_mac(auth_key(), body) == envelope.auth.mac


def test_gate_and_fidelity_perform_no_io(monkeypatch):
    envelope, record = keyed_case(**APPROVAL_REQUEST)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("I/O attempted")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(io, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert gate(envelope, expected_epoch=ProjectionEpoch.keyed(ref_key())).ok
    assert verify_projection_fidelity(envelope, record, both_keys()) is FidelityResult.MATCH


def test_envelope_v1_with_a_projection_like_body_is_refused():
    request, record = evaluate()
    v3 = seal_v3(record, request)
    assert type(v3) is AuditEnvelope
    assert gate(v3).code is ProjectionGateCode.V3_EVENT_NOT_PERSISTABLE
