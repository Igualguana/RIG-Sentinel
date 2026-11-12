"""Genesis B2-P2-B1-H1: hardening after the independent security review.

H1 positive UNLINKED source validation; H2 exception context and BaseException policy;
H3 every valid v3 request-digest state; H4 approver fidelity contract; H5 direct tests of
the shared profile/source check. Invalid states are built only with ``object.__setattr__``
on test-local copies or by a key holder sealing them, never by weakening validation.
Synthetic values only.
"""

import dataclasses
import hashlib
import hmac
import itertools
import json
from collections.abc import Mapping
from enum import StrEnum

import pytest
from audit_fixtures import FIXED_AUDIT_NOW, REF_MATERIAL, auth_key, both_keys
from policy_fixtures import POLICY_HEADER, RULE_BLOCKS, fixed_clock, make_request

from rig_sentinel.audit import (
    AUDIT_EVENT_SCHEMA_V3,
    AuditEnvelope,
    AuditError,
    AuditErrorCode,
    AuditEventBuilder,
    AuditKey,
    AuditKeys,
    AuthStatus,
    KeyPurpose,
    ProjectionEvent,
    ProjectionProfile,
    RedactionMode,
    RequestConsistency,
    keyring,
    project,
    projection_envelope_from_dict,
    projection_from_dict,
    verify_projection_envelope_dict,
)
from rig_sentinel.audit.projection import _require_profile_source
from rig_sentinel.policy import PolicyEngine, load_policy_text

NUL = bytes(1)
RING = keyring([auth_key()])
OTHER_AUTH = AuditKey.from_bytes(KeyPurpose.AUTH, bytes(range(110, 142)))
CANARY = "zq-" + "canary-" + "4d1e"
APPROVAL_REQUEST = dict(tool="mcp://helpdesk/tickets.update", operation="database_write",
                        resource="db:helpdesk/tickets")


class LookAlikeMode(StrEnum):
    """Same values as RedactionMode, different type: must never be accepted."""

    SCOPED = "scoped"
    NO_REF_KEY = "no-ref-key"


def engine_with_approvers(count=0, policy=True):
    if not policy:
        return PolicyEngine(None, clock=fixed_clock)
    blocks = "".join(f'\n[[approvers]]\nid = "canary-approver-{i:02d}"\nscopes = ["*"]\n' for i in range(count))
    return PolicyEngine(load_policy_text(POLICY_HEADER + blocks + "\n" + "\n".join(RULE_BLOCKS)), clock=fixed_clock)


def build(keys=None, engine=None, request=None, evaluate=None, **overrides):
    request = make_request(**overrides) if request is None else request
    record = (engine or engine_with_approvers()).evaluate(request if evaluate is None else evaluate)
    ids = itertools.count(1)
    builder = AuditEventBuilder(both_keys() if keys is None else keys, clock=lambda: FIXED_AUDIT_NOW,
                                id_factory=lambda: f"{next(ids):032x}", event_schema=AUDIT_EVENT_SCHEMA_V3)
    return builder.build_envelope(record, request)


def omitted_keys():
    return AuditKeys(auth=auth_key())


def raw_engine_ref(kind, value):
    k_eref = hmac.new(REF_MATERIAL, b"rig.audit-key-derive/v1" + NUL + b"engine-ref", hashlib.sha256).digest()
    return hmac.new(k_eref, f"rig.audit-engine-ref/v1/{kind}".encode() + NUL + value.encode(),
                    hashlib.sha256).hexdigest()[:32]


def raw_approver_ref(approver_id):
    return hmac.new(REF_MATERIAL, b"rig.audit-ref/v1/approver" + NUL + approver_id.encode(),
                    hashlib.sha256).hexdigest()[:32]


def code_of(fn, *args, **kwargs):
    with pytest.raises(AuditError) as info:
        fn(*args, **kwargs)
    error = info.value
    assert error.__context__ is None and error.__cause__ is None and not error.__suppress_context__
    return error


# --- H1: positive UNLINKED source validation -----------------------------------------------


def test_valid_no_ref_key_source_projects_unlinked():
    source = build(omitted_keys())
    assert source.event.audit.redaction_mode is RedactionMode.NO_REF_KEY
    projected = project(source, omitted_keys(), profile=ProjectionProfile.UNLINKED)
    assert projected.projection.audit.redaction_mode is RedactionMode.NO_REF_KEY
    assert projected.verify(RING) is AuthStatus.AUTHENTIC


@pytest.mark.parametrize("keys", ["with-ref", "without-ref"])
def test_scoped_source_is_rejected_for_unlinked(keys):
    supplied = both_keys() if keys == "with-ref" else omitted_keys()
    error = code_of(project, build(), supplied, profile=ProjectionProfile.UNLINKED)
    assert error.code is AuditErrorCode.INCONSISTENT_EVENT and error.path == "projection.engine_ref_mode"


VALID_PAIRS = {(ProjectionProfile.KEYED, RedactionMode.SCOPED), (ProjectionProfile.UNLINKED, RedactionMode.NO_REF_KEY)}
PROFILES = [ProjectionProfile.KEYED, ProjectionProfile.UNLINKED, "keyed", "unlinked", None]
MODES = [RedactionMode.SCOPED, RedactionMode.NO_REF_KEY, "scoped", "no-ref-key", None, 0,
         LookAlikeMode.SCOPED, LookAlikeMode.NO_REF_KEY, type("S", (str,), {})("no-ref-key")]


@pytest.mark.parametrize("profile", PROFILES, ids=lambda p: f"profile={p!r}")
@pytest.mark.parametrize("mode", MODES, ids=lambda m: f"mode={type(m).__name__}:{m!s}")
def test_profile_source_check_accepts_only_the_two_exact_pairs(profile, mode):
    if (profile, mode) in VALID_PAIRS and type(mode) is RedactionMode and type(profile) is ProjectionProfile:
        assert _require_profile_source(profile, mode) is None
    else:
        error = code_of(_require_profile_source, profile, mode)
        assert error.code is AuditErrorCode.INCONSISTENT_EVENT


def test_model_rejects_a_look_alike_no_ref_key_mode():
    event = project(build(omitted_keys()), omitted_keys(), profile=ProjectionProfile.UNLINKED).projection
    audit = dataclasses.replace(event.audit)
    object.__setattr__(audit, "redaction_mode", LookAlikeMode.NO_REF_KEY)  # test-local copy only
    error = code_of(ProjectionEvent, audit=audit, engine=event.engine, caller=event.caller, projection=event.projection)
    assert error.code is AuditErrorCode.INCONSISTENT_EVENT and error.path == "projection.engine_ref_mode"


@pytest.mark.parametrize("forgery", ["mac", "digest", "unsealed", "other-k-auth"])
def test_forged_no_ref_key_sources_are_refused_before_the_mode_check(forgery):
    source = build(omitted_keys())
    if forgery == "mac":
        source = dataclasses.replace(source, auth=dataclasses.replace(source.auth, mac="0" * 64))
        expected = AuditErrorCode.AUTHENTICATION_FAILED
    elif forgery == "digest":
        source = dataclasses.replace(source, event_digest="0" * 64)
        expected = AuditErrorCode.DIGEST_MISMATCH
    elif forgery == "unsealed":
        source = build(AuditKeys())
        expected = AuditErrorCode.UNAUTHENTICATED_REJECTED
    else:
        source = build(AuditKeys(auth=OTHER_AUTH))
        expected = AuditErrorCode.AUTHENTICATION_FAILED
    assert code_of(project, source, omitted_keys(), profile=ProjectionProfile.UNLINKED).code is expected


def test_in_memory_look_alike_mode_cannot_bypass_the_reparse():
    # Same canonical bytes (same .value), different type: the projector must read the re-parsed enum.
    source = build(omitted_keys())
    object.__setattr__(source.event.audit, "redaction_mode", LookAlikeMode.NO_REF_KEY)
    assert source.verify(RING) is AuthStatus.AUTHENTIC
    projected = project(source, omitted_keys(), profile=ProjectionProfile.UNLINKED)
    assert type(projected.projection.audit.redaction_mode) is RedactionMode
    assert projected.projection.audit.redaction_mode is RedactionMode.NO_REF_KEY


def test_scoped_source_disguised_as_no_ref_key_in_memory_is_refused():
    source = build()
    object.__setattr__(source.event.audit, "redaction_mode", RedactionMode.NO_REF_KEY)
    with pytest.raises(AuditError) as info:
        project(source, omitted_keys(), profile=ProjectionProfile.UNLINKED)
    assert info.value.code in (AuditErrorCode.INVALID_ENVELOPE, AuditErrorCode.DIGEST_MISMATCH)
    assert info.value.__context__ is None


def test_projector_layer_refuses_unlinked_scoped_source_without_the_model_check(monkeypatch):
    # H5: isolate the projector's own check by disabling the model check (test-local only).
    monkeypatch.setattr(ProjectionEvent, "__post_init__", lambda self: None)
    error = code_of(project, build(), both_keys(), profile=ProjectionProfile.UNLINKED)
    assert error.code is AuditErrorCode.INCONSISTENT_EVENT and error.path == "projection.engine_ref_mode"


def test_projection_enum_parser_never_raises_inside_a_handler():
    from rig_sentinel.audit.projection import _parse_enum

    for bad in (CANARY, "KEYED", None, 1, type("S", (str,), {})("keyed")):
        error = code_of(_parse_enum, ProjectionProfile, bad, "projection.engine_ref_mode")
        assert error.code is AuditErrorCode.INVALID_FIELD
        assert CANARY not in str(error) + repr(error)
    assert _parse_enum(ProjectionProfile, "keyed", "x") is ProjectionProfile.KEYED


def test_keyed_profile_requires_exactly_scoped_and_never_falls_back():
    assert code_of(project, build(omitted_keys()), both_keys()).code is AuditErrorCode.REF_KEY_REQUIRED
    assert code_of(project, build(omitted_keys()), omitted_keys()).code is AuditErrorCode.REF_KEY_REQUIRED


# --- H2: exception context and BaseException policy ----------------------------------------


def _projected_dict():
    return json.loads(project(build(**APPROVAL_REQUEST), both_keys()).canonical_bytes())


@pytest.mark.parametrize(
    "path",
    [("projection", "caller", "consistency"), ("projection", "caller", "identity_mode"),
     ("projection", "caller", "assurance_claim"), ("projection", "caller", "operation"),
     ("projection", "caller", "environment"), ("projection", "caller", "resource", "kind"),
     ("projection", "audit", "redaction_mode"), ("projection", "engine", "decision"),
     ("projection", "engine", "reason_code"), ("projection", "projection", "engine_ref_mode")],
    ids=lambda p: ".".join(p[1:]),
)
@pytest.mark.parametrize("parser", ["envelope", "projection"])
def test_parser_errors_never_carry_the_offending_value(path, parser):
    data = _projected_dict()
    target = data
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = CANARY
    with pytest.raises(AuditError) as info:
        if parser == "envelope":
            projection_envelope_from_dict(data)
        else:
            projection_from_dict(data["projection"])
    error = info.value
    assert error.code is AuditErrorCode.INVALID_FIELD
    assert error.__context__ is None and error.__cause__ is None and not error.__suppress_context__
    assert CANARY not in str(error) + repr(error) + repr(error.args)


class _Hostile:
    def __init__(self, exc):
        self._exc = exc

    @property
    def value(self):
        raise self._exc


def _hostile_source(exc):
    source = build()
    object.__setattr__(source.event.engine, "decision", _Hostile(exc))
    return source


def test_hostile_exception_inside_project_is_contained_without_context():
    error = code_of(project, _hostile_source(RuntimeError("hostile " + CANARY)), both_keys())
    assert error.code is AuditErrorCode.INVALID_ENVELOPE
    assert CANARY not in str(error) + repr(error) + repr(error.args)


class CustomBaseException(BaseException):
    pass


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit, CustomBaseException, GeneratorExit])
def test_base_exceptions_propagate_unchanged(kind):
    raised = kind("hostile " + CANARY)
    with pytest.raises(kind) as info:
        project(_hostile_source(raised), both_keys())
    assert info.value is raised  # never caught, converted or reconstructed


class _HostileRing(Mapping):
    def __getitem__(self, key):
        raise RuntimeError("ring " + CANARY)

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0

    def get(self, key, default=None):
        raise RuntimeError("ring " + CANARY)


def test_verify_never_runs_code_from_a_keyring_that_is_not_an_exact_dict():
    projected = project(build(), both_keys())
    assert projected.verify(_HostileRing()) is AuthStatus.UNKNOWN_KEY
    assert projected.verify(type("RingSubclass", (dict,), {})(RING)) is AuthStatus.UNKNOWN_KEY
    assert projected.verify(dict(RING)) is AuthStatus.AUTHENTIC
    data = json.loads(projected.canonical_bytes())
    assert verify_projection_envelope_dict(data, _HostileRing()) is AuthStatus.UNKNOWN_KEY


def test_projector_refusals_carry_no_context():
    other = AuditKeys(ref=AuditKey.from_bytes(KeyPurpose.REF, bytes(range(70, 102))), auth=auth_key())
    for call in (
        lambda: project(build(), other),
        lambda: project(build(), both_keys(), profile=ProjectionProfile.UNLINKED),
        lambda: project(build(), both_keys(), profile="unlinked"),
        lambda: project(dataclasses.replace(build(), event_digest="0" * 64), both_keys()),
    ):
        code_of(call)


# --- H3: every valid v3 request-digest state ------------------------------------------------


_CLAIM_FIELDS = ("agent_ref", "assurance_claim", "tool_ref", "manifest_ref", "operation", "environment",
                 "readable_labels", "label_refs", "omitted_labels_count", "resource", "session_ref", "request_ref")


def _sealed_state(consistency, request_digest, keys=None):
    """A key holder seals a v3 event in a state the v3 model accepts."""
    event = build(keys).event
    caller = dataclasses.replace(event.caller, consistency=consistency, **{name: None for name in _CLAIM_FIELDS})
    engine = dataclasses.replace(event.engine, request_digest=request_digest)
    return AuditEnvelope.seal(dataclasses.replace(event, caller=caller, engine=engine), auth_key())


def test_state_consistent_has_a_keyed_request_reference():
    source = build()
    assert source.event.caller.consistency is RequestConsistency.CONSISTENT
    engine = project(source, both_keys()).projection.engine
    assert engine.request_ref == raw_engine_ref("request-digest", source.event.engine.request_digest)


def test_state_mismatch_from_the_builder_keeps_a_request_reference():
    evaluated = make_request(agent="support-bot")
    passed = make_request(agent="other-bot")
    source = build(request=passed, evaluate=evaluated)
    assert source.event.caller.consistency is RequestConsistency.MISMATCH
    assert source.event.engine.request_digest is not None
    engine = project(source, both_keys()).projection.engine
    assert engine.request_ref == raw_engine_ref("request-digest", source.event.engine.request_digest)


def test_state_invalid_request_without_digest_from_m1():
    source = build(resource="fs:/a/../b")
    assert source.event.caller.consistency is RequestConsistency.INVALID_REQUEST
    assert source.event.engine.request_digest is None
    assert project(source, both_keys()).projection.engine.request_ref is None


def test_state_not_applicable_from_m1_without_policy():
    source = build(engine=engine_with_approvers(policy=False))
    assert source.event.caller.consistency is RequestConsistency.NOT_APPLICABLE
    assert source.event.engine.request_digest is None
    assert project(source, both_keys()).projection.engine.request_ref is None


@pytest.mark.parametrize(
    "consistency, digest_present",
    [(RequestConsistency.INVALID_REQUEST, True), (RequestConsistency.MISMATCH, False),
     (RequestConsistency.INVALID_REQUEST, False), (RequestConsistency.NOT_APPLICABLE, False)],
    ids=["invalid-request-with-digest", "mismatch-without-digest", "invalid-request-without-digest",
         "not-applicable"],
)
def test_every_v3_valid_state_is_preserved(consistency, digest_present):
    digest = "d4" * 32 if digest_present else None
    source = _sealed_state(consistency, digest)
    engine = project(source, both_keys()).projection.engine
    assert engine.request_ref == (raw_engine_ref("request-digest", digest) if digest_present else None)


@pytest.mark.parametrize(
    "consistency, digest_present",
    [(RequestConsistency.CONSISTENT, False), (RequestConsistency.NOT_APPLICABLE, True)],
    ids=["consistent-without-digest", "not-applicable-with-digest"],
)
def test_states_invalid_in_v3_are_invalid_in_projection(consistency, digest_present):
    event = project(build(), both_keys()).projection
    caller = event.caller
    if consistency is not RequestConsistency.CONSISTENT:
        caller = dataclasses.replace(caller, consistency=consistency, **{name: None for name in _CLAIM_FIELDS})
    engine = dataclasses.replace(event.engine, request_ref="a" * 32 if digest_present else None)
    error = code_of(dataclasses.replace, event, caller=caller, engine=engine)
    assert error.code is AuditErrorCode.INCONSISTENT_EVENT


# --- H4: approver fidelity contract ---------------------------------------------------------


def _approval_for(count):
    engine = engine_with_approvers(count)
    source = build(engine=engine, **APPROVAL_REQUEST)
    raw_ids = sorted([f"canary-approver-{i:02d}" for i in range(count)] + ["oncall-lead"])
    return source, raw_ids, project(source, both_keys()).projection.engine.approval


def test_retains_the_first_32_sorted_raw_ids_then_hmac_sorts_them():
    source, raw_ids, approval = _approval_for(99)
    assert len(raw_ids) == 100 and approval.eligible_approver_count == 100
    assert source.event.engine.approval.eligible_approvers == tuple(raw_ids[:32])
    expected = tuple(sorted(raw_approver_ref(i) for i in raw_ids[:32]))
    assert approval.eligible_approver_refs == expected
    wrong = tuple(sorted(raw_approver_ref(i) for i in raw_ids)[:32])  # first 32 after HMAC-sorting all 100
    assert approval.eligible_approver_refs != wrong


@pytest.mark.parametrize("count, retained, truncated", [(31, 32, False), (32, 32, True)],
                         ids=["exactly-32", "33-truncated"])
def test_count_and_truncation_semantics(count, retained, truncated):
    _source, raw_ids, approval = _approval_for(count)
    assert approval.eligible_approver_count == len(raw_ids) == count + 1
    assert len(approval.eligible_approver_refs) == retained
    assert (approval.eligible_approver_count > len(approval.eligible_approver_refs)) is truncated


def test_zero_eligible_approvers_from_a_sealed_source():
    event = build(**APPROVAL_REQUEST).event
    approval = dataclasses.replace(event.engine.approval, eligible_approvers=(), eligible_approver_count=0)
    sealed = AuditEnvelope.seal(dataclasses.replace(event, engine=dataclasses.replace(event.engine, approval=approval)),
                                auth_key())
    projected = project(sealed, both_keys()).projection.engine.approval
    assert projected.eligible_approver_refs == () and projected.eligible_approver_count == 0


def test_output_references_are_deterministic_and_sorted():
    first = _approval_for(40)[2].eligible_approver_refs
    second = _approval_for(40)[2].eligible_approver_refs
    assert first == second and list(first) == sorted(first) and len(set(first)) == len(first)
