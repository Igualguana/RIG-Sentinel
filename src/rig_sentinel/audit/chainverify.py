"""Pure verification of an audit chain given as record lines (Genesis B2-M2-C1).

:func:`verify_chain` takes byte lines already in memory; it reads no file and evaluates no
anchor or external checkpoint (anchor classification and checkpoint matching are C4). Its
best outcome is therefore :attr:`ChainStatus.CHAIN_VALID`: every record parsed, linked and
authenticated under the configured keys. That does **not** exclude truncation of the tail, a
rollback of the whole chain, or forgery by a holder of the relevant K_chain.

Rules checked:

* the first record is the genesis ``segment_open`` (segment 0, seq 0, no previous digest);
* ``seq`` is contiguous, every ``prev_record_digest`` names the previous record, and the
  ``chain_id`` never changes (and equals ``expected_chain_id`` when given);
* each segment starts with ``segment_open``; segments increase; nothing follows a
  ``segment_close`` except the next ``segment_open``; ``previous_segment``, close counts and
  rotation reasons match; K_chain, K_auth or epoch change only with the matching rotation;
* every chain MAC verifies under the segment header's ``chain_key_id``;
* every event's envelope bytes pass the P2 gate again with the header's K_auth and epoch and
  equal the gate's canonical output; a refused envelope is ``PRIVACY_DAMAGE``, never valid;
* an ``event_id`` appears at most once per segment.

Outcomes (worst wins): ``DAMAGED`` > ``UNVERIFIABLE`` (a needed key is missing, F9) >
``DISCONTINUOUS`` (a recovery or anchor re-initialization was recorded) > ``CHAIN_VALID``.
Resources (H1-02): the input is a ``list`` or ``tuple`` the caller has already materialized;
generators and other iterables are refused, so the input cannot be endless, and a list can't
reference earlier records (segments are only compared by number, never followed). Verification
is a single pass over at most ``max_records`` lines (default 1,000,000; larger input is refused
with ``RECORD_BUDGET_EXCEEDED`` before any work). Each line is bounded by the 20,480-byte line
limit before parsing. Memory added by the verifier is the current line, the last parsed record,
one segment's event ids (at most ``max_records``) and at most ``max_issues + 1`` issues. The
memory of the caller's materialized input itself is outside this function's control.

Output privacy (H1-04): :class:`ChainReport` and :class:`ChainIssue` contain only status codes,
line indexes, sequence numbers, counts and ``last_record_digest`` (a digest of persisted bytes of
the same kind that anchors and checkpoints publish). They never contain projection content,
key ids, MACs, key material or input bytes. When ``authenticated`` is ``False`` (structure-only
or a missing key), ``last_record_digest`` and ``last_seq`` are **unauthenticated** values taken
from the input and must not be treated as evidence. Configuration errors raise
:class:`StorageError` with a code and a fixed path only, without exception context.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from rig_sentinel.audit.bounded_json import strict_canonical_loads
from rig_sentinel.audit.keys import AuditKey, KeyPurpose
from rig_sentinel.audit.projection import (
    ProjectionGateCode,
    check_projection_persistable,
    projection_envelope_from_dict,
)
from rig_sentinel.audit.records import (
    CloseReason,
    OpenReason,
    ParsedRecord,
    RecordKind,
    SegmentHeader,
    _require_chain_keyring,
    key_matches_epoch,
    parse_record,
    verify_record_mac,
)
from rig_sentinel.audit.storage_errors import StorageError, StorageErrorCode
from rig_sentinel.audit.validation import MAX_ENVELOPE_BYTES

DEFAULT_MAX_ISSUES = 1_000
MAX_ISSUES_LIMIT = 100_000
DEFAULT_MAX_RECORDS = 1_000_000
MAX_RECORDS_LIMIT = 10_000_000


class ChainStatus(StrEnum):
    DAMAGED = "DAMAGED"
    UNVERIFIABLE = "UNVERIFIABLE"
    DISCONTINUOUS = "DISCONTINUOUS"
    CHAIN_VALID = "CHAIN_VALID"


_RANK = {
    ChainStatus.CHAIN_VALID: 0,
    ChainStatus.DISCONTINUOUS: 1,
    ChainStatus.UNVERIFIABLE: 2,
    ChainStatus.DAMAGED: 3,
}


@dataclass(frozen=True)
class ChainIssue:
    """One finding: line index (0-based), the record's seq if known, a code and its severity."""

    index: int
    seq: int | None
    code: StorageErrorCode
    severity: ChainStatus


@dataclass(frozen=True)
class ChainReport:
    status: ChainStatus
    issues: tuple[ChainIssue, ...]
    records: int
    segments: int
    last_seq: int | None
    last_record_digest: str | None
    authenticated: bool  # False whenever any record's chain MAC or P2 MAC could not be checked


# What a close reason allows the next segment_open to be, and what that open may change.
_OPEN_AFTER_CLOSE = {
    CloseReason.SIZE: frozenset({OpenReason.ROTATION, OpenReason.WRITER_RESTART}),
    CloseReason.SHUTDOWN: frozenset({OpenReason.WRITER_RESTART, OpenReason.ROTATION}),
    CloseReason.EPOCH_ROTATION: frozenset({OpenReason.EPOCH_ROTATION}),
    CloseReason.KEY_ROTATION: frozenset({OpenReason.KEY_ROTATION}),
    CloseReason.CHAIN_KEY_ROTATION: frozenset({OpenReason.CHAIN_KEY_ROTATION}),
}
_OPEN_WITHOUT_CLOSE = frozenset({OpenReason.RECOVERY, OpenReason.ANCHOR_REINITIALIZED})
_CHANGE_ALLOWED = {
    OpenReason.EPOCH_ROTATION: "epoch",
    OpenReason.KEY_ROTATION: "auth",
    OpenReason.CHAIN_KEY_ROTATION: "chain",
}
_GATE_PRIVACY = frozenset(
    {ProjectionGateCode.SCHEMA_INVALID, ProjectionGateCode.FORBIDDEN_FIELD, ProjectionGateCode.LABEL_NOT_ALLOWED,
     ProjectionGateCode.NOT_A_PROJECTION, ProjectionGateCode.V2_EVENT_NOT_PERSISTABLE,
     ProjectionGateCode.V3_EVENT_NOT_PERSISTABLE}
)
_GATE_AUTH = frozenset({ProjectionGateCode.DIGEST_MISMATCH, ProjectionGateCode.AUTHENTICATION_FAILED})


class _TooManyIssues(Exception):
    pass


def _require_auth_keyring(keys: object) -> dict[str, AuditKey]:
    if type(keys) is not dict:
        raise StorageError(StorageErrorCode.KEYRING_INVALID, "auth_keys")
    for key_id, key in keys.items():
        if type(key_id) is not str or type(key) is not AuditKey:
            raise StorageError(StorageErrorCode.KEYRING_INVALID, "auth_keys")
        if key.purpose is not KeyPurpose.AUTH or key.key_id != key_id:
            raise StorageError(StorageErrorCode.KEYRING_INVALID, "auth_keys")
    return keys


class _Verifier:
    def __init__(
        self, chain_keys: dict[str, AuditKey], auth_keys: dict[str, AuditKey], expected_chain_id: str | None,
        readable_labels: object, max_issues: int,
    ) -> None:
        self.chain_keys = chain_keys
        self.auth_keys = auth_keys
        self.expected_chain_id = expected_chain_id
        self.readable_labels = readable_labels
        self.max_issues = max_issues
        self.issues: list[ChainIssue] = []
        self.status = ChainStatus.CHAIN_VALID
        self.authenticated = True
        self.records = 0
        self.segments = 0
        self.chain_id: str | None = None
        self.last: ParsedRecord | None = None  # last successfully parsed record
        self.linked = True  # False after a damaged line: the next link cannot be checked
        self.header: SegmentHeader | None = None
        self.segment: int | None = None
        self.segment_first_seq = 0
        self.closed: CloseReason | None = None
        self.event_ids: set[str] = set()

    def issue(self, index: int, seq: int | None, code: StorageErrorCode, severity: ChainStatus) -> None:
        if _RANK[severity] > _RANK[self.status]:
            self.status = severity
        if severity is ChainStatus.UNVERIFIABLE:
            self.authenticated = False
        if len(self.issues) >= self.max_issues:
            self.issues.append(ChainIssue(index, None, StorageErrorCode.TOO_MANY_ISSUES, ChainStatus.DAMAGED))
            self.status = ChainStatus.DAMAGED
            raise _TooManyIssues
        self.issues.append(ChainIssue(index, seq, code, severity))

    def damaged(self, index: int, seq: int | None, code: StorageErrorCode) -> None:
        self.issue(index, seq, code, ChainStatus.DAMAGED)

    # -- per line ---------------------------------------------------------------------------

    def line(self, index: int, data: object) -> None:
        self.records += 1
        code: StorageErrorCode | None = None
        record: ParsedRecord | None = None
        try:
            record = parse_record(data)
        except StorageError as error:
            code = error.code
        if record is None:
            self.damaged(index, None, code or StorageErrorCode.SCHEMA_INVALID)
            self.linked = False
            return
        self.position(index, record)
        if record.kind is RecordKind.SEGMENT_OPEN:
            self.segment_open(index, record)
        else:
            self.in_segment(index, record)
        self.chain_mac(index, record)
        if record.kind is RecordKind.EVENT:
            self.event(index, record)
        self.last = record
        self.linked = True

    def position(self, index: int, record: ParsedRecord) -> None:
        if self.chain_id is None:
            self.chain_id = record.chain_id
            if self.expected_chain_id is not None and record.chain_id != self.expected_chain_id:
                self.damaged(index, record.seq, StorageErrorCode.CHAIN_ID_MISMATCH)
        elif record.chain_id != self.chain_id:
            self.damaged(index, record.seq, StorageErrorCode.CHAIN_ID_MISMATCH)
        if index == 0:
            if record.kind is not RecordKind.SEGMENT_OPEN or record.seq != 0:
                self.damaged(index, record.seq, StorageErrorCode.GENESIS_INVALID)
            return
        if self.last is None or not self.linked:
            return  # the previous line was unreadable; that is already reported
        if record.seq != self.last.seq + 1:
            self.damaged(index, record.seq, StorageErrorCode.SEQUENCE_GAP)
        elif record.prev_record_digest != self.last.record_digest:
            self.damaged(index, record.seq, StorageErrorCode.LINK_BROKEN)

    def segment_open(self, index: int, record: ParsedRecord) -> None:
        header = record.header
        assert header is not None  # parse_record always sets it for segment_open
        previous_header = self.header
        if index != 0:
            self.check_transition(index, record, header, previous_header)
        if header.reason in _OPEN_WITHOUT_CLOSE:
            code = (StorageErrorCode.ANCHOR_REINITIALIZED if header.reason is OpenReason.ANCHOR_REINITIALIZED
                    else StorageErrorCode.RECOVERY_RECORDED)
            self.issue(index, record.seq, code, ChainStatus.DISCONTINUOUS)
        self.header = header
        self.segment = record.segment
        self.segment_first_seq = record.seq
        self.segments += 1
        self.closed = None
        self.event_ids = set()
        if header.chain_key_id != record.chain_key_id:
            self.damaged(index, record.seq, StorageErrorCode.KEY_CHANGE_INVALID)
        # H1-03: the segment's K_chain or K_auth must not be its epoch's K_ref or K_eref.
        keys = [key for key in (self.chain_keys.get(header.chain_key_id), self.auth_keys.get(header.auth_key_id))
                if key is not None]
        shared = False
        for key in keys:
            shared = key_matches_epoch(key, header.epoch) | shared
        if shared:
            self.damaged(index, record.seq, StorageErrorCode.KEYS_NOT_INDEPENDENT)

    def check_transition(
        self, index: int, record: ParsedRecord, header: SegmentHeader, previous_header: SegmentHeader | None
    ) -> None:
        if previous_header is None or self.segment is None:
            return  # no valid earlier header to compare with (already reported)
        if self.closed is not None:
            allowed = _OPEN_AFTER_CLOSE[self.closed] | _OPEN_WITHOUT_CLOSE  # recovery may follow a close
            if header.reason not in allowed:
                self.damaged(index, record.seq, StorageErrorCode.SEGMENT_INVALID)
        elif header.reason not in _OPEN_WITHOUT_CLOSE:
            self.damaged(index, record.seq, StorageErrorCode.SEGMENT_INVALID)
        if header.reason is OpenReason.RECOVERY:
            if record.segment <= self.segment:
                self.damaged(index, record.seq, StorageErrorCode.SEGMENT_INVALID)
        elif record.segment != self.segment + 1:
            self.damaged(index, record.seq, StorageErrorCode.SEGMENT_INVALID)
        previous = header.previous_segment
        if self.last is not None and self.linked and previous is not None and (
            previous.segment != self.segment
            or previous.last_seq != self.last.seq
            or previous.last_record_digest != self.last.record_digest
        ):
            self.damaged(index, record.seq, StorageErrorCode.SEGMENT_INVALID)
        changes = set()
        if header.chain_key_id != previous_header.chain_key_id:
            changes.add("chain")
        if header.auth_key_id != previous_header.auth_key_id:
            changes.add("auth")
        if header.epoch != previous_header.epoch:
            changes.add("epoch")
        allowed_change = _CHANGE_ALLOWED.get(header.reason)
        if changes - ({allowed_change} if allowed_change else set()):
            self.damaged(index, record.seq, StorageErrorCode.KEY_CHANGE_INVALID)

    def in_segment(self, index: int, record: ParsedRecord) -> None:
        if self.header is None or self.segment is None:
            return  # no header yet: GENESIS_INVALID already reported for index 0
        if record.segment != self.segment or self.closed is not None:
            self.damaged(index, record.seq, StorageErrorCode.SEGMENT_INVALID)
        if record.chain_key_id != self.header.chain_key_id:
            self.damaged(index, record.seq, StorageErrorCode.KEY_CHANGE_INVALID)
        if record.kind is RecordKind.SEGMENT_CLOSE:
            body = record.body or {}
            if body.get("record_count") != record.seq - self.segment_first_seq + 1:
                self.damaged(index, record.seq, StorageErrorCode.SEGMENT_INVALID)
            self.closed = CloseReason(body.get("reason"))

    def chain_mac(self, index: int, record: ParsedRecord) -> None:
        key = self.chain_keys.get(record.chain_key_id)
        if key is None:
            self.issue(index, record.seq, StorageErrorCode.UNKNOWN_KEY, ChainStatus.UNVERIFIABLE)
        elif not verify_record_mac(record, key):
            self.damaged(index, record.seq, StorageErrorCode.MAC_INVALID)

    def event(self, index: int, record: ParsedRecord) -> None:
        header = self.header
        if header is None:
            return
        raw = record.envelope_bytes
        envelope: Any = None
        refused = False
        try:
            envelope = projection_envelope_from_dict(strict_canonical_loads(raw, max_bytes=MAX_ENVELOPE_BYTES))
        except Exception:  # a bounded-parser or closed-schema refusal is privacy damage
            refused = True
        if refused:
            self.damaged(index, record.seq, StorageErrorCode.PRIVACY_DAMAGE)
            return
        auth_key = self.auth_keys.get(header.auth_key_id)
        ring = {} if auth_key is None else {auth_key.key_id: auth_key}
        result = check_projection_persistable(
            envelope, ring, readable_labels=self.readable_labels, expected_epoch=header.epoch
        )
        if result.ok and result.validated is not None:
            if result.validated.canonical != raw:
                self.damaged(index, record.seq, StorageErrorCode.PRIVACY_DAMAGE)
                return
            event_id = result.validated.event_id
            if event_id in self.event_ids:
                self.damaged(index, record.seq, StorageErrorCode.DUPLICATE_EVENT_ID)
            self.event_ids.add(event_id)
            return
        gate = result.code
        if gate in _GATE_PRIVACY or gate is ProjectionGateCode.CONFIGURATION_INVALID:
            self.damaged(index, record.seq, StorageErrorCode.PRIVACY_DAMAGE)
        elif gate is ProjectionGateCode.UNKNOWN_KEY:
            if auth_key is None:
                self.issue(index, record.seq, StorageErrorCode.UNKNOWN_KEY, ChainStatus.UNVERIFIABLE)
            else:  # sealed under a different K_auth than the segment header names
                self.damaged(index, record.seq, StorageErrorCode.KEY_CHANGE_INVALID)
        elif gate is ProjectionGateCode.EPOCH_MISMATCH:
            self.damaged(index, record.seq, StorageErrorCode.EPOCH_MISMATCH)
        elif gate in _GATE_AUTH:
            self.damaged(index, record.seq, StorageErrorCode.PROJECTION_AUTH_FAILED)
        else:
            self.damaged(index, record.seq, StorageErrorCode.PRIVACY_DAMAGE)


def verify_chain(
    lines: Iterable[bytes],
    *,
    chain_keys: object,
    auth_keys: object,
    expected_chain_id: object = None,
    readable_labels: object = None,
    max_issues: object = DEFAULT_MAX_ISSUES,
    max_records: object = DEFAULT_MAX_RECORDS,
) -> ChainReport:
    """Verify a chain from its record lines (each ending in ``\\n``), oldest first.

    ``chain_keys`` and ``auth_keys`` are exact dicts ({key_id: key}); either may be empty, in
    which case the affected MACs are not checked and the outcome is at best ``UNVERIFIABLE``
    (structure-only, F9). Configuration errors raise :class:`StorageError`; content problems
    never raise and are reported as issues.
    """
    chain_ring = _require_chain_keyring(chain_keys)
    auth_ring = _require_auth_keyring(auth_keys)
    for chain_key in chain_ring.values():
        for auth_key in auth_ring.values():
            if chain_key._same_material(auth_key):
                raise StorageError(StorageErrorCode.KEYS_NOT_INDEPENDENT, "keys")
    if expected_chain_id is not None and (
        type(expected_chain_id) is not str or len(expected_chain_id) != 32
        or any(c not in "0123456789abcdef" for c in expected_chain_id)
    ):
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "expected_chain_id")
    if type(max_issues) is not int or not 1 <= max_issues <= MAX_ISSUES_LIMIT:
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "max_issues")
    if type(lines) not in (list, tuple):
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "lines")
    if type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS_LIMIT:
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "max_records")
    if len(lines) > max_records:
        raise StorageError(StorageErrorCode.RECORD_BUDGET_EXCEEDED, "lines")
    if readable_labels is not None and type(readable_labels) not in (set, frozenset):
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "readable_labels")

    verifier = _Verifier(chain_ring, auth_ring, expected_chain_id, readable_labels, max_issues)  # type: ignore[arg-type]
    if not chain_ring or not auth_ring:
        verifier.authenticated = False
    try:
        if not lines:
            verifier.issue(0, None, StorageErrorCode.EMPTY_CHAIN, ChainStatus.UNVERIFIABLE)
        for index, data in enumerate(lines):
            verifier.line(index, data)
    except _TooManyIssues:
        pass
    if not verifier.authenticated and verifier.status is not ChainStatus.DAMAGED:
        verifier.status = ChainStatus.UNVERIFIABLE  # F9: no "valid" without authentication
    last = verifier.last
    return ChainReport(
        status=verifier.status,
        issues=tuple(verifier.issues),
        records=verifier.records,
        segments=verifier.segments,
        last_seq=None if last is None else last.seq,
        last_record_digest=None if last is None else last.record_digest,
        authenticated=verifier.authenticated and verifier.status is not ChainStatus.UNVERIFIABLE,
    )


__all__ = [
    "DEFAULT_MAX_ISSUES",
    "DEFAULT_MAX_RECORDS",
    "ChainIssue",
    "ChainReport",
    "ChainStatus",
    "verify_chain",
]
