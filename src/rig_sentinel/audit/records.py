"""Pure audit-chain records, anchors and checkpoints (Genesis B2-M2-C1).

This module builds and parses the byte contracts of the future persistent audit chain
(``M2_C0_H1_ARCHITECTURE_FINAL.md``) without touching any file:

* ``rig.audit-record/v2`` lines: ``event`` records carrying the exact bytes of a P2 projection
  envelope (spliced, never re-serialized), and ``segment_open`` / ``segment_close`` /
  ``checkpoint_marker`` control records;
* ``rig.audit-anchor/v1`` contents (the future ``.seq_anchor`` file; C1 never writes one);
* ``rig.audit-checkpoint/v2`` contents (content-free, bound to the anchor generation).

Every chain, anchor and checkpoint MAC uses an independent ``K_chain``
(:attr:`KeyPurpose.CHAIN`) under its own domain. ``K_chain`` must differ from ``K_auth`` and
``K_ref``; nothing ever falls back to another key.

A :class:`ValidatedProjection` is treated as an untrusted carrier: its bytes are captured,
re-parsed under the bounded parser, re-checked by the P2 gate with the caller's ``K_auth`` and
explicit epoch, and must equal the gate's canonical output byte for byte before a record is
built. Parsing a stored line (:func:`parse_record`) checks structure and digests only;
authentication is separate (:func:`verify_record_mac`), and chain-level checks live in
:mod:`rig_sentinel.audit.chainverify`.

No file, lock, sync, anchor-file or recovery I/O happens here (those are C2-C4). Key separation
does not protect against compromise of a process that holds both keys.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from rig_sentinel.audit.bounded_json import strict_canonical_loads
from rig_sentinel.audit.errors import AuditError
from rig_sentinel.audit.keys import AuditKey, KeyPurpose, derive_engine_ref_key
from rig_sentinel.audit.projection import (
    ProjectionEpoch,
    ProjectionProfile,
    ValidatedProjection,
    check_projection_persistable,
    projection_envelope_from_dict,
)
from rig_sentinel.audit.storage_errors import StorageError, StorageErrorCode
from rig_sentinel.audit.validation import MAX_ENVELOPE_BYTES
from rig_sentinel.policy.canonical import canonical_json

__all__ = [
    "ANCHOR_MAC_DOMAIN",
    "ANCHOR_SCHEMA",
    "CHAIN_MAC_ALGORITHM",
    "CHAIN_MAC_DOMAIN",
    "CHECKPOINT_MAC_DOMAIN",
    "CHECKPOINT_SCHEMA",
    "ENVELOPE_IN_RECORD_DOMAIN",
    "MAX_ANCHOR_BYTES",
    "MAX_CHECKPOINT_BYTES",
    "MAX_POSITION",
    "MAX_RECORD_LINE_BYTES",
    "MAX_UNCONFIRMED_SEQS",
    "RECORD_DIGEST_DOMAIN",
    "RECORD_SCHEMA",
    "Anchor",
    "ChainPosition",
    "Checkpoint",
    "CloseReason",
    "DamageKind",
    "OpenReason",
    "ParsedRecord",
    "PreviousSegment",
    "RecordKind",
    "RecoveryInfo",
    "SegmentHeader",
    "StorageError",
    "StorageErrorCode",
    "build_anchor",
    "build_checkpoint",
    "build_checkpoint_marker",
    "build_event_record",
    "build_segment_close",
    "build_segment_open",
    "key_matches_epoch",
    "new_chain_id",
    "parse_record",
    "require_chain_key",
    "require_independent_keys",
    "revalidate_envelope_bytes",
    "verify_anchor",
    "verify_checkpoint",
    "verify_record_mac",
]

RECORD_SCHEMA = "rig.audit-record/v2"
ANCHOR_SCHEMA = "rig.audit-anchor/v1"
CHECKPOINT_SCHEMA = "rig.audit-checkpoint/v2"
CHAIN_MAC_ALGORITHM = "HMAC-SHA256"

ENVELOPE_IN_RECORD_DOMAIN = b"rig.audit-envelope-in-record/v2"
RECORD_DIGEST_DOMAIN = b"rig.audit-record/v2"
CHAIN_MAC_DOMAIN = b"rig.audit-chain-mac/v2"
ANCHOR_MAC_DOMAIN = b"rig.audit-anchor/v1"
CHECKPOINT_MAC_DOMAIN = b"rig.audit-checkpoint/v2"

MAX_RECORD_LINE_BYTES = 20_480  # including the terminating newline
MAX_ANCHOR_BYTES = 1_024
MAX_CHECKPOINT_BYTES = 2_048
MAX_POSITION = 2**53 - 1  # segments, sequence numbers, generations and counts
MAX_UNCONFIRMED_SEQS = 256

_NUL = bytes(1)
_NEWLINE = b"\n"
_SPLICE_PLACEHOLDER = "~rig-envelope-splice~"  # '~' never occurs in any validated record field
_HEX32_RE = re.compile(r"[0-9a-f]{32}")
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,31}")


# --- Enums ---------------------------------------------------------------------------------


class RecordKind(StrEnum):
    EVENT = "event"
    SEGMENT_OPEN = "segment_open"
    SEGMENT_CLOSE = "segment_close"
    CHECKPOINT_MARKER = "checkpoint_marker"


class OpenReason(StrEnum):
    GENESIS = "genesis"
    ROTATION = "rotation"
    RECOVERY = "recovery"
    EPOCH_ROTATION = "epoch_rotation"
    KEY_ROTATION = "key_rotation"
    CHAIN_KEY_ROTATION = "chain_key_rotation"
    WRITER_RESTART = "writer_restart"
    ANCHOR_REINITIALIZED = "anchor_reinitialized"


class CloseReason(StrEnum):
    SIZE = "size"
    EPOCH_ROTATION = "epoch_rotation"
    KEY_ROTATION = "key_rotation"
    CHAIN_KEY_ROTATION = "chain_key_rotation"
    SHUTDOWN = "shutdown"


class DamageKind(StrEnum):
    # Tail damage recorded by a ``recovery`` segment (classification itself is C4).
    PARTIAL_LINE = "partial_line"
    CORRUPT_TAIL = "corrupt_tail"
    UNCONFIRMED = "unconfirmed"
    HEADER_INCOMPLETE = "header_incomplete"
    PRIVACY_DAMAGE = "privacy_damage"
    # Anchor anomalies acknowledged by an operator (``anchor_reinitialized``, F15).
    ANCHOR_MISSING = "anchor_missing"
    ANCHOR_INVALID = "anchor_invalid"
    ANCHOR_STALE = "anchor_stale"
    LOG_BEHIND_ANCHOR = "log_behind_anchor"


_RECOVERY_DAMAGE = frozenset(
    {DamageKind.PARTIAL_LINE, DamageKind.CORRUPT_TAIL, DamageKind.UNCONFIRMED,
     DamageKind.HEADER_INCOMPLETE, DamageKind.PRIVACY_DAMAGE}
)
_ANCHOR_DAMAGE = frozenset(
    {DamageKind.ANCHOR_MISSING, DamageKind.ANCHOR_INVALID, DamageKind.ANCHOR_STALE,
     DamageKind.LOG_BEHIND_ANCHOR}
)


# --- Field checks (codes only, never values) -----------------------------------------------


def _schema_error(path: str) -> StorageError:
    return StorageError(StorageErrorCode.SCHEMA_INVALID, path)


def _hex32(value: object, path: str) -> str:
    if type(value) is not str or _HEX32_RE.fullmatch(value) is None:
        raise _schema_error(path)
    return value


def _hex64(value: object, path: str) -> str:
    if type(value) is not str or _HEX64_RE.fullmatch(value) is None:
        raise _schema_error(path)
    return value


def _count(value: object, path: str, low: int = 0, high: int = MAX_POSITION) -> int:
    if type(value) is not int or not low <= value <= high:
        raise _schema_error(path)
    return value


def _timestamp(value: object, path: str) -> str:
    if type(value) is not str or _TIMESTAMP_RE.fullmatch(value) is None:
        raise _schema_error(path)
    if not _is_real_time(value):
        raise _schema_error(path)
    return value


def _is_real_time(value: str) -> bool:
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def _enum_value(enum_type: Any, value: object, path: str) -> Any:
    if type(value) is not str or value not in enum_type._value2member_map_:
        raise _schema_error(path)
    return enum_type(value)


def _exact_type(value: object, kind: type, code: StorageErrorCode, path: str) -> Any:
    if type(value) is not kind:
        raise StorageError(code, path)
    return value


def _table(value: object, fields: frozenset[str], path: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise _schema_error(path)
    return value


def _sha256_hex(domain: bytes, payload: bytes) -> str:
    return hashlib.sha256(domain + _NUL + payload).hexdigest()


# --- Keys ----------------------------------------------------------------------------------


def require_chain_key(key: object) -> AuditKey:
    """Return ``key`` if it is exactly an :class:`AuditKey` with purpose ``CHAIN``."""
    if type(key) is not AuditKey:
        raise StorageError(StorageErrorCode.KEY_INVALID, "chain_key")
    if key.purpose is not KeyPurpose.CHAIN:
        raise StorageError(StorageErrorCode.KEY_PURPOSE_MISMATCH, "chain_key")
    return key


def _require_auth_key(key: object) -> AuditKey:
    if type(key) is not AuditKey:
        raise StorageError(StorageErrorCode.KEY_INVALID, "auth_key")
    if key.purpose is not KeyPurpose.AUTH:
        raise StorageError(StorageErrorCode.KEY_PURPOSE_MISMATCH, "auth_key")
    return key


def require_independent_keys(chain_key: object, auth_key: object, ref_key: object = None) -> None:
    """Refuse unless K_chain, K_auth (and K_ref and its derived K_eref, if K_ref is given) all
    have pairwise different material.

    Purposes are checked by identity first. Material is compared in constant time
    (``hmac.compare_digest``); every pair is compared, without early exit. K_eref is derived with
    the unchanged P2 construction (H1-03): a K_chain equal to K_eref would make K_chain
    recoverable from K_ref.
    """
    chain = require_chain_key(chain_key)
    auth = _require_auth_key(auth_key)
    ref: AuditKey | None = None
    if ref_key is not None:
        if type(ref_key) is not AuditKey:
            raise StorageError(StorageErrorCode.KEY_INVALID, "ref_key")
        if ref_key.purpose is not KeyPurpose.REF:
            raise StorageError(StorageErrorCode.KEY_PURPOSE_MISMATCH, "ref_key")
        ref = ref_key
    same = chain._same_material(auth)
    if ref is not None:
        eref = derive_engine_ref_key(ref)
        same = chain._same_material(ref) | same
        same = chain._same_material(eref) | same
        same = auth._same_material(ref) | same
        same = auth._same_material(eref) | same
    if same:
        raise StorageError(StorageErrorCode.KEYS_NOT_INDEPENDENT, "keys")


def key_matches_epoch(key: AuditKey, epoch: ProjectionEpoch) -> bool:
    """True if ``key``'s material is K_ref or K_eref of a keyed ``epoch`` (compared by key id).

    The epoch carries only public key ids, so this detects shared material without holding
    K_ref. An ``unlinked`` epoch names no K_ref and cannot be checked this way.
    """
    if epoch.engine_ref_mode is not ProjectionProfile.KEYED:
        return False
    as_ref = key._material_has_key_id(KeyPurpose.REF, epoch.ref_key_id)
    as_eref = key._material_has_key_id(KeyPurpose.ENGINE_REF, epoch.engine_ref_key_id)
    return as_ref | as_eref


def _require_independent_of_epoch(epoch: ProjectionEpoch, *keys: AuditKey) -> None:
    shared = False
    for key in keys:
        shared = key_matches_epoch(key, epoch) | shared
    if shared:
        raise StorageError(StorageErrorCode.KEYS_NOT_INDEPENDENT, "epoch")


def _require_chain_keyring(keys: object) -> dict[str, AuditKey]:
    """An exact ``dict`` {chain_key_id: K_chain}; anything else is a configuration error."""
    if type(keys) is not dict:
        raise StorageError(StorageErrorCode.KEYRING_INVALID, "chain_keys")
    for key_id, key in keys.items():
        if type(key_id) is not str or type(key) is not AuditKey:
            raise StorageError(StorageErrorCode.KEYRING_INVALID, "chain_keys")
        if key.purpose is not KeyPurpose.CHAIN or key.key_id != key_id:
            raise StorageError(StorageErrorCode.KEYRING_INVALID, "chain_keys")
    return keys


def _keyed_mac(key: AuditKey, domain: bytes, payload: bytes) -> str:
    return key._hmac_hex(KeyPurpose.CHAIN, domain + _NUL + key.key_id.encode("ascii") + _NUL + payload)


def new_chain_id() -> str:
    """A fresh random 128-bit chain id (32 lowercase hex characters)."""
    return secrets.token_hex(16)


# --- Positions and header parts --------------------------------------------------------------


@dataclass(frozen=True)
class ChainPosition:
    """Where a record sits: chain id, segment, contiguous ``seq`` and the previous digest."""

    chain_id: str
    segment: int
    seq: int
    prev_record_digest: str | None

    def __post_init__(self) -> None:
        _hex32(self.chain_id, "chain.chain_id")
        _count(self.segment, "chain.segment")
        _count(self.seq, "chain.seq")
        if self.segment > self.seq:
            raise _schema_error("chain.segment")
        if self.seq == 0:
            if self.prev_record_digest is not None:
                raise _schema_error("chain.prev_record_digest")
        else:
            _hex64(self.prev_record_digest, "chain.prev_record_digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "prev_record_digest": self.prev_record_digest,
            "segment": self.segment,
            "seq": self.seq,
        }


def _position(value: object) -> ChainPosition:
    position = _exact_type(value, ChainPosition, StorageErrorCode.INPUT_TYPE_INVALID, "position")
    # Re-validate: a frozen dataclass can still be changed with object.__setattr__.
    return ChainPosition(position.chain_id, position.segment, position.seq, position.prev_record_digest)


@dataclass(frozen=True)
class PreviousSegment:
    segment: int
    last_seq: int
    last_record_digest: str

    def __post_init__(self) -> None:
        _count(self.segment, "previous_segment.segment")
        _count(self.last_seq, "previous_segment.last_seq")
        _hex64(self.last_record_digest, "previous_segment.last_record_digest")

    def to_dict(self) -> dict[str, Any]:
        return {"last_record_digest": self.last_record_digest, "last_seq": self.last_seq, "segment": self.segment}


@dataclass(frozen=True)
class RecoveryInfo:
    """Counts and digests only; never bytes from a damaged region."""

    damaged_segment: int
    damage_kind: DamageKind
    last_valid_seq: int
    last_valid_record_digest: str
    discarded_bytes: int
    invalid_lines: int
    unconfirmed_seqs: tuple[int, ...]
    previous_anchor_seq: int | None = None
    previous_anchor_generation: int | None = None

    def __post_init__(self) -> None:
        _count(self.damaged_segment, "recovery.damaged_segment")
        if type(self.damage_kind) is not DamageKind:
            raise _schema_error("recovery.damage_kind")
        _count(self.last_valid_seq, "recovery.last_valid_seq")
        _hex64(self.last_valid_record_digest, "recovery.last_valid_record_digest")
        _count(self.discarded_bytes, "recovery.discarded_bytes")
        _count(self.invalid_lines, "recovery.invalid_lines")
        seqs = self.unconfirmed_seqs
        if type(seqs) is not tuple or len(seqs) > MAX_UNCONFIRMED_SEQS:
            raise _schema_error("recovery.unconfirmed_seqs")
        for index, seq in enumerate(seqs):
            _count(seq, "recovery.unconfirmed_seqs")
            if index and seq <= seqs[index - 1]:
                raise _schema_error("recovery.unconfirmed_seqs")
        anchor_fields = (self.previous_anchor_seq, self.previous_anchor_generation)
        for value, name in zip(anchor_fields, ("previous_anchor_seq", "previous_anchor_generation"), strict=True):
            if value is not None:
                _count(value, f"recovery.{name}")
        if self.damage_kind not in _ANCHOR_DAMAGE and anchor_fields != (None, None):
            raise _schema_error("recovery.previous_anchor_seq")

    def to_dict(self) -> dict[str, Any]:
        return {
            "damage_kind": self.damage_kind.value,
            "damaged_segment": self.damaged_segment,
            "discarded_bytes": self.discarded_bytes,
            "invalid_lines": self.invalid_lines,
            "last_valid_record_digest": self.last_valid_record_digest,
            "last_valid_seq": self.last_valid_seq,
            "previous_anchor_generation": self.previous_anchor_generation,
            "previous_anchor_seq": self.previous_anchor_seq,
            "unconfirmed_seqs": list(self.unconfirmed_seqs),
        }


@dataclass(frozen=True)
class SegmentHeader:
    """Typed view of a parsed ``segment_open`` body (all values already validated)."""

    reason: OpenReason
    created_at: str
    auth_key_id: str
    chain_key_id: str
    epoch: ProjectionEpoch
    previous_segment: PreviousSegment | None
    recovery: RecoveryInfo | None
    writer_version: str


def _epoch_dict(epoch: ProjectionEpoch) -> dict[str, Any]:
    return {
        "engine_ref_key_id": epoch.engine_ref_key_id,
        "engine_ref_mode": epoch.engine_ref_mode.value,
        "ref_key_id": epoch.ref_key_id,
    }


def _epoch(value: object, code: StorageErrorCode) -> ProjectionEpoch:
    epoch = _exact_type(value, ProjectionEpoch, code, "epoch")
    return _rebuilt_epoch(epoch.engine_ref_mode, epoch.ref_key_id, epoch.engine_ref_key_id)


def _rebuilt_epoch(mode: object, ref_key_id: object, engine_ref_key_id: object) -> ProjectionEpoch:
    failed = False
    try:
        epoch = ProjectionEpoch(mode, ref_key_id, engine_ref_key_id)  # type: ignore[arg-type]
    except AuditError:
        failed = True
    if failed:
        raise _schema_error("epoch")
    return epoch


def _segment_open_body(
    position: ChainPosition,
    created_at: object,
    reason: OpenReason,
    auth_key_id: object,
    chain_key_id: str,
    epoch: ProjectionEpoch,
    previous: PreviousSegment | None,
    recovery: RecoveryInfo | None,
    writer_version: object,
) -> dict[str, Any]:
    _timestamp(created_at, "body.created_at")
    _hex32(auth_key_id, "body.auth_key_id")
    _hex32(chain_key_id, "body.chain_key_id")
    if type(writer_version) is not str or _VERSION_RE.fullmatch(writer_version) is None:
        raise _schema_error("body.writer.rig_sentinel_version")
    genesis_position = position.segment == 0 and position.seq == 0
    if (reason is OpenReason.GENESIS) is not genesis_position:
        raise _schema_error("body.reason")
    if reason is OpenReason.GENESIS:
        if previous is not None or recovery is not None:
            raise _schema_error("body.previous_segment")
    else:
        if position.segment == 0 or previous is None:
            raise _schema_error("body.previous_segment")
        if previous.last_seq != position.seq - 1 or previous.last_record_digest != position.prev_record_digest:
            raise _schema_error("body.previous_segment")
        if reason is OpenReason.RECOVERY:
            if previous.segment >= position.segment:
                raise _schema_error("body.previous_segment.segment")
        elif previous.segment != position.segment - 1:
            raise _schema_error("body.previous_segment.segment")
    needs_recovery = reason in (OpenReason.RECOVERY, OpenReason.ANCHOR_REINITIALIZED)
    if needs_recovery is (recovery is None):
        raise _schema_error("body.recovery")
    if recovery is not None and previous is not None:
        allowed = _RECOVERY_DAMAGE if reason is OpenReason.RECOVERY else _ANCHOR_DAMAGE
        if recovery.damage_kind not in allowed:
            raise _schema_error("body.recovery.damage_kind")
        if recovery.last_valid_seq != previous.last_seq or (
            recovery.last_valid_record_digest != previous.last_record_digest
        ):
            raise _schema_error("body.recovery.last_valid_seq")
        if not previous.segment <= recovery.damaged_segment < position.segment:
            raise _schema_error("body.recovery.damaged_segment")
    return {
        "auth_key_id": auth_key_id,
        "chain_key_id": chain_key_id,
        "created_at": created_at,
        "epoch": _epoch_dict(epoch),
        "previous_segment": None if previous is None else previous.to_dict(),
        "reason": reason.value,
        "recovery": None if recovery is None else recovery.to_dict(),
        "segment": position.segment,
        "writer": {"record_schema": RECORD_SCHEMA, "rig_sentinel_version": writer_version},
    }


def _segment_close_body(position: ChainPosition, record_count: object, reason: CloseReason) -> dict[str, Any]:
    if position.seq == 0:
        raise _schema_error("chain.seq")
    _count(record_count, "body.record_count", 2, position.seq + 1)
    return {"last_seq": position.seq - 1, "reason": reason.value, "record_count": record_count,
            "segment": position.segment}


def _checkpoint_marker_body(position: ChainPosition, checkpoint_seq: object, digest: object) -> dict[str, Any]:
    if position.seq == 0:
        raise _schema_error("chain.seq")
    _count(checkpoint_seq, "body.checkpoint_seq", 0, position.seq - 1)
    _hex64(digest, "body.checkpoint_record_digest")
    return {"checkpoint_record_digest": digest, "checkpoint_seq": checkpoint_seq}


# --- Line assembly (splice with proof) -----------------------------------------------------


def _record_preimage(kind: RecordKind, body: object, position: ChainPosition, envelope_digest: str | None) -> dict:
    return {
        "body": body,
        "chain": position.to_dict(),
        "envelope": None if envelope_digest is None else _SPLICE_PLACEHOLDER,
        "envelope_digest": envelope_digest,
        "kind": kind.value,
        "record_schema": RECORD_SCHEMA,
    }


def _splice(template: bytes, raw: bytes | None) -> tuple[bytes, int]:
    """Replace the single placeholder string with ``raw``; return the bytes and its offset."""
    if raw is None:
        return template, -1
    marker = b'"' + _SPLICE_PLACEHOLDER.encode("ascii") + b'"'
    if template.count(marker) != 1:
        raise StorageError(StorageErrorCode.INTERNAL_INVARIANT, "splice")
    offset = template.index(marker)
    return template[:offset] + raw + template[offset + len(marker):], offset


def _assemble(
    kind: RecordKind, body: object, position: ChainPosition, chain_key: AuditKey, raw: bytes | None
) -> bytes:
    envelope_digest = None if raw is None else _sha256_hex(ENVELOPE_IN_RECORD_DOMAIN, raw)
    preimage = _record_preimage(kind, body, position, envelope_digest)
    digest_input, _ = _splice(canonical_json(preimage), raw)
    record_digest = _sha256_hex(RECORD_DIGEST_DOMAIN, digest_input)
    chain_auth = {
        "algorithm": CHAIN_MAC_ALGORITHM,
        "key_id": chain_key.key_id,
        "mac": _keyed_mac(chain_key, CHAIN_MAC_DOMAIN, record_digest.encode("ascii")),
    }
    record = dict(preimage, chain_auth=chain_auth, record_digest=record_digest)
    text, offset = _splice(canonical_json(record), raw)
    line = text + _NEWLINE
    if len(line) > MAX_RECORD_LINE_BYTES:
        raise StorageError(StorageErrorCode.LINE_TOO_LONG, "record")
    _prove_line(text, raw, offset)
    return line


def _prove_line(text: bytes, raw: bytes | None, offset: int) -> None:
    """The whole line must be canonical JSON under the bounded parser, and the spliced region
    must be exactly ``raw``. Any failure means nothing may be written."""
    failed = False
    try:
        strict_canonical_loads(text, max_bytes=MAX_RECORD_LINE_BYTES - 1)
    except StorageError:
        failed = True
    if failed or (raw is not None and text[offset:offset + len(raw)] != raw):
        raise StorageError(StorageErrorCode.INTERNAL_INVARIANT, "splice")


# --- P2 boundary -----------------------------------------------------------------------------


def revalidate_envelope_bytes(
    raw: object, *, auth_key: AuditKey, epoch: ProjectionEpoch, readable_labels: object = None
) -> bytes:
    """Re-prove that ``raw`` is a persistable P2 projection envelope; return the gate's bytes.

    ``raw`` is parsed under the bounded parser, rebuilt with the context-free P2 parser, and
    re-checked by :func:`check_projection_persistable` with the keyring ``{K_auth.key_id: K_auth}``
    and the explicit ``epoch``. The gate's canonical output must equal ``raw`` byte for byte.
    Every failure is ``PROJECTION_REJECTED`` (the path names the gate code, never content).
    """
    if type(raw) is not bytes or len(raw) > MAX_ENVELOPE_BYTES:
        raise StorageError(StorageErrorCode.PROJECTION_REJECTED, "size")
    path = ""
    tree: Any = None
    try:
        tree = strict_canonical_loads(raw, max_bytes=MAX_ENVELOPE_BYTES)
    except StorageError as error:
        path = f"parse:{error.code.value}"
    if path:
        raise StorageError(StorageErrorCode.PROJECTION_REJECTED, path)
    envelope: Any = None
    try:
        envelope = projection_envelope_from_dict(tree)
    except Exception:  # closed P2 schema refused it; BaseException propagates
        path = "schema"
    if path:
        raise StorageError(StorageErrorCode.PROJECTION_REJECTED, path)
    result = check_projection_persistable(
        envelope, {auth_key.key_id: auth_key}, readable_labels=readable_labels, expected_epoch=epoch
    )
    if not result.ok or result.validated is None:
        raise StorageError(StorageErrorCode.PROJECTION_REJECTED, f"gate:{result.code.value}")
    canonical = result.validated.canonical
    if type(canonical) is not bytes or canonical != raw:
        raise StorageError(StorageErrorCode.PROJECTION_REJECTED, "bytes")
    return canonical


def _capture_bytes(validated: ValidatedProjection) -> object:
    """Read the carrier's bytes once; nothing else on the carrier is ever used."""
    return object.__getattribute__(validated, "canonical")


# --- Builders --------------------------------------------------------------------------------


def build_event_record(
    validated: object,
    *,
    auth_key: object,
    epoch: object,
    position: object,
    chain_key: object,
    readable_labels: object = None,
) -> bytes:
    """Build one ``event`` line carrying the exact, re-validated projection envelope bytes."""
    auth = _require_auth_key(auth_key)
    chain = require_chain_key(chain_key)
    require_independent_keys(chain, auth)
    checked_epoch = _epoch(epoch, StorageErrorCode.INPUT_TYPE_INVALID)
    _require_independent_of_epoch(checked_epoch, chain, auth)  # H1-03: neither may be K_ref or K_eref
    checked_position = _position(position)
    if checked_position.seq == 0:
        raise _schema_error("chain.seq")  # seq 0 is always the genesis segment_open
    if type(validated) is not ValidatedProjection:
        raise StorageError(StorageErrorCode.NOT_VALIDATED, "validated")
    raw = _capture_bytes(validated)
    canonical = revalidate_envelope_bytes(
        raw, auth_key=auth, epoch=checked_epoch, readable_labels=readable_labels
    )
    return _assemble(RecordKind.EVENT, None, checked_position, chain, canonical)


def build_segment_open(
    *,
    position: object,
    created_at: object,
    reason: object,
    auth_key_id: object,
    chain_key: object,
    epoch: object,
    previous_segment: object,
    recovery: object,
    writer_version: object,
) -> bytes:
    chain = require_chain_key(chain_key)
    checked_position = _position(position)
    checked_reason = _exact_type(reason, OpenReason, StorageErrorCode.INPUT_TYPE_INVALID, "reason")
    checked_epoch = _epoch(epoch, StorageErrorCode.INPUT_TYPE_INVALID)
    _require_independent_of_epoch(checked_epoch, chain)  # H1-03
    previous = None if previous_segment is None else _rebuilt_previous(
        _exact_type(previous_segment, PreviousSegment, StorageErrorCode.INPUT_TYPE_INVALID, "previous_segment"))
    checked_recovery = None if recovery is None else _rebuilt_recovery(
        _exact_type(recovery, RecoveryInfo, StorageErrorCode.INPUT_TYPE_INVALID, "recovery"))
    body = _segment_open_body(
        checked_position, created_at, checked_reason, auth_key_id, chain.key_id, checked_epoch,
        previous, checked_recovery, writer_version,
    )
    return _assemble(RecordKind.SEGMENT_OPEN, body, checked_position, chain, None)


def _rebuilt_previous(value: PreviousSegment) -> PreviousSegment:
    return PreviousSegment(value.segment, value.last_seq, value.last_record_digest)


def _rebuilt_recovery(value: RecoveryInfo) -> RecoveryInfo:
    return RecoveryInfo(
        value.damaged_segment, value.damage_kind, value.last_valid_seq, value.last_valid_record_digest,
        value.discarded_bytes, value.invalid_lines, value.unconfirmed_seqs, value.previous_anchor_seq,
        value.previous_anchor_generation,
    )


def build_segment_close(*, position: object, chain_key: object, record_count: object, reason: object) -> bytes:
    chain = require_chain_key(chain_key)
    checked_position = _position(position)
    checked_reason = _exact_type(reason, CloseReason, StorageErrorCode.INPUT_TYPE_INVALID, "reason")
    body = _segment_close_body(checked_position, record_count, checked_reason)
    return _assemble(RecordKind.SEGMENT_CLOSE, body, checked_position, chain, None)


def build_checkpoint_marker(
    *, position: object, chain_key: object, checkpoint_seq: object, checkpoint_record_digest: object
) -> bytes:
    chain = require_chain_key(chain_key)
    checked_position = _position(position)
    body = _checkpoint_marker_body(checked_position, checkpoint_seq, checkpoint_record_digest)
    return _assemble(RecordKind.CHECKPOINT_MARKER, body, checked_position, chain, None)


# --- Parsing stored lines ----------------------------------------------------------------------


_RECORD_FIELDS = frozenset(
    {"body", "chain", "chain_auth", "envelope", "envelope_digest", "kind", "record_digest", "record_schema"}
)
_CHAIN_FIELDS = frozenset({"chain_id", "prev_record_digest", "segment", "seq"})
_CHAIN_AUTH_FIELDS = frozenset({"algorithm", "key_id", "mac"})
_OPEN_FIELDS = frozenset(
    {"auth_key_id", "chain_key_id", "created_at", "epoch", "previous_segment", "reason", "recovery",
     "segment", "writer"}
)
_EPOCH_FIELDS = frozenset({"engine_ref_key_id", "engine_ref_mode", "ref_key_id"})
_PREVIOUS_FIELDS = frozenset({"last_record_digest", "last_seq", "segment"})
_RECOVERY_FIELDS = frozenset(
    {"damage_kind", "damaged_segment", "discarded_bytes", "invalid_lines", "last_valid_record_digest",
     "last_valid_seq", "previous_anchor_generation", "previous_anchor_seq", "unconfirmed_seqs"}
)
_WRITER_FIELDS = frozenset({"record_schema", "rig_sentinel_version"})
_CLOSE_FIELDS = frozenset({"last_seq", "reason", "record_count", "segment"})
_MARKER_FIELDS = frozenset({"checkpoint_record_digest", "checkpoint_seq"})


@dataclass(frozen=True)
class ParsedRecord:
    """A structurally valid, digest-consistent record line. **Not authenticated.**

    Use :func:`verify_record_mac` for the chain MAC and, for events, re-apply the P2 gate to
    ``envelope_bytes`` (see :mod:`rig_sentinel.audit.chainverify`).

    Operator-side object: ``envelope_bytes``, ``body``, ``header`` and ``mac`` are left out of
    ``repr()`` (H1-04), so logging a parsed record never prints projection content or tags.
    """

    kind: RecordKind
    chain_id: str
    segment: int
    seq: int
    prev_record_digest: str | None
    body: dict[str, Any] | None = field(repr=False)
    header: SegmentHeader | None = field(repr=False)
    envelope_bytes: bytes | None = field(repr=False)
    envelope_digest: str | None = field()
    record_digest: str = field()
    chain_key_id: str = field()
    mac: str = field(repr=False)


def _load_line(data: object, max_bytes: int) -> Any:
    if type(data) is not bytes:
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "line")
    if len(data) > max_bytes:
        raise StorageError(StorageErrorCode.LINE_TOO_LONG, "line")
    if not data.endswith(_NEWLINE):
        raise StorageError(StorageErrorCode.PARTIAL_LINE, "line")
    return strict_canonical_loads(data[:-1], max_bytes=max_bytes - 1)


def _schema_guard(build: Any, *args: Any) -> Any:
    """Run a schema constructor; turn any refusal into a context-free SCHEMA_INVALID."""
    path: str | None = None
    result: Any = None
    try:
        result = build(*args)
    except StorageError as error:
        path = error.path
    except (AuditError, ValueError, TypeError, KeyError):
        path = "body"
    if path is not None:
        raise _schema_error(path)
    return result


def _parse_header(position: ChainPosition, data: dict[str, Any]) -> tuple[SegmentHeader, dict[str, Any]]:
    body = _table(data, _OPEN_FIELDS, "body")
    epoch_data = _table(body["epoch"], _EPOCH_FIELDS, "body.epoch")
    mode = _enum_value(ProjectionProfile, epoch_data["engine_ref_mode"], "body.epoch.engine_ref_mode")
    epoch = _rebuilt_epoch(mode, epoch_data["ref_key_id"], epoch_data["engine_ref_key_id"])
    previous = None
    if body["previous_segment"] is not None:
        prev_data = _table(body["previous_segment"], _PREVIOUS_FIELDS, "body.previous_segment")
        previous = PreviousSegment(prev_data["segment"], prev_data["last_seq"], prev_data["last_record_digest"])
    recovery = None
    if body["recovery"] is not None:
        rec_data = _table(body["recovery"], _RECOVERY_FIELDS, "body.recovery")
        seqs = rec_data["unconfirmed_seqs"]
        if type(seqs) is not list:
            raise _schema_error("body.recovery.unconfirmed_seqs")
        recovery = RecoveryInfo(
            rec_data["damaged_segment"],
            _enum_value(DamageKind, rec_data["damage_kind"], "body.recovery.damage_kind"),
            rec_data["last_valid_seq"],
            rec_data["last_valid_record_digest"],
            rec_data["discarded_bytes"],
            rec_data["invalid_lines"],
            tuple(seqs),
            rec_data["previous_anchor_seq"],
            rec_data["previous_anchor_generation"],
        )
    writer = _table(body["writer"], _WRITER_FIELDS, "body.writer")
    if writer["record_schema"] != RECORD_SCHEMA:
        raise _schema_error("body.writer.record_schema")
    reason = _enum_value(OpenReason, body["reason"], "body.reason")
    rebuilt = _segment_open_body(
        position, body["created_at"], reason, body["auth_key_id"], body["chain_key_id"], epoch, previous,
        recovery, writer["rig_sentinel_version"],
    )
    if rebuilt != body:
        raise _schema_error("body")
    header = SegmentHeader(
        reason=reason, created_at=body["created_at"], auth_key_id=body["auth_key_id"],
        chain_key_id=body["chain_key_id"], epoch=epoch, previous_segment=previous, recovery=recovery,
        writer_version=writer["rig_sentinel_version"],
    )
    return header, rebuilt


def _parse_body(kind: RecordKind, position: ChainPosition, data: object) -> tuple[Any, SegmentHeader | None]:
    if kind is RecordKind.EVENT:
        if data is not None:
            raise _schema_error("body")
        return None, None
    if kind is RecordKind.SEGMENT_OPEN:
        header, body = _parse_header(position, data)  # type: ignore[arg-type]
        return body, header
    if kind is RecordKind.SEGMENT_CLOSE:
        body = _table(data, _CLOSE_FIELDS, "body")
        reason = _enum_value(CloseReason, body["reason"], "body.reason")
        rebuilt = _segment_close_body(position, body["record_count"], reason)
    else:
        body = _table(data, _MARKER_FIELDS, "body")
        rebuilt = _checkpoint_marker_body(position, body["checkpoint_seq"], body["checkpoint_record_digest"])
    if rebuilt != body:
        raise _schema_error("body")
    return rebuilt, None


def _envelope_region(text: bytes, record: dict[str, Any]) -> bytes:
    """The exact envelope bytes inside a canonical event line, located by its fixed prefix."""
    prefix = canonical_json(
        {"body": None, "chain": record["chain"], "chain_auth": record["chain_auth"]}
    )[:-1] + b',"envelope":'
    envelope = canonical_json(record["envelope"])
    if not text.startswith(prefix) or text[len(prefix):len(prefix) + len(envelope)] != envelope:
        raise _schema_error("envelope")
    return envelope


def parse_record(line: object) -> ParsedRecord:
    """Parse one stored record line (bounded, strict, closed schema, digests). No MAC check."""
    record = _load_line(line, MAX_RECORD_LINE_BYTES)
    text: bytes = line[:-1]  # type: ignore[index]
    record = _table(record, _RECORD_FIELDS, "record")
    if record["record_schema"] != RECORD_SCHEMA:
        raise _schema_error("record_schema")
    kind = _enum_value(RecordKind, record["kind"], "kind")
    chain = _table(record["chain"], _CHAIN_FIELDS, "chain")
    position = _schema_guard(
        ChainPosition, chain["chain_id"], chain["segment"], chain["seq"], chain["prev_record_digest"]
    )
    chain_auth = _table(record["chain_auth"], _CHAIN_AUTH_FIELDS, "chain_auth")
    if chain_auth["algorithm"] != CHAIN_MAC_ALGORITHM:
        raise _schema_error("chain_auth.algorithm")
    key_id = _hex32(chain_auth["key_id"], "chain_auth.key_id")
    mac = _hex64(chain_auth["mac"], "chain_auth.mac")
    record_digest = _hex64(record["record_digest"], "record_digest")
    body, header = _schema_guard(_parse_body, kind, position, record["body"])

    envelope_bytes: bytes | None = None
    envelope_digest: str | None = None
    if kind is RecordKind.EVENT:
        if type(record["envelope"]) is not dict or position.seq == 0:
            raise _schema_error("envelope")
        envelope_digest = _hex64(record["envelope_digest"], "envelope_digest")
        envelope_bytes = _envelope_region(text, record)
        if len(envelope_bytes) > MAX_ENVELOPE_BYTES:
            raise _schema_error("envelope")
        if not hmac.compare_digest(_sha256_hex(ENVELOPE_IN_RECORD_DOMAIN, envelope_bytes), envelope_digest):
            raise StorageError(StorageErrorCode.DIGEST_MISMATCH, "envelope_digest")
    elif record["envelope"] is not None or record["envelope_digest"] is not None:
        raise _schema_error("envelope")

    preimage = {key: value for key, value in record.items() if key not in ("record_digest", "chain_auth")}
    if not hmac.compare_digest(_sha256_hex(RECORD_DIGEST_DOMAIN, canonical_json(preimage)), record_digest):
        raise StorageError(StorageErrorCode.DIGEST_MISMATCH, "record_digest")
    return ParsedRecord(
        kind=kind, chain_id=position.chain_id, segment=position.segment, seq=position.seq,
        prev_record_digest=position.prev_record_digest, body=body, header=header,
        envelope_bytes=envelope_bytes, envelope_digest=envelope_digest, record_digest=record_digest,
        chain_key_id=key_id, mac=mac,
    )


def verify_record_mac(parsed: object, chain_key: object) -> bool:
    """True only if ``parsed`` names this K_chain and its chain MAC verifies under it."""
    if type(parsed) is not ParsedRecord:
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "parsed")
    key = require_chain_key(chain_key)
    expected = _keyed_mac(key, CHAIN_MAC_DOMAIN, parsed.record_digest.encode("ascii"))
    return hmac.compare_digest(expected, parsed.mac) and parsed.chain_key_id == key.key_id


# --- Anchors (contents of the future .seq_anchor file; never written here) ------------------


_ANCHOR_FIELDS = frozenset(
    {"anchor_schema", "auth_key_id", "chain_id", "chain_key_id", "generation", "mac", "record_digest", "segment",
     "seq"}
)


@dataclass(frozen=True)
class Anchor:
    chain_id: str
    segment: int
    seq: int
    record_digest: str
    auth_key_id: str
    chain_key_id: str
    generation: int


def _anchor_body(
    chain_id: object, segment: object, seq: object, record_digest: object, auth_key_id: object,
    chain_key_id: object, generation: object,
) -> dict[str, Any]:
    position_seq = _count(seq, "seq")
    if _count(segment, "segment") > position_seq:
        raise _schema_error("segment")
    return {
        "anchor_schema": ANCHOR_SCHEMA,
        "auth_key_id": _hex32(auth_key_id, "auth_key_id"),
        "chain_id": _hex32(chain_id, "chain_id"),
        "chain_key_id": _hex32(chain_key_id, "chain_key_id"),
        "generation": _count(generation, "generation"),
        "record_digest": _hex64(record_digest, "record_digest"),
        "segment": segment,
        "seq": seq,
    }


def build_anchor(
    *, chain_id: object, segment: object, seq: object, record_digest: object, auth_key_id: object,
    generation: object, chain_key: object,
) -> bytes:
    """Canonical anchor contents (one line, at most 1,024 bytes), MAC'd under K_chain."""
    key = require_chain_key(chain_key)
    body = _anchor_body(chain_id, segment, seq, record_digest, auth_key_id, key.key_id, generation)
    line = canonical_json(dict(body, mac=_keyed_mac(key, ANCHOR_MAC_DOMAIN, canonical_json(body)))) + _NEWLINE
    if len(line) > MAX_ANCHOR_BYTES:
        raise StorageError(StorageErrorCode.INTERNAL_INVARIANT, "anchor")
    return line


def verify_anchor(data: object, chain_keys: object) -> Anchor:
    """Parse and authenticate anchor contents; raise on any failure (each class its own code)."""
    keys = _require_chain_keyring(chain_keys)
    value = _table(_load_line(data, MAX_ANCHOR_BYTES), _ANCHOR_FIELDS, "anchor")
    if value["anchor_schema"] != ANCHOR_SCHEMA:
        raise _schema_error("anchor_schema")
    mac = _hex64(value["mac"], "mac")
    body = _anchor_body(
        value["chain_id"], value["segment"], value["seq"], value["record_digest"], value["auth_key_id"],
        value["chain_key_id"], value["generation"],
    )
    key = keys.get(body["chain_key_id"])
    if key is None:
        raise StorageError(StorageErrorCode.UNKNOWN_KEY, "chain_key_id")
    if not hmac.compare_digest(_keyed_mac(key, ANCHOR_MAC_DOMAIN, canonical_json(body)), mac):
        raise StorageError(StorageErrorCode.MAC_INVALID, "mac")
    return Anchor(
        chain_id=body["chain_id"], segment=body["segment"], seq=body["seq"], record_digest=body["record_digest"],
        auth_key_id=body["auth_key_id"], chain_key_id=body["chain_key_id"], generation=body["generation"],
    )


# --- Checkpoints (content-free; exported to custody in later stages) ---------------------------


_CHECKPOINT_FIELDS = frozenset(
    {"anchor_generation", "auth_key_id", "chain_id", "chain_key_id", "checkpoint_schema", "created_at", "mac",
     "record_digest", "segment", "seq"}
)


@dataclass(frozen=True)
class Checkpoint:
    chain_id: str
    segment: int
    seq: int
    record_digest: str
    created_at: str
    auth_key_id: str
    chain_key_id: str
    anchor_generation: int


def _checkpoint_body(
    chain_id: object, segment: object, seq: object, record_digest: object, created_at: object,
    auth_key_id: object, chain_key_id: object, anchor_generation: object,
) -> dict[str, Any]:
    position_seq = _count(seq, "seq")
    if _count(segment, "segment") > position_seq:
        raise _schema_error("segment")
    return {
        "anchor_generation": _count(anchor_generation, "anchor_generation"),
        "auth_key_id": _hex32(auth_key_id, "auth_key_id"),
        "chain_id": _hex32(chain_id, "chain_id"),
        "chain_key_id": _hex32(chain_key_id, "chain_key_id"),
        "checkpoint_schema": CHECKPOINT_SCHEMA,
        "created_at": _timestamp(created_at, "created_at"),
        "record_digest": _hex64(record_digest, "record_digest"),
        "segment": segment,
        "seq": seq,
    }


def build_checkpoint(
    *, chain_id: object, segment: object, seq: object, record_digest: object, created_at: object,
    auth_key_id: object, anchor_generation: object, chain_key: object,
) -> bytes:
    """Canonical checkpoint contents (at most 2,048 bytes), MAC'd under K_chain."""
    key = require_chain_key(chain_key)
    body = _checkpoint_body(
        chain_id, segment, seq, record_digest, created_at, auth_key_id, key.key_id, anchor_generation
    )
    line = canonical_json(dict(body, mac=_keyed_mac(key, CHECKPOINT_MAC_DOMAIN, canonical_json(body)))) + _NEWLINE
    if len(line) > MAX_CHECKPOINT_BYTES:
        raise StorageError(StorageErrorCode.INTERNAL_INVARIANT, "checkpoint")
    return line


def verify_checkpoint(data: object, chain_keys: object) -> Checkpoint:
    keys = _require_chain_keyring(chain_keys)
    value = _table(_load_line(data, MAX_CHECKPOINT_BYTES), _CHECKPOINT_FIELDS, "checkpoint")
    if value["checkpoint_schema"] != CHECKPOINT_SCHEMA:
        raise _schema_error("checkpoint_schema")
    mac = _hex64(value["mac"], "mac")
    body = _checkpoint_body(
        value["chain_id"], value["segment"], value["seq"], value["record_digest"], value["created_at"],
        value["auth_key_id"], value["chain_key_id"], value["anchor_generation"],
    )
    key = keys.get(body["chain_key_id"])
    if key is None:
        raise StorageError(StorageErrorCode.UNKNOWN_KEY, "chain_key_id")
    if not hmac.compare_digest(_keyed_mac(key, CHECKPOINT_MAC_DOMAIN, canonical_json(body)), mac):
        raise StorageError(StorageErrorCode.MAC_INVALID, "mac")
    return Checkpoint(
        chain_id=body["chain_id"], segment=body["segment"], seq=body["seq"], record_digest=body["record_digest"],
        created_at=body["created_at"], auth_key_id=body["auth_key_id"], chain_key_id=body["chain_key_id"],
        anchor_generation=body["anchor_generation"],
    )
