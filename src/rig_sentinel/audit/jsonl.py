"""Persistent local audit writer: :class:`LocalJsonlSink` (Genesis B2-M2-C3-H1).

Implements the founder-approved C3 architecture (``M2_C3_ARCHITECTURE_R2_1.md``, decisions D-C3-1 to
D-C3-13 and X-7 Option A). Section references ("A-n") point to that document.

* **Scope (D-C3-1):** a new chain (genesis) and a clean resume after a ``SHUTDOWN`` or ``SIZE`` close only.
  Every other on-disk state is refused with ``RECOVERY_REQUIRED`` (C4 owns recovery). Nothing is repaired,
  classified, quarantined, deleted or truncated here.
* **Filesystem:** only through the approved C2-C/C2-D primitives in :mod:`rig_sentinel.audit.safepath`
  (this module imports no ``os``). The writer lock is acquired before any write inside the chain directory,
  held for the writer's lifetime, verified before every protected operation together with the chain-directory
  identity (:meth:`AuditDirectory.verify_chain_named`) and the segment name (A-11), and released last.
* **Durability (D-C3-2):** every record is appended with one write, synced, and then anchored
  (``.seq_anchor``, one generation per record) before a ``STORED`` receipt exists (A-6.1).
* **Capacity (A-6.2):** seq, anchor-generation and segment limits are checked before any write, so a clean
  ``SHUTDOWN`` close always fits (invariant R). Refusals leave the writer READY and write nothing.
* **Failure:** a refusal before the first write call returns ``REJECTED`` (or raises for non-append calls)
  and keeps the writer READY. Any failure at or after a write call, and any lock or identity failure, seals
  the writer (no further write call is ever made) and raises. ``close()`` then releases the lock.
* **Windows** (and incapable POSIX) writers are refused before any I/O (D-C3-11).

Errors are :class:`StorageError` codes with fixed labels, never content, paths or ``OSError`` text, and are
raised without exception context. Production enablement is out of scope until C4 exists.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from rig_sentinel.audit import safepath
from rig_sentinel.audit.bounded_json import strict_canonical_loads
from rig_sentinel.audit.chainverify import MAX_RECORDS_LIMIT, ChainStatus, verify_chain
from rig_sentinel.audit.keyfile import KeySet
from rig_sentinel.audit.keys import AuditKey, KeyPurpose
from rig_sentinel.audit.projection import ProjectionEpoch, projection_envelope_from_dict
from rig_sentinel.audit.records import (
    MAX_ANCHOR_BYTES,
    MAX_POSITION,
    MAX_RECORD_LINE_BYTES,
    ChainPosition,
    CloseReason,
    OpenReason,
    ParsedRecord,
    PreviousSegment,
    RecordKind,
    build_anchor,
    build_checkpoint,
    build_checkpoint_marker,
    build_event_record,
    build_segment_close,
    build_segment_open,
    key_matches_epoch,
    new_chain_id,
    parse_record,
    require_independent_keys,
    verify_anchor,
    verify_record_mac,
)
from rig_sentinel.audit.safepath import (
    ANCHOR_NAME,
    ANCHOR_TEMP_NAME,
    MAX_FILE_BYTES,
    AuditDirectory,
    Durability,
    check_chain_directory_name,
)
from rig_sentinel.audit.storage_errors import StorageError, StorageErrorCode
from rig_sentinel.audit.validation import MAX_ENVELOPE_BYTES

__all__ = [
    "CLOSE_RESERVE",
    "DEFAULT_SEGMENT_MAX_BYTES",
    "DEFAULT_SEGMENT_MAX_RECORDS",
    "MIN_SEGMENT_BYTES",
    "MIN_SEGMENT_RECORDS",
    "WRITER_VERSION",
    "AnchorState",
    "LocalJsonlSink",
    "ReceiptStatus",
    "SinkLimits",
    "SinkState",
    "StorageReceipt",
]

WRITER_VERSION = "0.1.0"
CLOSE_RESERVE = MAX_RECORD_LINE_BYTES  # the largest line any C1 builder returns, incl. segment_close (A-7)
MIN_SEGMENT_BYTES = 3 * MAX_RECORD_LINE_BYTES  # open + one maximal record + the close reserve (A-7 rule 4)
MIN_SEGMENT_RECORDS = 3  # open + one record + close
DEFAULT_SEGMENT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_SEGMENT_MAX_RECORDS = 1_000_000
_LOCK_NAME = ".writer.lock"
_SEGMENT_RE = re.compile(r"seg-(0|[1-9][0-9]{0,15})\.jsonl")
_QUARANTINE_RE = re.compile(r"\.seq_anchor\.q[0-7]")
_CHAIN_ID_RE = re.compile(r"[0-9a-f]{32}")
_TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
_READ_CHUNK = 1 << 20


class SinkState(StrEnum):
    OPENING = "opening"
    READY = "ready"
    SEALED = "sealed"  # absorbing: no further write call is ever made
    CLOSED = "closed"  # terminal


class ReceiptStatus(StrEnum):
    STORED = "stored"
    REJECTED = "rejected"


class AnchorState(StrEnum):
    COMMITTED = "committed"


@dataclass(frozen=True)
class StorageReceipt:
    """What the writer did with one record. No content, paths or key material."""

    status: ReceiptStatus
    code: StorageErrorCode | None
    detail: str
    segment: int | None
    seq: int | None
    record_digest: str | None
    durability: Durability | None
    anchor: AnchorState | None

    @property
    def stored(self) -> bool:
        return self.status is ReceiptStatus.STORED


def _rejected(code: StorageErrorCode, detail: str) -> StorageReceipt:
    return StorageReceipt(ReceiptStatus.REJECTED, code, detail, None, None, None, None, None)


@dataclass(frozen=True)
class SinkLimits:
    """Segment limits (D-C3-8). Exact ``int`` values only; validated at construction."""

    segment_max_bytes: int = DEFAULT_SEGMENT_MAX_BYTES
    segment_max_records: int = DEFAULT_SEGMENT_MAX_RECORDS

    def __post_init__(self) -> None:
        size, records = self.segment_max_bytes, self.segment_max_records
        if type(size) is not int or not MIN_SEGMENT_BYTES <= size <= MAX_FILE_BYTES:
            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "limits:segment_max_bytes")
        if type(records) is not int or not MIN_SEGMENT_RECORDS <= records <= MAX_POSITION:
            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "limits:segment_max_records")

    @property
    def event_id_index_max(self) -> int:
        return self.segment_max_records


# --- Pure capacity predicates (A-6.2) -----------------------------------------------------------------


def _seq_capacity_ok(seq: int, reserve: int) -> bool:
    return seq + reserve <= MAX_POSITION


def _generation_capacity_ok(generation: int, reserve: int) -> bool:
    return generation + reserve <= MAX_POSITION


def _segment_capacity_ok(segment: int) -> bool:
    return segment + 1 <= MAX_POSITION


def _capacity_problem(seq: int, generation: int, segment: int, reserve: int, *, new_segment: bool) -> str | None:
    """The first failing capacity check, in the fixed order seq, generation, segment; ``None`` if all pass."""
    if not _seq_capacity_ok(seq, reserve):
        return "chain:seq"
    if not _generation_capacity_ok(generation, reserve):
        return "chain:generation"
    if new_segment and not _segment_capacity_ok(segment):
        return "chain:segment"
    return None


DIRECT_RESERVE = 2  # one record + the reserved SHUTDOWN close
SIZE_ROTATION_RESERVE = 4  # close + open + record + the reserved close
KEY_ROTATION_RESERVE = 3  # close + open + the reserved close
RESUME_RESERVE = 2  # WRITER_RESTART open + the reserved close


# --- Small pure helpers ----------------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _valid_timestamp(value: object) -> bool:
    if type(value) is not str or _TIMESTAMP_RE.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def _valid_chain_id(value: object) -> bool:
    return type(value) is str and _CHAIN_ID_RE.fullmatch(value) is not None


def _weakest(*levels: Durability) -> Durability:
    return Durability.FULLFSYNC if all(level is Durability.FULLFSYNC for level in levels) else Durability.FSYNC


def _segment_name(number: int) -> str:
    return f"seg-{number}.jsonl"


def _require_epoch_independent(epoch: ProjectionEpoch, *keys: AuditKey) -> None:
    shared = False
    for key in keys:
        shared = key_matches_epoch(key, epoch) | shared
    if shared:
        raise StorageError(StorageErrorCode.KEYS_NOT_INDEPENDENT, "epoch")


def _require_key(value: object, purpose: KeyPurpose, label: str) -> AuditKey:
    if type(value) is not AuditKey:
        raise StorageError(StorageErrorCode.KEY_INVALID, label)
    if value.purpose is not purpose:
        raise StorageError(StorageErrorCode.KEY_PURPOSE_MISMATCH, label)
    return value


def _event_id(line: bytes) -> str:
    """The event id from the line's re-validated envelope bytes; never from the carrier (A-9)."""
    parsed = parse_record(line)
    raw = parsed.envelope_bytes
    if type(raw) is not bytes:
        raise StorageError(StorageErrorCode.INTERNAL_INVARIANT, "event:id")
    tree = strict_canonical_loads(raw, max_bytes=MAX_ENVELOPE_BYTES)
    envelope = projection_envelope_from_dict(tree)
    value = envelope.projection.audit.event_id
    if type(value) is not str or _CHAIN_ID_RE.fullmatch(value) is None:
        raise StorageError(StorageErrorCode.INTERNAL_INVARIANT, "event:id")
    return value


def _event_id_or_none(line: bytes) -> str | None:
    found: str | None = None
    try:
        found = _event_id(line)
    except Exception:  # noqa: BLE001 - any refusal is an internal invariant breach (A-9); BaseException propagates
        found = None
    return found


class _Refusal(Exception):
    """Internal: a refusal before any write call. Never escapes this module."""

    def __init__(self, code: StorageErrorCode, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _try_build(build: Any, **kwargs: Any) -> tuple[bytes | None, StorageError | None]:
    """Run a pure C1 builder; a refusal is returned, never raised (so no exception context is chained)."""
    line: bytes | None = None
    problem: StorageError | None = None
    try:
        line = build(**kwargs)
    except StorageError as error:
        problem = error
    return line, problem


def _digest_of(line: bytes) -> str:
    return parse_record(line).record_digest


# --- The writer ----------------------------------------------------------------------------------------


class LocalJsonlSink:
    """The C3 persistent writer for one chain (POSIX only). Obtain it from :meth:`create_chain` or
    :meth:`resume_chain`; use it as a context manager. Not picklable or copyable; ``repr`` shows the state only.
    """

    __slots__ = (
        "_audit", "_auth", "_busy", "_chain", "_chain_id", "_chain_key", "_clock", "_epoch", "_generation",
        "_index", "_last_timestamp", "_limits", "_lock", "_prev_digest", "_readable_labels", "_records_in_segment",
        "_ref", "_seg", "_segment", "_seq", "_state",
    )

    def __init__(self, *, _token: object, audit: AuditDirectory, keys: KeySet, epoch: ProjectionEpoch,
                 limits: SinkLimits, clock: Any, readable_labels: object) -> None:
        if _token is not _CONSTRUCT:
            raise TypeError("use LocalJsonlSink.create_chain or LocalJsonlSink.resume_chain")
        self._audit = audit
        self._auth: AuditKey = keys.auth
        self._chain_key: AuditKey = keys.chain
        self._ref: AuditKey | None = keys.ref
        self._epoch = epoch
        self._limits = limits
        self._clock = clock
        self._readable_labels = readable_labels
        self._busy = threading.Lock()
        self._state = SinkState.OPENING
        self._chain: Any = None
        self._lock: Any = None
        self._seg: Any = None
        self._chain_id = ""
        self._seq = -1  # seq of the last committed record (-1: none yet)
        self._prev_digest: str | None = None
        self._generation = 0  # generation of the last written anchor (0: none yet)
        self._segment = 0
        self._records_in_segment = 0
        self._index: set[str] = set()
        self._last_timestamp: str | None = None

    # -- construction -------------------------------------------------------------------------------------

    @classmethod
    def _prepare(cls, audit: object, keys: object, epoch: object, limits: object, clock: object,
                 readable_labels: object) -> LocalJsonlSink:
        """Every check that needs no I/O (A-5.1). Nothing is read or written if any fails."""
        if type(audit) is not AuditDirectory:
            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "audit")
        # L-2 (C3-H2), documented private coupling to C2-C. D-C3-11 requires refusing Windows and incapable POSIX
        # before *any* I/O, but C2-C exposes no public, side-effect-free capability query: its own refusals sit
        # inside I/O methods (``list_names`` reads on Windows before any write method would refuse). Adding a public
        # query would broaden the approved C2-C API, which the founder excluded. So C3 reads two package-private
        # facts, read-only and without calling any I/O: ``AuditDirectory._kind`` (set once at ``open``) and
        # ``safepath._lock_capable()`` (attribute-presence checks only; it calls no OS function). Both are pinned
        # by tests (Windows and incapable-POSIX refusal with an empty call log) and by C3 mutants M-PLAT-1/2.
        # If C2-C ever renames either, this line raises (AttributeError) before any I/O: it fails closed, not open.
        if audit._kind != "posix" or not safepath._lock_capable():
            raise StorageError(StorageErrorCode.UNSUPPORTED_PLATFORM, "sink:platform")  # D-C3-11: before any I/O
        if type(keys) is not KeySet:
            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "keys")
        chain_key = _require_key(keys.chain, KeyPurpose.CHAIN, "chain_key")
        auth_key = _require_key(keys.auth, KeyPurpose.AUTH, "auth_key")
        require_independent_keys(chain_key, auth_key, keys.ref)  # repeated: frozen dataclasses can be mutated
        if type(epoch) is not ProjectionEpoch:
            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "epoch")
        _require_epoch_independent(epoch, chain_key, auth_key)  # K_auth too: C1 headers check K_chain only
        given = SinkLimits() if limits is None else limits
        if type(given) is not SinkLimits:
            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "limits")
        checked_limits = SinkLimits(given.segment_max_bytes, given.segment_max_records)  # re-validated private copy
        if clock is not None and not callable(clock):
            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "clock")
        if readable_labels is not None and type(readable_labels) not in (set, frozenset):
            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "readable_labels")
        frozen_keys = KeySet(auth=auth_key, chain=chain_key, ref=keys.ref)
        return cls(_token=_CONSTRUCT, audit=audit, keys=frozen_keys, epoch=epoch, limits=checked_limits,
                   clock=_utc_now if clock is None else clock,
                   readable_labels=None if readable_labels is None else frozenset(readable_labels))

    @classmethod
    def create_chain(cls, audit: object, *, keys: object, epoch: object, limits: object = None,
                     clock: object = None, readable_labels: object = None) -> LocalJsonlSink:
        """Create a new chain (genesis, A-5.2) and return a READY writer holding its lock."""
        sink = cls._prepare(audit, keys, epoch, limits, clock, readable_labels)
        sink._open(sink._genesis)
        return sink

    def _open(self, procedure: Any) -> None:
        """Run genesis or resume; on any failure close handles and release the lock (nothing is removed)."""
        refusal: _Refusal | None = None
        try:
            procedure()
        except _Refusal as caught:
            refusal = caught
            self._abandon()
        except BaseException:
            self._abandon()
            raise
        if refusal is not None:
            raise StorageError(refusal.code, refusal.detail)

    @classmethod
    def resume_chain(cls, audit: object, chain_id: object, *, keys: object, epoch: object, limits: object = None,
                     clock: object = None, readable_labels: object = None, verify_on_resume: object = False,
                     verify_chain_keys: object = None, verify_auth_keys: object = None) -> LocalJsonlSink:
        """Resume a cleanly closed chain (A-5.3): a new segment after a ``SHUTDOWN`` or ``SIZE`` close.

        ``verify_on_resume=True`` also verifies every segment with :func:`verify_chain` first (D-C3-7);
        ``verify_chain_keys`` / ``verify_auth_keys`` may add retired keys ({key_id: key}) for that check.
        """
        if not _valid_chain_id(chain_id):
            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "chain:id")  # L-1: nothing is opened
        if verify_on_resume is not True and verify_on_resume is not False:
            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "verify_on_resume")
        sink = cls._prepare(audit, keys, epoch, limits, clock, readable_labels)
        rings = sink._verify_rings(verify_chain_keys, verify_auth_keys) if verify_on_resume else None
        sink._open(lambda: sink._resume(chain_id, rings))  # type: ignore[arg-type]
        return sink

    # -- hygiene ----------------------------------------------------------------------------------------------

    def __reduce_ex__(self, protocol: object) -> object:
        raise TypeError("LocalJsonlSink cannot be pickled")

    def __copy__(self) -> object:
        raise TypeError("LocalJsonlSink cannot be copied")

    def __deepcopy__(self, memo: object) -> object:
        raise TypeError("LocalJsonlSink cannot be copied")

    def __repr__(self) -> str:
        return f"LocalJsonlSink(state={self._state.value!r})"

    __str__ = __repr__

    def __enter__(self) -> LocalJsonlSink:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def state(self) -> SinkState:
        return self._state

    @property
    def chain_id(self) -> str:
        return self._chain_id

    # -- genesis (A-5.2) ----------------------------------------------------------------------------------------

    def _genesis(self) -> None:
        chain_id = new_chain_id()  # G1 (A1: secrets.token_hex(16))
        if not _valid_chain_id(chain_id):
            raise StorageError(StorageErrorCode.INTERNAL_INVARIANT, "chain:id")
        name = "chain-" + chain_id
        if check_chain_directory_name(name) != name:
            raise StorageError(StorageErrorCode.INTERNAL_INVARIANT, "chain:name")
        self._chain_id = chain_id
        if name in self._audit.list_names().names:  # G2: pre-creation absence check (A2)
            raise StorageError(StorageErrorCode.FILE_EXISTS, "chain:exists")
        self._chain = self._audit.open_chain(name, create=True)  # G3: approved, unchanged C2-C primitive (X-7 A)
        self._audit.sync()  # G4: the only other pre-lock write-path call
        self._lock = self._chain.acquire_writer_lock()  # G5
        self._lock.verify_held()  # G6 (matrix row G)
        self._audit.verify_chain_named(self._chain)
        listing = self._chain.list_names()  # G7: exactly the lock file (A5)
        if listing.names != (_LOCK_NAME,) or listing.other_entries != 0:
            raise StorageError(StorageErrorCode.RECOVERY_REQUIRED, "genesis:not-fresh")
        timestamp = self._next_timestamp()  # G8: build before creating the segment
        header, problem = _try_build(
            build_segment_open, position=ChainPosition(chain_id, 0, 0, None), created_at=timestamp,
            reason=OpenReason.GENESIS, auth_key_id=self._auth.key_id, chain_key=self._chain_key, epoch=self._epoch,
            previous_segment=None, recovery=None, writer_version=WRITER_VERSION)
        if problem is not None:
            raise problem
        self._state = SinkState.READY  # write-path failures from here on seal
        self._create_segment(0)  # G9 (rows C, CS)
        self._commit(header)  # type: ignore[arg-type]  # G10: generation 1
        self._last_timestamp = timestamp

    # -- clean resume (A-5.3) -------------------------------------------------------------------------------------

    def _verify_rings(self, chain_keys: object, auth_keys: object) -> tuple[dict[str, AuditKey], dict[str, AuditKey]]:
        chain_ring = {self._chain_key.key_id: self._chain_key}
        auth_ring = {self._auth.key_id: self._auth}
        for extra, ring, purpose, label in ((chain_keys, chain_ring, KeyPurpose.CHAIN, "verify_chain_keys"),
                                            (auth_keys, auth_ring, KeyPurpose.AUTH, "verify_auth_keys")):
            if extra is None:
                continue
            if type(extra) is not dict:
                raise StorageError(StorageErrorCode.KEYRING_INVALID, label)
            for key_id, key in extra.items():
                if type(key) is not AuditKey or key.purpose is not purpose or key.key_id != key_id:
                    raise StorageError(StorageErrorCode.KEYRING_INVALID, label)
                ring[key_id] = key
        return chain_ring, auth_ring

    def _resume(self, chain_id: str, rings: tuple[dict[str, AuditKey], dict[str, AuditKey]] | None) -> None:
        self._chain_id = chain_id
        self._chain = self._audit.open_chain("chain-" + chain_id)  # never create=True
        self._lock = self._chain.acquire_writer_lock()
        self._lock.verify_held()  # matrix row R
        self._audit.verify_chain_named(self._chain)
        last = self._resume_listing()
        self._lock.verify_held()  # matrix row R2: before the reads
        self._audit.verify_chain_named(self._chain)
        anchor = self._read_anchor(last)
        tail = self._read_tail(last)
        if (tail.chain_id, tail.segment, tail.seq, tail.record_digest) != (
                anchor.chain_id, anchor.segment, anchor.seq, anchor.record_digest):
            raise StorageError(StorageErrorCode.RECOVERY_REQUIRED, "resume:tail-anchor")
        if rings is not None:
            self._verify_everything(last, anchor, rings)
        timestamp = self._next_timestamp()
        self._generation = anchor.generation  # M-1: restored from the authenticated anchor; never reset
        self._seq = anchor.seq
        self._prev_digest = anchor.record_digest
        self._segment = last + 1
        position = ChainPosition(chain_id, last + 1, anchor.seq + 1, anchor.record_digest)
        header, problem = _try_build(
            build_segment_open, position=position, created_at=timestamp, reason=OpenReason.WRITER_RESTART,
            auth_key_id=self._auth.key_id, chain_key=self._chain_key, epoch=self._epoch,
            previous_segment=PreviousSegment(last, anchor.seq, anchor.record_digest), recovery=None,
            writer_version=WRITER_VERSION)
        if problem is not None:
            raise problem
        self._state = SinkState.READY
        self._create_segment(last + 1)
        self._commit(header)  # type: ignore[arg-type]
        self._last_timestamp = timestamp

    def _resume_listing(self) -> int:
        listing = self._chain.list_names()
        numbers: list[int] = []
        problem: str | None = None
        for name in listing.names:
            match = _SEGMENT_RE.fullmatch(name)
            if match is not None:
                numbers.append(int(match.group(1)))
            elif name == ANCHOR_TEMP_NAME or _QUARANTINE_RE.fullmatch(name) is not None:
                problem = "resume:pending-anchor"
            elif name not in (ANCHOR_NAME, _LOCK_NAME):
                problem = "resume:unexpected-entry"
        if listing.other_entries != 0:
            problem = problem or "resume:unexpected-entry"
        if ANCHOR_NAME not in listing.names:
            problem = problem or "resume:no-anchor"
        numbers.sort()
        if not numbers or numbers != list(range(len(numbers))):
            problem = problem or "resume:segments"
        if problem is not None:
            raise StorageError(StorageErrorCode.RECOVERY_REQUIRED, problem)
        last = numbers[-1]
        if last > MAX_POSITION:
            raise StorageError(StorageErrorCode.RECOVERY_REQUIRED, "resume:segments")
        return last

    def _read_member(self, name: str, max_size: int) -> bytes:
        """Read a whole member, bounded; prove it unchanged afterwards."""
        handle = self._chain.open_read(name, max_size=max_size)
        try:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = handle.read(min(_READ_CHUNK, max_size + 1))
                if not chunk:
                    break
                total += len(chunk)
                chunks.append(chunk)
            handle.verify_unchanged()
        finally:
            handle.close()
        data = b"".join(chunks)
        if len(data) != total or len(data) > max_size:
            raise StorageError(StorageErrorCode.RECOVERY_REQUIRED, "resume:read")
        return data

    def _guarded_read(self, name: str, max_size: int, label: str) -> bytes:
        data: bytes | None = None
        try:
            data = self._read_member(name, max_size)
        except StorageError:
            data = None
        if data is None:
            raise StorageError(StorageErrorCode.RECOVERY_REQUIRED, label)
        return data

    def _read_anchor(self, last: int) -> Any:
        data = self._guarded_read(ANCHOR_NAME, MAX_ANCHOR_BYTES, "resume:anchor")
        anchor: Any = None
        try:
            anchor = verify_anchor(data, {self._chain_key.key_id: self._chain_key})
        except StorageError:
            anchor = None
        if anchor is None or anchor.chain_id != self._chain_id or anchor.segment != last or anchor.generation < 1:
            raise StorageError(StorageErrorCode.RECOVERY_REQUIRED, "resume:anchor")
        problem = _capacity_problem(anchor.seq, anchor.generation, last, RESUME_RESERVE, new_segment=True)
        if problem == "chain:generation":
            problem = "anchor:generation"
        if problem is not None:
            raise StorageError(StorageErrorCode.ENTRY_LIMIT_EXCEEDED, problem)
        if anchor.auth_key_id != self._auth.key_id or anchor.chain_key_id != self._chain_key.key_id:
            raise StorageError(StorageErrorCode.KEY_CHANGE_REQUIRES_ROTATION, "resume:keys")
        return anchor

    def _read_tail(self, last: int) -> ParsedRecord:
        """The last complete line of ``seg-<last>`` must be an authenticated SHUTDOWN or SIZE close (A-5.3.5)."""
        data = self._guarded_read(_segment_name(last), self._limits.segment_max_bytes, "resume:segment")
        window = data[-(MAX_RECORD_LINE_BYTES + 1):]
        record: ParsedRecord | None = None
        if window.endswith(b"\n"):
            start = window.rfind(b"\n", 0, len(window) - 1)
            if start >= 0 or len(data) == len(window):
                line = window[start + 1:]
                try:
                    record = parse_record(line)
                except StorageError:
                    record = None
        if record is None or not verify_record_mac(record, self._chain_key):
            raise StorageError(StorageErrorCode.RECOVERY_REQUIRED, "resume:tail")
        reason = None if record.body is None else record.body.get("reason")
        if record.kind is not RecordKind.SEGMENT_CLOSE or reason not in (CloseReason.SHUTDOWN.value,
                                                                           CloseReason.SIZE.value):
            raise StorageError(StorageErrorCode.RECOVERY_REQUIRED, "resume:not-clean")
        return record

    def _verify_everything(self, last: int, anchor: Any,
                           rings: tuple[dict[str, AuditKey], dict[str, AuditKey]]) -> None:
        """``verify_on_resume``: the whole chain verifies and ends at the anchored record (D-C3-7)."""
        lines: list[bytes] = []
        for number in range(last + 1):
            data = self._guarded_read(_segment_name(number), self._limits.segment_max_bytes, "verify:segment")
            if data and not data.endswith(b"\n"):
                raise StorageError(StorageErrorCode.RECOVERY_REQUIRED, "verify:segment")
            lines.extend(piece + b"\n" for piece in data.split(b"\n")[:-1])
            if len(lines) > MAX_RECORDS_LIMIT:
                raise StorageError(StorageErrorCode.RECOVERY_REQUIRED, "verify:budget")
        report = verify_chain(lines, chain_keys=rings[0], auth_keys=rings[1], expected_chain_id=self._chain_id,
                              readable_labels=self._readable_labels, max_records=MAX_RECORDS_LIMIT)
        if (report.status is not ChainStatus.CHAIN_VALID or report.last_seq != anchor.seq
                or report.last_record_digest != anchor.record_digest):
            raise StorageError(StorageErrorCode.RECOVERY_REQUIRED, "verify:chain")

    # -- protected-operation checks (A-11) ---------------------------------------------------------------------

    def _check(self, *, lock: bool = True, directory: bool = True, segment: bool = True) -> None:
        """Matrix checks L, D, S immediately before a guarded call. Any failure seals before that call."""
        problem: StorageError | None = None
        try:
            if lock:
                self._lock.verify_held()
            if directory:
                self._audit.verify_chain_named(self._chain)
            if segment:
                self._seg.verify_name()
        except StorageError as error:
            problem = error
        if problem is not None:
            self._enter_sealed()
            raise problem

    def _enter_sealed(self) -> None:
        """Matrix row SE: no check and no write; close the segment handle and mark SEALED."""
        if self._state in (SinkState.OPENING, SinkState.READY):
            self._state = SinkState.SEALED
        seg, self._seg = self._seg, None
        if seg is not None:
            seg.close()

    def _write_failed(self, error: StorageError) -> StorageError:
        self._enter_sealed()
        return error

    def _next_timestamp(self) -> str:
        """Validated per use and monotonic within the session (A-13); nothing is built before this."""
        value = self._clock()
        if not _valid_timestamp(value) or (self._last_timestamp is not None and value < self._last_timestamp):
            raise _Refusal(StorageErrorCode.INPUT_TYPE_INVALID, "clock")
        return value  # type: ignore[no-any-return]

    # -- the commit protocol (A-6.1) ----------------------------------------------------------------------------

    def _commit(self, line: bytes, *, chain_key: AuditKey | None = None, auth_key_id: str | None = None,
                event_id: str | None = None) -> tuple[ParsedRecord, Durability]:
        key = self._chain_key if chain_key is None else chain_key
        auth_id = self._auth.key_id if auth_key_id is None else auth_key_id
        # W1: the record and its anchor must be representable (invariant R; unreachable when A-6.2 holds)
        if not (_seq_capacity_ok(self._seq, 1) and _generation_capacity_ok(self._generation, 1)):
            self._enter_sealed()
            raise StorageError(StorageErrorCode.INTERNAL_INVARIANT, "capacity:w1")
        self._check()  # matrix row W
        parsed: ParsedRecord | None = None
        anchor: bytes | None = None
        try:
            parsed = parse_record(line)
            if (parsed.chain_id, parsed.segment, parsed.seq, parsed.prev_record_digest) == (
                    self._chain_id, self._segment, self._seq + 1, self._prev_digest):
                anchor = build_anchor(chain_id=self._chain_id, segment=parsed.segment, seq=parsed.seq,
                                      record_digest=parsed.record_digest, auth_key_id=auth_id,
                                      generation=self._generation + 1, chain_key=key)
        except StorageError:
            anchor = None
        if parsed is None or anchor is None:
            self._enter_sealed()
            raise StorageError(StorageErrorCode.INTERNAL_INVARIANT, "commit:prepare")
        problem: StorageError | None = None
        data_level: Durability | None = None
        try:
            self._seg.append(line)  # W2: exactly one write
            self._lock.verify_held()  # W3 (row SS: L, S)
            self._seg.verify_name()
            data_level = self._seg.sync()
        except StorageError as error:
            problem = error
        if problem is not None:
            raise self._write_failed(problem)
        self._check(segment=False)  # W4 (row X: L, D)
        anchor_level: Durability | None = None
        failed = False
        try:
            anchor_level = self._chain.replace_atomically(ANCHOR_NAME, anchor, max_bytes=MAX_ANCHOR_BYTES)
        except StorageError:
            failed = True
        if failed:
            raise self._write_failed(StorageError(StorageErrorCode.ANCHOR_UPDATE_FAILED, "anchor:update"))
        # W5: only now advance the in-memory state (I3)
        self._seq = parsed.seq
        self._prev_digest = parsed.record_digest
        self._generation += 1
        self._records_in_segment += 1
        if event_id is not None:
            self._index.add(event_id)
        return parsed, _weakest(data_level, anchor_level)  # type: ignore[arg-type]

    def _create_segment(self, number: int) -> None:
        """Rows C and CS: a new segment (``O_EXCL``) and a directory sync. The old handle is already closed."""
        self._check(segment=False)  # row C
        problem: StorageError | None = None
        try:
            self._seg = self._chain.create_exclusive(_segment_name(number), max_size=self._limits.segment_max_bytes)
        except StorageError as error:
            problem = error
        if problem is not None:
            raise self._write_failed(problem)
        self._segment = number
        self._records_in_segment = 0
        self._index = set()
        self._check(segment=False)  # row CS
        try:
            self._chain.sync()
        except StorageError as error:
            problem = error
        if problem is not None:
            raise self._write_failed(problem)

    def _finish_segment(self) -> None:
        seg, self._seg = self._seg, None
        if seg is not None:
            seg.close()

    # -- serialisation (D-C3-5) ------------------------------------------------------------------------------------

    def _enter(self) -> bool:
        return self._busy.acquire(blocking=False)

    # -- append (A-6) -----------------------------------------------------------------------------------------------

    def append(self, validated: object) -> StorageReceipt:
        """Append one P2-validated projection. ``REJECTED`` receipts mean nothing was written."""
        if not self._enter():
            return _rejected(StorageErrorCode.SINK_BUSY, "sink:busy")
        try:
            if self._state is not SinkState.READY:
                return _rejected(StorageErrorCode.SINK_SEALED, "sink:" + self._state.value)
            try:
                return self._append(validated)
            except _Refusal as refusal:
                return _rejected(refusal.code, refusal.detail)
            except BaseException:
                self._enter_sealed()
                raise
        finally:
            self._busy.release()

    def _record_at(self, segment: int, seq: int, prev: str | None) -> ChainPosition:
        return ChainPosition(self._chain_id, segment, seq, prev)

    def _build_event(self, validated: object, position: ChainPosition) -> bytes:
        line, problem = _try_build(build_event_record, validated=validated, auth_key=self._auth, epoch=self._epoch,
                                   position=position, chain_key=self._chain_key,
                                   readable_labels=self._readable_labels)
        if problem is not None:
            raise _Refusal(problem.code, problem.path or "event")
        return line  # type: ignore[return-value]

    def _admits(self, line: bytes) -> bool:
        """P5: the record plus the close reserve fit the current segment, in bytes and in records (A-7)."""
        return (self._seg.size + len(line) + CLOSE_RESERVE <= self._limits.segment_max_bytes
                and self._records_in_segment + 2 <= self._limits.segment_max_records)

    def _append(self, validated: object) -> StorageReceipt:
        self._check()  # P1 (row A)
        line = self._build_event(validated, self._record_at(self._segment, self._seq + 1, self._prev_digest))  # P2
        event_id = _event_id_or_none(line)  # P3
        if event_id is None:
            raise _Refusal(StorageErrorCode.INTERNAL_INVARIANT, "event:id")
        if event_id in self._index:  # P4: before any admission or rotation decision
            raise _Refusal(StorageErrorCode.DUPLICATE_EVENT_ID, "event:duplicate")
        direct = self._admits(line)  # P5 selects the path
        reserve = DIRECT_RESERVE if direct else SIZE_ROTATION_RESERVE
        capacity = _capacity_problem(self._seq, self._generation, self._segment, reserve, new_segment=not direct)
        if capacity is not None:  # P6: before any write
            raise _Refusal(StorageErrorCode.ENTRY_LIMIT_EXCEEDED, capacity)
        if direct:  # P7
            parsed, level = self._commit(line, event_id=event_id)
        else:  # P8
            parsed, level = self._size_rotation(lambda position: self._build_event(validated, position), event_id)
        return StorageReceipt(ReceiptStatus.STORED, None, "", parsed.segment, parsed.seq, parsed.record_digest,
                              level, AnchorState.COMMITTED)

    # -- rotation (A-8) -----------------------------------------------------------------------------------------------

    def _prebuild_rotation(self, close_reason: CloseReason, open_reason: OpenReason, *, timestamp: str,
                           new_chain_key: AuditKey, new_auth_id: str,
                           new_epoch: ProjectionEpoch) -> tuple[bytes, bytes, str]:
        """A-8.1 steps 2-3: the close (old K_chain) and the open (new parameters), built before any write."""
        close_position = self._record_at(self._segment, self._seq + 1, self._prev_digest)
        close_line, problem = _try_build(build_segment_close, position=close_position, chain_key=self._chain_key,
                                         record_count=self._records_in_segment + 1, reason=close_reason)
        if problem is not None:
            raise _Refusal(problem.code, problem.path or "rotation:close")
        close_digest = _digest_of(close_line)  # type: ignore[arg-type]
        open_position = self._record_at(self._segment + 1, self._seq + 2, close_digest)
        open_line, problem = _try_build(
            build_segment_open, position=open_position, created_at=timestamp, reason=open_reason,
            auth_key_id=new_auth_id, chain_key=new_chain_key, epoch=new_epoch,
            previous_segment=PreviousSegment(self._segment, self._seq + 1, close_digest), recovery=None,
            writer_version=WRITER_VERSION)
        if problem is not None:
            raise _Refusal(problem.code, problem.path or "rotation:open")
        return close_line, open_line, _digest_of(open_line)  # type: ignore[arg-type]

    def _size_rotation(self, rebuild: Any, event_id: str | None,
                       timestamp: str | None = None) -> tuple[ParsedRecord, Durability]:
        """P8: close (SIZE), new segment, open (ROTATION), then the record rebuilt at the new position."""
        timestamp = self._next_timestamp() if timestamp is None else timestamp
        close_line, open_line, open_digest = self._prebuild_rotation(
            CloseReason.SIZE, OpenReason.ROTATION, timestamp=timestamp, new_chain_key=self._chain_key,
            new_auth_id=self._auth.key_id, new_epoch=self._epoch)
        record_line = rebuild(self._record_at(self._segment + 1, self._seq + 3, open_digest))
        if event_id is not None and _event_id_or_none(record_line) != event_id:
            raise _Refusal(StorageErrorCode.INTERNAL_INVARIANT, "event:id")
        fits = (len(open_line) + len(record_line) + CLOSE_RESERVE <= self._limits.segment_max_bytes
                and MIN_SEGMENT_RECORDS <= self._limits.segment_max_records)
        if not fits:
            raise _Refusal(StorageErrorCode.FILE_TOO_LARGE, "rotation:fit")
        next_segment = self._segment + 1
        self._commit(close_line)
        self._finish_segment()
        self._create_segment(next_segment)
        self._commit(open_line)
        self._last_timestamp = timestamp
        return self._commit(record_line, event_id=event_id)

    def _operator_rotation(self, reason_close: CloseReason, reason_open: OpenReason, *, new_chain_key: AuditKey,
                           new_auth: AuditKey, new_epoch: ProjectionEpoch) -> None:
        self._check()  # rows RO / K
        capacity = _capacity_problem(self._seq, self._generation, self._segment, KEY_ROTATION_RESERVE,
                                     new_segment=True)
        if capacity is not None:  # A-8.1 step 0: before parameters, clock or any build
            raise _Refusal(StorageErrorCode.ENTRY_LIMIT_EXCEEDED, capacity)
        problem: StorageError | None = None
        try:  # step 1: the new parameters are independent of every current key and of the epoch
            require_independent_keys(new_chain_key, new_auth, self._ref)
            if new_chain_key is not self._chain_key and new_chain_key._same_material(self._chain_key):
                raise StorageError(StorageErrorCode.KEYS_NOT_INDEPENDENT, "keys")
            if new_auth is not self._auth and new_auth._same_material(self._auth):
                raise StorageError(StorageErrorCode.KEYS_NOT_INDEPENDENT, "keys")
            if new_chain_key._same_material(self._auth) or new_auth._same_material(self._chain_key):
                raise StorageError(StorageErrorCode.KEYS_NOT_INDEPENDENT, "keys")
            _require_epoch_independent(new_epoch, new_chain_key, new_auth)
        except StorageError as error:
            problem = error
        if problem is not None:
            raise _Refusal(problem.code, problem.path or "rotation:keys")
        timestamp = self._next_timestamp()
        close_line, open_line, _ = self._prebuild_rotation(
            reason_close, reason_open, timestamp=timestamp, new_chain_key=new_chain_key,
            new_auth_id=new_auth.key_id, new_epoch=new_epoch)
        next_segment = self._segment + 1
        self._commit(close_line)  # anchored under the old K_chain and auth key id
        self._finish_segment()
        self._create_segment(next_segment)
        self._commit(open_line, chain_key=new_chain_key, auth_key_id=new_auth.key_id)  # anchored under the new
        self._chain_key, self._auth, self._epoch = new_chain_key, new_auth, new_epoch
        self._last_timestamp = timestamp

    def _run(self, operation: Any) -> Any:
        """Serialised, READY-only entry for non-append operations. Refusals raise; the writer stays READY."""
        if not self._enter():
            raise StorageError(StorageErrorCode.SINK_BUSY, "sink:busy")
        try:
            if self._state is not SinkState.READY:
                raise StorageError(StorageErrorCode.SINK_SEALED, "sink:" + self._state.value)
            refusal: _Refusal | None = None
            try:
                return operation()
            except _Refusal as caught:
                refusal = caught
            except BaseException:
                self._enter_sealed()
                raise
            raise StorageError(refusal.code, refusal.detail)
        finally:
            self._busy.release()

    def rotate_epoch(self, new_epoch: object) -> None:
        """Operator epoch rotation (D-C3-10): close ``EPOCH_ROTATION``, open ``EPOCH_ROTATION``."""
        def operation() -> None:
            if type(new_epoch) is not ProjectionEpoch:
                raise _Refusal(StorageErrorCode.INPUT_TYPE_INVALID, "epoch")
            if new_epoch == self._epoch:
                raise _Refusal(StorageErrorCode.INPUT_TYPE_INVALID, "epoch:unchanged")
            self._operator_rotation(CloseReason.EPOCH_ROTATION, OpenReason.EPOCH_ROTATION,
                                    new_chain_key=self._chain_key, new_auth=self._auth, new_epoch=new_epoch)
        self._run(operation)

    def rotate_auth_key(self, new_auth: object) -> None:
        """Operator K_auth rotation: later events and anchors use the new key (id)."""
        def operation() -> None:
            key = self._as_key(new_auth, KeyPurpose.AUTH, "auth_key")
            if key.key_id == self._auth.key_id:
                raise _Refusal(StorageErrorCode.KEYS_NOT_INDEPENDENT, "auth_key:unchanged")
            self._operator_rotation(CloseReason.KEY_ROTATION, OpenReason.KEY_ROTATION,
                                    new_chain_key=self._chain_key, new_auth=key, new_epoch=self._epoch)
        self._run(operation)

    def rotate_chain_key(self, new_chain_key: object) -> None:
        """Operator K_chain rotation: the close is MAC'd with the old key, the open and later records with the new."""
        def operation() -> None:
            key = self._as_key(new_chain_key, KeyPurpose.CHAIN, "chain_key")
            if key.key_id == self._chain_key.key_id:
                raise _Refusal(StorageErrorCode.KEYS_NOT_INDEPENDENT, "chain_key:unchanged")
            self._operator_rotation(CloseReason.CHAIN_KEY_ROTATION, OpenReason.CHAIN_KEY_ROTATION,
                                    new_chain_key=key, new_auth=self._auth, new_epoch=self._epoch)
        self._run(operation)

    @staticmethod
    def _as_key(value: object, purpose: KeyPurpose, label: str) -> AuditKey:
        problem: StorageError | None = None
        key: AuditKey | None = None
        try:
            key = _require_key(value, purpose, label)
        except StorageError as error:
            problem = error
        if problem is not None:
            raise _Refusal(problem.code, problem.path)
        return key  # type: ignore[return-value]

    # -- checkpoints (H0 section 8) ------------------------------------------------------------------------------------

    def checkpoint(self) -> bytes:
        """Write a ``checkpoint_marker`` and return a content-free checkpoint for external custody."""
        return self._run(self._checkpoint)  # type: ignore[no-any-return]

    def _checkpoint(self) -> bytes:
        self._check()  # row A
        documents: list[bytes] = []

        def marker_at(position: ChainPosition) -> bytes:
            """The marker names the record before it. Pure: it carries no timestamp."""
            line, problem = _try_build(build_checkpoint_marker, position=position, chain_key=self._chain_key,
                                       checkpoint_seq=position.seq - 1,
                                       checkpoint_record_digest=position.prev_record_digest)
            if problem is not None:
                raise _Refusal(problem.code, problem.path or "checkpoint")
            return line  # type: ignore[return-value]

        # L-1 (C3-H2): path selection and capacity need no clock, so a full chain is refused before the clock
        # callable is ever invoked (as append and the operator rotations already do).
        line = marker_at(self._record_at(self._segment, self._seq + 1, self._prev_digest))
        direct = self._admits(line)
        reserve = DIRECT_RESERVE if direct else SIZE_ROTATION_RESERVE
        capacity = _capacity_problem(self._seq, self._generation, self._segment, reserve, new_segment=not direct)
        if capacity is not None:
            raise _Refusal(StorageErrorCode.ENTRY_LIMIT_EXCEEDED, capacity)
        timestamp = self._next_timestamp()  # only now; still before any build of the document or any write

        def documented(position: ChainPosition, generation: int) -> bytes:
            """Marker plus its custody document, both built before any write."""
            marker = marker_at(position)
            documents.append(self._prebuilt_checkpoint(position.segment, position.seq, _digest_of(marker),
                                                       timestamp, generation))
            return marker

        if direct:
            self._commit(documented(self._record_at(self._segment, self._seq + 1, self._prev_digest),
                                    self._generation + 1))
        else:  # the rebuilt marker is the third record of the rotation: generation + 3
            generation = self._generation + 3
            self._size_rotation(lambda position: documented(position, generation), None, timestamp)
        self._last_timestamp = timestamp
        return documents[-1]

    def _prebuilt_checkpoint(self, segment: int, seq: int, digest: str, timestamp: str, generation: int) -> bytes:
        document, problem = _try_build(build_checkpoint, chain_id=self._chain_id, segment=segment, seq=seq,
                                       record_digest=digest, created_at=timestamp, auth_key_id=self._auth.key_id,
                                       anchor_generation=generation, chain_key=self._chain_key)
        if problem is not None:
            raise _Refusal(problem.code, problem.path or "checkpoint")
        return document  # type: ignore[return-value]

    # -- close (H0 5.4) --------------------------------------------------------------------------------------------------

    def close(self) -> None:
        """Idempotent. From READY, write the SHUTDOWN close first; in every state release the lock last."""
        if not self._enter():
            raise StorageError(StorageErrorCode.SINK_BUSY, "sink:busy")
        try:
            if self._state is SinkState.CLOSED:
                return
            try:
                if self._state is SinkState.READY:
                    self._shutdown()
            except BaseException:
                self._enter_sealed()
                raise
            finally:
                self._release_all()
        finally:
            self._busy.release()

    def _shutdown(self) -> None:
        self._check()  # row CL
        position = self._record_at(self._segment, self._seq + 1, self._prev_digest)
        line, problem = _try_build(build_segment_close, position=position, chain_key=self._chain_key,
                                   record_count=self._records_in_segment + 1, reason=CloseReason.SHUTDOWN)
        if problem is not None:
            self._enter_sealed()
            raise problem
        self._commit(line)  # type: ignore[arg-type]

    def _release_all(self) -> None:
        """Close handles, then release the lock last (C2-D contract rule 5). The audit root is the caller's."""
        self._state = SinkState.CLOSED
        self._finish_segment()
        chain, self._chain = self._chain, None
        lock, self._lock = self._lock, None
        if chain is not None:
            chain.close()
        if lock is not None:
            lock.release()

    def _abandon(self) -> None:
        """A failed open: nothing is removed or cleaned up (A7); handles are closed and the lock released."""
        if self._state in (SinkState.OPENING, SinkState.READY):
            self._state = SinkState.SEALED
        self._release_all()


_CONSTRUCT = object()
