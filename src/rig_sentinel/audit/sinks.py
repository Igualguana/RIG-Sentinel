"""Audit sinks: the ``AuditSink`` protocol, ``AuditReceipt`` and ``MemorySink`` (M2-B).

A receipt reports what a sink did with one envelope. It is returned to the
caller and is never written into the event, so an event can never claim its
own persistence. ``MemorySink`` keeps envelopes in process memory only: its
receipts always say ``durability = "none"``, and everything is lost when the
process ends. There is no file, database or network I/O in this module.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from rig_sentinel.audit.chain import AuthStatus, event_digest, macs_equal
from rig_sentinel.audit.errors import AuditError, AuditErrorCode
from rig_sentinel.audit.events import AuditEnvelope
from rig_sentinel.audit.keys import AuditKey, KeyPurpose
from rig_sentinel.audit.validation import MAX_ENVELOPE_BYTES, envelope_from_dict

DEFAULT_MAX_EVENTS = 10_000
DEFAULT_MAX_BYTES = 32 * 1024 * 1024
HARD_MAX_EVENTS = 1_000_000
HARD_MAX_BYTES = 1024 * 1024 * 1024


class ReceiptStatus(StrEnum):
    STORED_IN_MEMORY = "stored_in_memory"
    REJECTED = "rejected"


class Durability(StrEnum):
    NONE = "none"  # process memory only; lost on exit or crash


@dataclass(frozen=True)
class AuditReceipt:
    """What a sink did with one envelope. Never stored inside the event.

    ``auth_status`` is ``None`` when the sink did not verify the authenticator.
    """

    status: ReceiptStatus
    sequence: int | None
    event_id: str | None
    event_digest: str | None
    auth_status: AuthStatus | None
    error_code: AuditErrorCode | None
    durability: Durability = Durability.NONE

    @property
    def stored(self) -> bool:
        return self.status is ReceiptStatus.STORED_IN_MEMORY


def _rejected(code: AuditErrorCode, envelope: object = None, auth: AuthStatus | None = None) -> AuditReceipt:
    event_id = None
    digest_value = None
    if type(envelope) is AuditEnvelope:
        event_id = envelope.event.audit.event_id
        digest_value = envelope.event_digest
    return AuditReceipt(ReceiptStatus.REJECTED, None, event_id, digest_value, auth, code)


@runtime_checkable
class AuditSink(Protocol):
    def append(self, envelope: AuditEnvelope) -> AuditReceipt:
        """Store ``envelope`` or reject it. Must not raise for invalid content."""
        ...


class MemorySink:
    """Bounded, ordered, thread-safe in-memory sink.

    * Stores each accepted envelope as immutable canonical bytes; readers get
      fresh copies, never the internal list.
    * Rejects (never evicts) once ``max_events`` or ``max_bytes`` is reached:
      nothing is silently dropped or overwritten.
    * Rejects envelopes whose ``event_digest`` does not match, duplicate
      ``event_id`` values, oversized envelopes, and (when ``verify_keys`` is
      given) envelopes whose MAC does not verify.
    * ``require_authenticated=True`` also rejects envelopes without an
      authenticator; it requires ``verify_keys``.
    """

    def __init__(
        self,
        *,
        max_events: int = DEFAULT_MAX_EVENTS,
        max_bytes: int = DEFAULT_MAX_BYTES,
        verify_keys: Mapping[str, AuditKey] | None = None,
        require_authenticated: bool = False,
    ) -> None:
        if type(max_events) is not int or not 1 <= max_events <= HARD_MAX_EVENTS:
            raise AuditError(AuditErrorCode.INVALID_FIELD, "max_events")
        if type(max_bytes) is not int or not MAX_ENVELOPE_BYTES <= max_bytes <= HARD_MAX_BYTES:
            raise AuditError(AuditErrorCode.INVALID_FIELD, "max_bytes")
        ring: dict[str, AuditKey] | None = None
        if verify_keys is not None:
            ring = {}
            for key_id, key in dict(verify_keys).items():
                if type(key) is not AuditKey or key.purpose is not KeyPurpose.AUTH or key.key_id != key_id:
                    raise AuditError(AuditErrorCode.KEY_PURPOSE_MISMATCH, "verify_keys")
                ring[key_id] = key
        if type(require_authenticated) is not bool or (require_authenticated and not ring):
            raise AuditError(AuditErrorCode.INVALID_FIELD, "require_authenticated")
        self._max_events = max_events
        self._max_bytes = max_bytes
        self._keys = ring
        self._require_authenticated = require_authenticated
        self._lock = threading.Lock()
        self._records: list[bytes] = []
        self._event_ids: set[str] = set()
        self._bytes = 0

    def __repr__(self) -> str:
        return (
            f"MemorySink(events={len(self)}, bytes={self.total_bytes}, "
            f"max_events={self._max_events}, max_bytes={self._max_bytes})"
        )

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    @property
    def total_bytes(self) -> int:
        with self._lock:
            return self._bytes

    @property
    def max_events(self) -> int:
        return self._max_events

    @property
    def max_bytes(self) -> int:
        return self._max_bytes

    def append(self, envelope: AuditEnvelope) -> AuditReceipt:
        try:
            return self._append(envelope)
        except Exception:  # never raise for content; BaseException propagates
            return _rejected(AuditErrorCode.SINK_ERROR)

    def _append(self, envelope: AuditEnvelope) -> AuditReceipt:
        if type(envelope) is not AuditEnvelope:
            return _rejected(AuditErrorCode.INVALID_ENVELOPE)
        body = envelope.event.to_dict()
        if not macs_equal(event_digest(body), envelope.event_digest):
            return _rejected(AuditErrorCode.DIGEST_MISMATCH, envelope)

        auth_status: AuthStatus | None = None
        if self._keys is not None:
            auth_status = envelope.verify(self._keys)
            if auth_status is AuthStatus.UNAUTHENTICATED:
                if self._require_authenticated:
                    return _rejected(AuditErrorCode.UNAUTHENTICATED_REJECTED, envelope, auth_status)
            elif auth_status is not AuthStatus.AUTHENTIC:
                return _rejected(AuditErrorCode.AUTHENTICATION_FAILED, envelope, auth_status)

        record = envelope.canonical_bytes()
        if len(record) > MAX_ENVELOPE_BYTES:
            return _rejected(AuditErrorCode.LIMIT_EXCEEDED, envelope, auth_status)
        event_id = envelope.event.audit.event_id

        with self._lock:
            if event_id in self._event_ids:
                return _rejected(AuditErrorCode.DUPLICATE_EVENT_ID, envelope, auth_status)
            if len(self._records) >= self._max_events or self._bytes + len(record) > self._max_bytes:
                return _rejected(AuditErrorCode.SINK_FULL, envelope, auth_status)
            sequence = len(self._records)
            self._records.append(record)
            self._event_ids.add(event_id)
            self._bytes += len(record)

        return AuditReceipt(
            status=ReceiptStatus.STORED_IN_MEMORY,
            sequence=sequence,
            event_id=event_id,
            event_digest=envelope.event_digest,
            auth_status=auth_status,
            error_code=None,
        )

    def canonical_records(self) -> tuple[bytes, ...]:
        """The stored envelopes as canonical JSON bytes, in acceptance order."""
        with self._lock:
            return tuple(self._records)

    def envelopes(self) -> tuple[AuditEnvelope, ...]:
        """Fresh envelope objects rebuilt (and re-validated) from the stored bytes."""
        return tuple(envelope_from_dict(json.loads(record)) for record in self.canonical_records())
