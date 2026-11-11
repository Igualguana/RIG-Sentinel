"""M2-B MemorySink and AuditReceipt: ordering, limits, rejection, concurrency, honesty."""

import dataclasses
import threading

import pytest
from audit_fixtures import auth_key, both_keys, builder, evaluated, ref_key

from rig_sentinel.audit import (
    MAX_ENVELOPE_BYTES,
    AuditEnvelope,
    AuditError,
    AuditErrorCode,
    AuditEventBuilder,
    AuditKeys,
    AuditSink,
    AuthStatus,
    Durability,
    MemorySink,
    ReceiptStatus,
    keyring,
)

RING = keyring([auth_key()])


def _envelopes(count, keys=None):
    request, record = evaluated()
    build = builder(keys)
    return [build.build_envelope(record, request) for _ in range(count)]


def test_memory_sink_satisfies_the_protocol():
    assert isinstance(MemorySink(), AuditSink)


def test_receipts_report_order_and_never_claim_durability():
    sink = MemorySink(verify_keys=RING)
    envelopes = _envelopes(3)
    receipts = [sink.append(envelope) for envelope in envelopes]
    assert [r.sequence for r in receipts] == [0, 1, 2]
    for receipt, envelope in zip(receipts, envelopes, strict=True):
        assert receipt.status is ReceiptStatus.STORED_IN_MEMORY and receipt.stored
        assert receipt.durability is Durability.NONE
        assert receipt.event_id == envelope.event.audit.event_id
        assert receipt.event_digest == envelope.event_digest
        assert receipt.auth_status is AuthStatus.AUTHENTIC
        assert receipt.error_code is None
    assert sink.envelopes() == tuple(envelopes)
    assert len(sink) == 3


def test_receipt_is_not_part_of_the_stored_event():
    sink = MemorySink()
    envelope = _envelopes(1)[0]
    sink.append(envelope)
    stored = sink.canonical_records()[0]
    assert stored == envelope.canonical_bytes()
    for word in (b"stored_in_memory", b"sequence", b"durability", b"receipt"):
        assert word not in stored


def test_without_verify_keys_the_auth_status_is_unchecked():
    receipt = MemorySink().append(_envelopes(1)[0])
    assert receipt.stored and receipt.auth_status is None


def test_duplicate_event_ids_are_rejected():
    sink = MemorySink()
    envelope = _envelopes(1)[0]
    assert sink.append(envelope).stored
    again = sink.append(envelope)
    assert again.status is ReceiptStatus.REJECTED and not again.stored
    assert again.error_code is AuditErrorCode.DUPLICATE_EVENT_ID
    assert again.sequence is None and len(sink) == 1


def test_capacity_by_count_rejects_without_evicting():
    sink = MemorySink(max_events=2)
    first, second, third = _envelopes(3)
    assert sink.append(first).stored and sink.append(second).stored
    receipt = sink.append(third)
    assert receipt.error_code is AuditErrorCode.SINK_FULL and not receipt.stored
    assert sink.envelopes() == (first, second)


def test_capacity_by_bytes_rejects_without_evicting():
    envelopes = _envelopes(40)
    size = len(envelopes[0].canonical_bytes())
    limit = max(MAX_ENVELOPE_BYTES, size * 10)
    sink = MemorySink(max_bytes=limit)
    receipts = [sink.append(e) for e in envelopes]
    stored = [r for r in receipts if r.stored]
    assert sink.total_bytes <= limit
    assert all(r.error_code is AuditErrorCode.SINK_FULL for r in receipts[len(stored):])
    assert [r.sequence for r in stored] == list(range(len(stored)))


@pytest.mark.parametrize(
    "kwargs",
    [{"max_events": 0}, {"max_events": True}, {"max_events": 10**9}, {"max_bytes": 100},
     {"max_bytes": 2**40}, {"require_authenticated": True}, {"require_authenticated": 1}],
    ids=lambda k: str(k),
)
def test_invalid_sink_configuration_is_rejected(kwargs):
    with pytest.raises(AuditError):
        MemorySink(**kwargs)


def test_verify_keys_must_be_auth_keys_with_matching_ids():
    with pytest.raises(AuditError):
        MemorySink(verify_keys={ref_key().key_id: ref_key()})
    with pytest.raises(AuditError):
        MemorySink(verify_keys={"0" * 32: auth_key()})


def test_tampered_digest_is_rejected():
    envelope = _envelopes(1)[0]
    broken = dataclasses.replace(envelope, event_digest="0" * 64)
    receipt = MemorySink().append(broken)
    assert receipt.error_code is AuditErrorCode.DIGEST_MISMATCH and not receipt.stored


def test_bad_mac_is_rejected_when_verifying():
    envelope = _envelopes(1)[0]
    forged = dataclasses.replace(envelope, auth=dataclasses.replace(envelope.auth, mac="0" * 64))
    receipt = MemorySink(verify_keys=RING).append(forged)
    assert receipt.error_code is AuditErrorCode.AUTHENTICATION_FAILED
    assert receipt.auth_status is AuthStatus.MAC_MISMATCH


def test_require_authenticated_rejects_unauthenticated_envelopes():
    unauthenticated = _envelopes(1, keys=AuditKeys(ref=ref_key()))[0]
    sink = MemorySink(verify_keys=RING, require_authenticated=True)
    receipt = sink.append(unauthenticated)
    assert receipt.error_code is AuditErrorCode.UNAUTHENTICATED_REJECTED
    assert MemorySink(verify_keys=RING).append(unauthenticated).auth_status is AuthStatus.UNAUTHENTICATED


@pytest.mark.parametrize("bad", [None, {}, b"{}", "envelope", 1])
def test_non_envelopes_are_rejected_not_raised(bad):
    receipt = MemorySink().append(bad)
    assert receipt.error_code is AuditErrorCode.INVALID_ENVELOPE and not receipt.stored


def test_internal_state_is_not_exposed():
    sink = MemorySink()
    envelope = _envelopes(1)[0]
    sink.append(envelope)
    records = sink.canonical_records()
    assert isinstance(records, tuple) and isinstance(records[0], bytes)
    copies = sink.envelopes()
    assert copies[0] == envelope and copies[0] is not envelope
    assert "records" not in repr(sink) and envelope.event.audit.event_id not in repr(sink)


def test_sink_never_changes_m1_records():
    request, record = evaluated()
    before = record.to_dict()
    MemorySink(verify_keys=RING).append(builder().build_envelope(record, request))
    assert record.to_dict() == before


def test_concurrent_appends_keep_order_unique_and_bounded():
    request, record = evaluated()
    build = AuditEventBuilder(both_keys())  # random ids, safe across threads
    sink = MemorySink(max_events=300, verify_keys=RING)
    receipts = []
    lock = threading.Lock()

    def worker():
        local = [sink.append(build.build_envelope(record, request)) for _ in range(50)]
        with lock:
            receipts.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    stored = [r for r in receipts if r.stored]
    rejected = [r for r in receipts if not r.stored]
    assert len(stored) == 300 and len(rejected) == 100
    assert sorted(r.sequence for r in stored) == list(range(300))
    assert all(r.error_code is AuditErrorCode.SINK_FULL for r in rejected)
    assert len({r.event_id for r in stored}) == 300 and len(sink) == 300
    order = [env.event.audit.event_id for env in sink.envelopes()]
    by_sequence = [r.event_id for r in sorted(stored, key=lambda r: r.sequence)]
    assert order == by_sequence


def test_sink_append_survives_hostile_envelope_subclass():
    class Hostile(AuditEnvelope):
        pass

    envelope = _envelopes(1)[0]
    hostile = object.__new__(Hostile)
    object.__setattr__(hostile, "event", envelope.event)
    object.__setattr__(hostile, "event_digest", envelope.event_digest)
    object.__setattr__(hostile, "auth", envelope.auth)
    receipt = MemorySink().append(hostile)
    assert receipt.error_code is AuditErrorCode.INVALID_ENVELOPE
