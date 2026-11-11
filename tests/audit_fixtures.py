"""Shared helpers for the M2-B audit tests. Synthetic values only."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

from policy_fixtures import baseline_engine, make_request

from rig_sentinel.audit import AuditEventBuilder, AuditKey, AuditKeys, KeyPurpose

REF_MATERIAL = bytes(range(1, 33))
AUTH_MATERIAL = bytes(range(33, 65))
FIXED_AUDIT_NOW = datetime(2026, 11, 10, 12, 0, 0, 123456, tzinfo=UTC)

# Synthetic canary built from fragments so no scanner-matching literal sits in the file.
CANARY = "sk-" + "canary-" + "a1b2c3d4e5f6a7b8c9d0e1f2"


def ref_key() -> AuditKey:
    return AuditKey.from_bytes(KeyPurpose.REF, REF_MATERIAL)


def auth_key() -> AuditKey:
    return AuditKey.from_bytes(KeyPurpose.AUTH, AUTH_MATERIAL)


def both_keys() -> AuditKeys:
    return AuditKeys(ref=ref_key(), auth=auth_key())


def audit_clock() -> datetime:
    return FIXED_AUDIT_NOW


def counter_ids():
    counter = itertools.count(1)
    return lambda: f"{next(counter):032x}"


def builder(keys: AuditKeys | None = None) -> AuditEventBuilder:
    return AuditEventBuilder(
        both_keys() if keys is None else keys, clock=audit_clock, id_factory=counter_ids()
    )


def evaluated(**request_overrides):
    """Return (request, record) from the baseline M1 engine."""
    request = make_request(**request_overrides)
    return request, baseline_engine().evaluate(request)
