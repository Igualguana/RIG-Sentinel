"""Stable decision records returned by the policy engine.

A decision record is *advisory output*: it tells a trusted enforcement
adapter what the policy says. ``enforced`` is always ``False`` because the
engine never blocks, executes or approves anything itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from rig_sentinel.policy.canonical import DECISION_DIGEST_DOMAIN, digest
from rig_sentinel.policy.model import Decision
from rig_sentinel.policy.reasons import ReasonCode
from rig_sentinel.policy.schema import SCHEMA_VERSION

# Identifier of this engine build, independent of the package version.
ENGINE_VERSION = "genesis-b2-m1"
DECISION_RECORD_SCHEMA = "rig.decision/v1"


@dataclass(frozen=True)
class ApprovalRequirement:
    """What a REQUIRE_APPROVAL decision needs.

    M1 describes the requirement only. Issuing, verifying, expiring and
    consuming approval grants is the M3 approval lifecycle and is not
    implemented: an approval cannot turn this decision into ALLOW yet.
    """

    eligible_approvers: tuple[str, ...]
    request_binding_sha256: str
    ttl_seconds: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible_approvers": list(self.eligible_approvers),
            "request_binding_sha256": self.request_binding_sha256,
            "ttl_seconds": self.ttl_seconds,
        }


@dataclass(frozen=True)
class DecisionRecord:
    decision: Decision
    reason_code: ReasonCode
    deciding_rule_ids: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]
    policy_id: str | None
    policy_version: str | None
    policy_sha256: str | None
    request_digest: str | None
    evaluated_at: str | None
    protected: bool
    approval: ApprovalRequirement | None = None
    error_type: str | None = None
    decision_digest: str = ""
    schema_version: str = SCHEMA_VERSION
    engine_version: str = ENGINE_VERSION
    record_schema: str = DECISION_RECORD_SCHEMA
    # Not a constructor argument: the engine never enforces.
    enforced: bool = field(default=False, init=False)

    @property
    def allowed(self) -> bool:
        """True only for an ALLOW decision. Adapters must check this."""
        return self.decision is Decision.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_schema": self.record_schema,
            "decision": self.decision.value,
            "reason_code": self.reason_code.value,
            "deciding_rule_ids": list(self.deciding_rule_ids),
            "matched_rule_ids": list(self.matched_rule_ids),
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "schema_version": self.schema_version,
            "engine_version": self.engine_version,
            "request_digest": self.request_digest,
            "evaluated_at": self.evaluated_at,
            "protected": self.protected,
            "approval": None if self.approval is None else self.approval.to_dict(),
            "error_type": self.error_type,
            "enforced": self.enforced,
            "decision_digest": self.decision_digest,
        }


def make_record(**fields: Any) -> DecisionRecord:
    """Build a record and fill in its ``decision_digest``."""
    record = DecisionRecord(**fields)
    body = record.to_dict()
    del body["decision_digest"]
    return replace(record, decision_digest=digest(DECISION_DIGEST_DOMAIN, body))


# Returned if even building an error record fails. Built at import time so
# the failure path never depends on code that might itself be failing.
FALLBACK_DENY = make_record(
    decision=Decision.DENY,
    reason_code=ReasonCode.EVALUATION_ERROR,
    deciding_rule_ids=(),
    matched_rule_ids=(),
    policy_id=None,
    policy_version=None,
    policy_sha256=None,
    request_digest=None,
    evaluated_at=None,
    protected=True,
    error_type="InternalError",
)
