"""Stable, public reason codes attached to every policy decision."""

from __future__ import annotations

from enum import StrEnum


class ReasonCode(StrEnum):
    """Why the engine reached a decision.

    Values are part of the public decision-record contract. Do not rename
    existing members; add new ones instead.
    """

    # Rule-driven outcomes
    RULE_ALLOW = "RULE_ALLOW"
    RULE_DENY = "RULE_DENY"
    RULE_REQUIRES_APPROVAL = "RULE_REQUIRES_APPROVAL"

    # No rule matched
    DEFAULT_DENY = "DEFAULT_DENY"
    DEFAULT_REQUIRE_APPROVAL = "DEFAULT_REQUIRE_APPROVAL"

    # Tool registry checks
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    TOOL_MANIFEST_MISMATCH = "TOOL_MANIFEST_MISMATCH"
    OPERATION_NOT_DECLARED = "OPERATION_NOT_DECLARED"
    RESOURCE_KIND_MISMATCH = "RESOURCE_KIND_MISMATCH"

    # Request validation
    MISSING_IDENTITY = "MISSING_IDENTITY"
    INVALID_IDENTITY = "INVALID_IDENTITY"
    INVALID_TOOL_ID = "INVALID_TOOL_ID"
    UNKNOWN_OPERATION = "UNKNOWN_OPERATION"
    INVALID_RESOURCE = "INVALID_RESOURCE"
    INVALID_REQUEST = "INVALID_REQUEST"

    # Engine state
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    POLICY_DIGEST_MISMATCH = "POLICY_DIGEST_MISMATCH"
    EVALUATION_ERROR = "EVALUATION_ERROR"
