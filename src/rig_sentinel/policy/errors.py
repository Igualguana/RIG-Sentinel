"""Exception types for policy loading, validation and request parsing.

Error messages never include raw policy or request values: they describe
*where* a problem is (a field path) and *what kind* of problem it is.
"""

from __future__ import annotations

from dataclasses import dataclass

from rig_sentinel.policy.reasons import ReasonCode


@dataclass(frozen=True)
class PolicyIssue:
    """One validation error or lint warning.

    ``path`` uses a dotted/indexed form such as ``rules[2].effect``.
    """

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.code} at {self.path or '<root>'}: {self.message}"


class PolicyError(Exception):
    """Base class for all policy-engine errors."""


class PolicyLoadError(PolicyError):
    """The policy could not be read, decoded or parsed."""


class PolicyValidationError(PolicyLoadError):
    """The policy parsed but violates the schema. Nothing is loaded."""

    def __init__(self, issues: tuple[PolicyIssue, ...]) -> None:
        self.issues = tuple(issues)
        summary = "; ".join(str(issue) for issue in self.issues[:10])
        if len(self.issues) > 10:
            summary += f"; ... ({len(self.issues) - 10} more)"
        super().__init__(
            f"policy rejected with {len(self.issues)} issue(s): {summary}"
        )

    @property
    def codes(self) -> tuple[str, ...]:
        return tuple(issue.code for issue in self.issues)


class PolicyDigestMismatchError(PolicyLoadError):
    """The policy's SHA-256 fingerprint differs from the pinned value."""


class RequestValidationError(PolicyError):
    """An authorization request is malformed.

    The engine converts this into a DENY decision carrying ``reason_code``.
    """

    def __init__(self, reason_code: ReasonCode, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code.value}: {message}")
