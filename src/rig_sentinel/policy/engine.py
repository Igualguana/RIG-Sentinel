"""Deterministic, fail-closed policy decision point.

``PolicyEngine.evaluate`` is a pure function of (policy, request, clock):
it performs no I/O and invokes no tools. Every problem that surfaces as an
``Exception`` (including ``RecursionError`` and ``MemoryError``) produces a
DENY record. ``BaseException`` subclasses that are not ``Exception``
(``KeyboardInterrupt``, ``SystemExit``, ``GeneratorExit``) propagate, and a
process can also die or hang without returning at all. Callers must
therefore treat *anything other than a returned ALLOW record* as "do not
invoke the tool".

The engine does not authenticate anything. Agent identity, assurance level,
tool identity, manifest digest, resource and context labels are taken from
the request as supplied by the caller (a trusted enforcement adapter).

Decision order:

1. Engine state  - no policy / digest pin mismatch      -> DENY
2. Request       - missing or invalid identity, tool,
                   operation, resource or context       -> DENY
3. Tool registry - unknown tool, manifest mismatch,
                   undeclared operation, resource kind   -> DENY
4. Rules         - any matching deny                    -> DENY
                   else any matching require_approval   -> REQUIRE_APPROVAL
                   else any matching allow              -> ALLOW
                   else policy default (deny | require_approval)

Rule order in the policy file never affects the result.
"""

from __future__ import annotations

import builtins
import hmac
import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime

from rig_sentinel.policy.canonical import (
    APPROVAL_BINDING_DOMAIN,
    REQUEST_DIGEST_DOMAIN,
    digest,
)
from rig_sentinel.policy.decision import (
    FALLBACK_DENY,
    ApprovalRequirement,
    DecisionRecord,
    make_record,
)
from rig_sentinel.policy.errors import RequestValidationError
from rig_sentinel.policy.identifiers import is_sha256_hex
from rig_sentinel.policy.matching import CompiledRule, compile_rule, rule_matches
from rig_sentinel.policy.model import (
    PROTECTED_OPERATIONS,
    AuthorizationRequest,
    Decision,
    Effect,
    Policy,
    ToolSpec,
    parse_request,
)
from rig_sentinel.policy.reasons import ReasonCode
from rig_sentinel.policy.schema import WILDCARD
from rig_sentinel.policy.validation import validate_policy

Clock = Callable[[], datetime]

# ``error_type`` of an EVALUATION_ERROR record names the exception class only if
# that class *is* one of Python's built-in ``Exception`` classes; any other class
# is recorded as UNLISTED_ERROR_TYPE. Exception classes raised during evaluation
# can come from caller-supplied objects (a mapping, a clock), so their names,
# metaclass properties, ``__eq__`` and ``__hash__`` are untrusted. The lookup
# below therefore compares classes with ``is`` only: it never reads an
# attribute of, hashes, or compares with the exception's class. Names come from
# this table, built at import time from the ``builtins`` module.
UNLISTED_ERROR_TYPE = "UnlistedError"
_ERROR_TYPE_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


def _approved_error_types() -> tuple[tuple[type, str], ...]:
    approved: list[tuple[type, str]] = []
    for obj in vars(builtins).values():
        if (
            type(obj) is type  # plain classes only: no custom metaclass code runs below
            and issubclass(obj, Exception)
            and not any(obj is known for known, _ in approved)  # aliases, e.g. IOError
        ):
            name = obj.__name__
            if type(name) is str and _ERROR_TYPE_NAME_RE.fullmatch(name):
                approved.append((obj, name))
    return tuple(approved)


_APPROVED_ERROR_TYPES = _approved_error_types()


def _error_type_name(exc: BaseException) -> str:
    """Return a safe ``error_type`` for ``exc`` (see UNLISTED_ERROR_TYPE)."""
    exc_class = type(exc)  # the real class; ``__class__`` overrides are ignored
    for approved, name in _APPROVED_ERROR_TYPES:
        if exc_class is approved:
            return name
    return UNLISTED_ERROR_TYPE


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _format_time(value: object) -> str:
    if type(value) is not datetime or value.tzinfo is None:
        raise TypeError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def coerce_request(request: object) -> AuthorizationRequest:
    """Re-validate a request from scratch.

    Typed requests are converted back to their mapping form and parsed again,
    so an instance altered after construction (for example with
    ``object.__setattr__``) cannot skip validation.
    """
    if isinstance(request, AuthorizationRequest):
        try:
            data = request.to_dict()
        except Exception:
            raise RequestValidationError(
                ReasonCode.INVALID_REQUEST, "request could not be serialized"
            ) from None
    elif isinstance(request, Mapping):
        data = request
    else:
        raise RequestValidationError(ReasonCode.INVALID_REQUEST, "unsupported request type")
    return parse_request(data)


class PolicyEngine:
    """Evaluate authorization requests against one validated policy.

    The engine must be given a :class:`Policy` explicitly; it never discovers
    or loads policy files on its own, and it never activates advisory scanner
    output. The policy is re-validated on construction; if that fails, or if
    ``expected_policy_sha256`` does not match, every request is denied.
    """

    def __init__(
        self,
        policy: Policy | None,
        *,
        expected_policy_sha256: str | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._clock: Clock = clock if clock is not None else _utc_now
        self._policy: Policy | None = None
        self._meta: Policy | None = None
        self._unavailable: ReasonCode | None = ReasonCode.POLICY_UNAVAILABLE
        self._tools: dict[str, ToolSpec] = {}
        self._rules: tuple[CompiledRule, ...] = ()
        try:
            self._install(policy, expected_policy_sha256)
        except Exception:
            self._policy = None
            self._unavailable = ReasonCode.POLICY_UNAVAILABLE

    def _install(self, policy: object, expected_sha256: str | None) -> None:
        if not isinstance(policy, Policy):
            return
        validated = validate_policy(policy.to_dict())
        self._meta = validated
        if expected_sha256 is not None and (
            not is_sha256_hex(expected_sha256)
            or not hmac.compare_digest(validated.sha256, expected_sha256)
        ):
            self._unavailable = ReasonCode.POLICY_DIGEST_MISMATCH
            return
        self._tools = {tool.tool_id: tool for tool in validated.tools}
        self._rules = tuple(compile_rule(rule) for rule in validated.rules)
        self._policy = validated
        self._unavailable = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def policy_sha256(self) -> str | None:
        """Fingerprint of the active policy, or None if none is active."""
        return None if self._policy is None else self._policy.sha256

    @property
    def available(self) -> bool:
        return self._policy is not None

    def evaluate(self, request: AuthorizationRequest | Mapping[str, object]) -> DecisionRecord:
        """Return a decision for ``request``.

        ``Exception`` subclasses raised during evaluation are converted to
        ``DENY / EVALUATION_ERROR``; other ``BaseException`` subclasses
        propagate (see the module docstring).
        """
        try:
            return self._evaluate(request)
        except Exception as exc:  # fail closed
            return self._failure(exc)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _evaluate(self, request: object) -> DecisionRecord:
        evaluated_at = _format_time(self._clock())

        if self._unavailable is not None or self._policy is None:
            return self._record(
                Decision.DENY,
                self._unavailable or ReasonCode.POLICY_UNAVAILABLE,
                evaluated_at,
            )
        policy = self._policy

        try:
            req = coerce_request(request)
        except RequestValidationError as exc:
            return self._record(Decision.DENY, exc.reason_code, evaluated_at)

        request_digest = digest(REQUEST_DIGEST_DOMAIN, req.to_dict())

        def deny(reason: ReasonCode, protected: bool = True) -> DecisionRecord:
            return self._record(
                Decision.DENY,
                reason,
                evaluated_at,
                request_digest=request_digest,
                protected=protected,
            )

        tool = self._tools.get(req.tool.tool_id)
        if tool is None:
            return deny(ReasonCode.UNKNOWN_TOOL)

        protected = tool.protected or req.operation in PROTECTED_OPERATIONS

        if tool.manifest_sha256 is not None and (
            req.tool.manifest_sha256 is None
            or not hmac.compare_digest(tool.manifest_sha256, req.tool.manifest_sha256)
        ):
            return deny(ReasonCode.TOOL_MANIFEST_MISMATCH, protected)
        if req.operation not in tool.operations:
            return deny(ReasonCode.OPERATION_NOT_DECLARED, protected)
        if tool.resource_kind is not None and req.resource.kind != tool.resource_kind:
            return deny(ReasonCode.RESOURCE_KIND_MISMATCH, protected)

        matched = [rule for rule in self._rules if rule_matches(rule, req)]
        matched_ids = tuple(sorted(rule.rule_id for rule in matched))

        def ids(effect: Effect) -> tuple[str, ...]:
            return tuple(sorted(rule.rule_id for rule in matched if rule.effect is effect))

        denying = ids(Effect.DENY)
        approving = ids(Effect.REQUIRE_APPROVAL)
        allowing = ids(Effect.ALLOW)

        common = {
            "request_digest": request_digest,
            "protected": protected,
            "matched": matched_ids,
        }
        if denying:
            return self._record(
                Decision.DENY, ReasonCode.RULE_DENY, evaluated_at, deciding=denying, **common
            )
        if approving:
            return self._record(
                Decision.REQUIRE_APPROVAL,
                ReasonCode.RULE_REQUIRES_APPROVAL,
                evaluated_at,
                deciding=approving,
                approval=self._approval(req, approving),
                **common,
            )
        if allowing:
            return self._record(
                Decision.ALLOW, ReasonCode.RULE_ALLOW, evaluated_at, deciding=allowing, **common
            )
        if policy.defaults.decision is Effect.REQUIRE_APPROVAL:
            return self._record(
                Decision.REQUIRE_APPROVAL,
                ReasonCode.DEFAULT_REQUIRE_APPROVAL,
                evaluated_at,
                approval=self._approval(req, ()),
                **common,
            )
        # Any other default value (only "deny" is valid) fails closed.
        return self._record(Decision.DENY, ReasonCode.DEFAULT_DENY, evaluated_at, **common)

    def _approval(
        self, req: AuthorizationRequest, deciding: tuple[str, ...]
    ) -> ApprovalRequirement:
        policy = self._policy
        if policy is None or req.agent is None:
            # Unreachable by construction; fail closed if it ever happens.
            raise RuntimeError("approval requirement without policy or agent")
        wanted = set(deciding)
        approvers = tuple(
            sorted(
                approver.approver_id
                for approver in policy.approvers
                if WILDCARD in approver.scopes or wanted.intersection(approver.scopes)
            )
        )
        binding = digest(
            APPROVAL_BINDING_DOMAIN,
            {
                "agent_id": req.agent.agent_id,
                "tool_id": req.tool.tool_id,
                "operation": req.operation.value,
                "resource": req.resource.canonical,
                "environment": req.context.environment.value,
                "session_id": req.context.session_id,
                "policy_sha256": policy.sha256,
            },
        )
        return ApprovalRequirement(
            eligible_approvers=approvers,
            request_binding_sha256=binding,
            ttl_seconds=policy.defaults.approval_ttl_seconds,
        )

    def _record(
        self,
        decision: Decision,
        reason: ReasonCode,
        evaluated_at: str | None,
        *,
        request_digest: str | None = None,
        protected: bool = True,
        matched: tuple[str, ...] = (),
        deciding: tuple[str, ...] = (),
        approval: ApprovalRequirement | None = None,
        error_type: str | None = None,
    ) -> DecisionRecord:
        meta = self._meta
        return make_record(
            decision=decision,
            reason_code=reason,
            deciding_rule_ids=deciding,
            matched_rule_ids=matched,
            policy_id=None if meta is None else meta.policy_id,
            policy_version=None if meta is None else meta.policy_version,
            policy_sha256=None if meta is None else meta.sha256,
            request_digest=request_digest,
            evaluated_at=evaluated_at,
            protected=protected,
            approval=approval,
            error_type=error_type,
        )

    def _failure(self, exc: BaseException) -> DecisionRecord:
        try:
            return self._record(
                Decision.DENY,
                ReasonCode.EVALUATION_ERROR,
                None,
                error_type=_error_type_name(exc),
            )
        except Exception:
            return FALLBACK_DENY
