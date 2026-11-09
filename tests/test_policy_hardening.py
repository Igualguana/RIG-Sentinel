"""Hardening tests for the B2-M1 security review (findings F-1/H-1, H-2, H-4)
and for the engine's exception boundary.

F-1: the engine matches path identifiers byte-for-byte and cannot prove that
two spellings name the same filesystem object. A deny carved out of a broader
allow can therefore be bypassed by an alias (letter case, 8.3 short name,
link). The validator rejects such policies; matching is unchanged.
"""

from __future__ import annotations

import pytest
from policy_fixtures import fixed_clock

from rig_sentinel.policy import (
    Decision,
    PolicyEngine,
    PolicyValidationError,
    ReasonCode,
    lint_policy,
    load_policy_text,
)
from rig_sentinel.policy import engine as engine_module
from rig_sentinel.policy.resources import ResourceError, parse_resource
from rig_sentinel.policy.schema import IssueCode, LintCode

HEADER = """\
schema_version = "rig.policy/v1"
policy_id = "hardening"
policy_version = "1"

[[tools]]
id = "mcp://fs/read_file"
operations = ["read", "write"]
resource_kind = "fs"

[[tools]]
id = "mcp://fs/stat"
operations = ["read"]
resource_kind = "fs"

[[tools]]
id = "mcp://web/get"
operations = ["network"]
resource_kind = "url"

[[tools]]
id = "mcp://db/query"
operations = ["read"]
resource_kind = "db"

[[tools]]
id = "mcp://shell/run"
operations = ["execute"]
resource_kind = "shell"

[[tools]]
id = "mcp://vault/read"
operations = ["read"]
resource_kind = "secret"

[[approvers]]
id = "lead"
scopes = ["*"]
"""


def _rule(
    rule_id: str,
    effect: str,
    resources: list[str],
    *,
    agents: list[str] | None = None,
    tools: list[str] | None = None,
    operations: list[str] | None = None,
    conditions: str = "",
) -> str:
    def toml_list(values: list[str]) -> str:
        return "[" + ", ".join(f'"{value}"' for value in values) + "]"

    text = (
        f'\n[[rules]]\nid = "{rule_id}"\neffect = "{effect}"\n'
        f"agents = {toml_list(agents or ['bot'])}\n"
        f"tools = {toml_list(tools or ['mcp://fs/read_file'])}\n"
        f"operations = {toml_list(operations or ['read'])}\n"
        f"resources = {toml_list(resources)}\n"
    )
    if conditions:
        text += f"\n[rules.conditions]\n{conditions}\n"
    return text


def _policy(*rules: str, defaults: str = "") -> str:
    return HEADER + (f"\n[defaults]\n{defaults}\n" if defaults else "") + "".join(rules)


def _rejection_codes(text: str) -> set[str]:
    with pytest.raises(PolicyValidationError) as info:
        load_policy_text(text)
    return set(info.value.codes)


def _evaluate(engine: PolicyEngine, resource: str, *, tool: str = "mcp://fs/read_file",
              operation: str = "read", agent: str = "bot"):
    return engine.evaluate(
        {
            "agent": {"id": agent},
            "tool": {"id": tool},
            "operation": operation,
            "resource": resource,
            "context": {"environment": "dev"},
        }
    )


# ===========================================================================
# F-1 / H-1: alias-unsafe policy shapes are rejected
# ===========================================================================


def test_reported_f1_policy_is_rejected():
    text = _policy(
        _rule("allow-all", "allow", ["fs:/**"]),
        _rule("deny-secret", "deny", ["fs:/srv/secret/**"]),
    )
    with pytest.raises(PolicyValidationError) as info:
        load_policy_text(text)
    assert info.value.codes == (IssueCode.UNSAFE_PATH_CARVE_OUT,)
    assert info.value.issues[0].path == "rules[1].resources"
    assert "rules[0]" in info.value.issues[0].message


UNSAFE_CARVE_OUTS = {
    "deny prefix in root allow": (
        _rule("a", "allow", ["fs:/**"]), _rule("d", "deny", ["fs:/srv/secret/**"])),
    "deny exact file in prefix allow": (
        _rule("a", "allow", ["fs:/srv/**"]), _rule("d", "deny", ["fs:/srv/secret/key"])),
    "deny in wildcard-resource allow": (
        _rule("a", "allow", ["*"]), _rule("d", "deny", ["fs:/srv/secret/**"])),
    "require_approval carved out of allow": (
        _rule("a", "allow", ["fs:/srv/**"]),
        _rule("d", "require_approval", ["fs:/srv/secret/**"])),
    "url path carve-out": (
        _rule("a", "allow", ["url:https://app.example.com/**"],
              tools=["mcp://web/get"], operations=["network"]),
        _rule("d", "deny", ["url:https://app.example.com/admin/**"],
              tools=["mcp://web/get"], operations=["network"])),
    "deny for all agents vs allow for one": (
        _rule("a", "allow", ["fs:/srv/**"]),
        _rule("d", "deny", ["fs:/srv/secret/**"], agents=["*"])),
    "server wildcard overlaps exact tool": (
        _rule("a", "allow", ["fs:/srv/**"], tools=["mcp://fs/*"]),
        _rule("d", "deny", ["fs:/srv/secret/**"], tools=["mcp://fs/read_file"])),
    "deny with wildcard operations": (
        _rule("a", "allow", ["fs:/srv/**"]),
        _rule("d", "deny", ["fs:/srv/secret/**"], operations=["*"])),
    "conditions are not considered disjoint": (
        _rule("a", "allow", ["fs:/srv/**"], conditions='environment = ["dev"]'),
        _rule("d", "deny", ["fs:/srv/secret/**"], conditions='environment = ["prod"]')),
    "one of several patterns nested": (
        _rule("a", "allow", ["fs:/srv/public/**", "fs:/srv/**"]),
        _rule("d", "deny", ["fs:/etc/**", "fs:/srv/secret/**"])),
    "url host deny inside wildcard allow (host names have aliases)": (
        _rule("a", "allow", ["*"], tools=["mcp://web/get"], operations=["network"]),
        _rule("d", "deny", ["url:https://admin.example.com/**"],
              tools=["mcp://web/get"], operations=["network"])),
}


@pytest.mark.parametrize("rules", UNSAFE_CARVE_OUTS.values(), ids=UNSAFE_CARVE_OUTS.keys())
def test_unsafe_carve_outs_are_rejected(rules):
    assert IssueCode.UNSAFE_PATH_CARVE_OUT in _rejection_codes(_policy(*rules))


SAFE_SHAPES = {
    "disjoint agents": (
        _rule("a", "allow", ["fs:/srv/**"], agents=["reader"]),
        _rule("d", "deny", ["fs:/srv/secret/**"], agents=["other"])),
    "disjoint operations": (
        _rule("a", "allow", ["fs:/srv/**"], operations=["read"]),
        _rule("d", "deny", ["fs:/srv/secret/**"], operations=["write"])),
    "disjoint tools": (
        _rule("a", "allow", ["fs:/srv/**"], tools=["mcp://fs/stat"]),
        _rule("d", "deny", ["fs:/srv/secret/**"], tools=["mcp://fs/read_file"])),
    "sibling paths": (
        _rule("a", "allow", ["fs:/srv/public/**"]),
        _rule("d", "deny", ["fs:/srv/secret/**"])),
    "deny broader than allow": (
        _rule("a", "allow", ["fs:/srv/public/**"]), _rule("d", "deny", ["fs:/srv/**"])),
    "deny identical to allow": (
        _rule("a", "allow", ["fs:/srv/secret/**"]), _rule("d", "deny", ["fs:/srv/secret/**"])),
    "deny of the allowed directory entry itself": (
        _rule("a", "allow", ["fs:/srv/secret/**"]), _rule("d", "deny", ["fs:/srv/secret"])),
    "deny on wildcard resources": (
        _rule("a", "allow", ["fs:/srv/**"]), _rule("d", "deny", ["*"])),
    "different url origin": (
        _rule("a", "allow", ["url:https://app.example.com/**"],
              tools=["mcp://web/get"], operations=["network"]),
        _rule("d", "deny", ["url:https://admin.example.com/x/**"],
              tools=["mcp://web/get"], operations=["network"])),
    "root-wide fs deny inside wildcard allow (no fs alias escapes fs:/**)": (
        _rule("a", "allow", ["*"]), _rule("d", "deny", ["fs:/**"])),
}


@pytest.mark.parametrize("rules", SAFE_SHAPES.values(), ids=SAFE_SHAPES.keys())
def test_alias_safe_shapes_are_accepted(rules):
    load_policy_text(_policy(*rules))


# db:, secret: and shell: carve-outs are still ACCEPTED (changing that needs
# maintainer approval), but they are NOT alias-safe. These tests pin the
# current behavior and demonstrate the gap so it cannot be mistaken for a
# guarantee.

NOT_ALIAS_VERIFIED = {
    "db": (
        (_rule("a", "allow", ["db:crm/**"], tools=["mcp://db/query"]),
         _rule("d", "deny", ["db:crm/salaries"], tools=["mcp://db/query"])),
        "mcp://db/query", "read",
        "db:crm/salaries",
        # Schema-qualified spelling of the same table in many databases.
        "db:crm/public.salaries",
    ),
    "secret": (
        (_rule("a", "allow", ["secret:kv/**"], tools=["mcp://vault/read"]),
         _rule("d", "deny", ["secret:kv/app/key"], tools=["mcp://vault/read"])),
        "mcp://vault/read", "read",
        "secret:kv/app/key",
        # A key-value store's alternate API path for the same secret.
        "secret:kv/data/app/key",
    ),
    "shell": (
        (_rule("a", "allow", ["*"], tools=["mcp://shell/run"], operations=["execute"]),
         _rule("d", "deny", ["shell:rm"], tools=["mcp://shell/run"], operations=["execute"])),
        "mcp://shell/run", "execute",
        "shell:rm",
        # A different command with the same effect.
        "shell:unlink",
    ),
}


@pytest.mark.parametrize("case", NOT_ALIAS_VERIFIED.values(), ids=NOT_ALIAS_VERIFIED.keys())
def test_non_path_carve_outs_are_accepted_but_not_alias_safe(case):
    rules, tool, operation, denied, alias = case
    engine = PolicyEngine(load_policy_text(_policy(*rules)), clock=fixed_clock)
    assert _evaluate(engine, denied, tool=tool, operation=operation).decision is Decision.DENY
    # Known, documented gap: the alias is ALLOWED. Do not rely on db:/secret:/
    # shell: deny carve-outs; use allowlists.
    assert _evaluate(engine, alias, tool=tool, operation=operation).decision is Decision.ALLOW


CASE_CONFLICTS = {
    "author case mismatch (allow vs deny)": (
        _rule("a", "allow", ["fs:/srv/data/**"]), _rule("d", "deny", ["fs:/srv/Data/secret/**"])),
    "same depth": (
        _rule("a", "allow", ["fs:/srv/Secret/**"]), _rule("d", "deny", ["fs:/srv/secret/**"])),
    "exact files": (
        _rule("a", "allow", ["fs:/srv/Report.txt"]), _rule("d", "deny", ["fs:/srv/report.txt"])),
    "within one rule": (_rule("a", "allow", ["fs:/srv/a/**", "fs:/SRV/b/**"]),),
    "url path": (
        _rule("a", "allow", ["url:https://app.example.com/Docs/**"],
              tools=["mcp://web/get"], operations=["network"]),
        _rule("b", "allow", ["url:https://app.example.com/docs/x"],
              tools=["mcp://web/get"], operations=["network"])),
}


@pytest.mark.parametrize("rules", CASE_CONFLICTS.values(), ids=CASE_CONFLICTS.keys())
def test_case_conflicting_paths_are_rejected(rules):
    assert _rejection_codes(_policy(*rules)) == {IssueCode.PATH_CASE_CONFLICT}


def test_host_case_is_normalized_not_a_conflict():
    load_policy_text(_policy(
        _rule("a", "allow", ["url:https://Docs.Example.com/a/**"],
              tools=["mcp://web/get"], operations=["network"]),
        _rule("b", "allow", ["url:https://docs.example.com/a/b"],
              tools=["mcp://web/get"], operations=["network"]),
    ))


# ===========================================================================
# F-1 / H-1: allowlists fail closed for aliases; matching is unchanged
# ===========================================================================


@pytest.fixture(scope="module")
def allowlist_engine():
    return PolicyEngine(
        load_policy_text(_policy(_rule("public", "allow", ["fs:/srv/public/**"]))),
        clock=fixed_clock,
    )


@pytest.mark.parametrize(
    "resource",
    [
        "fs:/srv/secret/key",
        "fs:/srv/Secret/key",  # case variant of a path outside the allowlist
        "fs:/SRV/secret/key",
        "fs:/srv/SECRET~1/key",  # 8.3-style short-name alias
        "fs:/srv/PUBLIC/a",  # alias of the *allowed* prefix: denied (availability cost)
        "fs:/srv/PUBLI~1/a",
    ],
)
def test_aliases_outside_an_allowlist_fall_to_default_deny(allowlist_engine, resource):
    record = _evaluate(allowlist_engine, resource)
    assert record.decision is Decision.DENY
    assert record.reason_code is ReasonCode.DEFAULT_DENY


@pytest.mark.parametrize("resource", ["fs:/srv/public/a", "fs:/srv/public/notes~", "fs:/srv/public/~tmp/x"])
def test_tilde_is_still_accepted_inside_allowed_paths(allowlist_engine, resource):
    # '~' is NOT rejected: it would not remove all short-name aliases (short
    # names can be set without '~') and is common on POSIX systems.
    assert _evaluate(allowlist_engine, resource).decision is Decision.ALLOW


def test_matching_remains_case_sensitive():
    engine = PolicyEngine(
        load_policy_text(_policy(_rule("data", "allow", ["fs:/srv/Data/**"]))),
        clock=fixed_clock,
    )
    assert _evaluate(engine, "fs:/srv/Data/x").decision is Decision.ALLOW
    record = _evaluate(engine, "fs:/srv/data/x")
    assert record.decision is Decision.DENY
    assert record.reason_code is ReasonCode.DEFAULT_DENY


# --- ALIAS_DOWNGRADE_RISK (blocking): alias would turn DENY into REQUIRE_APPROVAL


def test_deny_inside_require_approval_is_rejected():
    with pytest.raises(PolicyValidationError) as info:
        load_policy_text(_policy(
            _rule("approve", "require_approval", ["fs:/srv/**"]),
            _rule("deny", "deny", ["fs:/srv/secret/**"]),
        ))
    assert info.value.codes == (IssueCode.ALIAS_DOWNGRADE_RISK,)
    assert info.value.issues[0].path == "rules[1].resources"
    assert "rules[0]" in info.value.issues[0].message


DOWNGRADE_REJECTED = {
    "fs deny inside require_approval": (
        (_rule("p", "require_approval", ["fs:/srv/**"]), _rule("d", "deny", ["fs:/srv/x/**"])), ""),
    "fs deny inside wildcard require_approval": (
        (_rule("p", "require_approval", ["*"]), _rule("d", "deny", ["fs:/srv/x"])), ""),
    "url deny inside require_approval": (
        (_rule("p", "require_approval", ["url:https://app.example.com/**"],
               tools=["mcp://web/get"], operations=["network"]),
         _rule("d", "deny", ["url:https://app.example.com/admin/**"],
               tools=["mcp://web/get"], operations=["network"])), ""),
    "fs deny under require_approval default": (
        (_rule("d", "deny", ["fs:/srv/secret/**"]),), 'decision = "require_approval"'),
    "url host deny under require_approval default": (
        (_rule("d", "deny", ["url:https://admin.example.com/**"],
               tools=["mcp://web/get"], operations=["network"]),), 'decision = "require_approval"'),
}


@pytest.mark.parametrize("case", DOWNGRADE_REJECTED.values(), ids=DOWNGRADE_REJECTED.keys())
def test_alias_downgrade_shapes_are_rejected(case):
    rules, defaults = case
    assert _rejection_codes(_policy(*rules, defaults=defaults)) == {IssueCode.ALIAS_DOWNGRADE_RISK}


DOWNGRADE_ACCEPTED = {
    "disjoint agents": (
        (_rule("p", "require_approval", ["fs:/srv/**"], agents=["a"]),
         _rule("d", "deny", ["fs:/srv/x/**"], agents=["b"])), ""),
    "deny broader than approval": (
        (_rule("p", "require_approval", ["fs:/srv/x/**"]), _rule("d", "deny", ["fs:/srv/**"])), ""),
    "root-wide fs deny under require_approval default": (
        (_rule("d", "deny", ["fs:/**"]),), 'decision = "require_approval"'),
    "approval rule nested in deny (stronger outside)": (
        (_rule("d", "deny", ["fs:/srv/**"]), _rule("p", "require_approval", ["fs:/srv/x/**"])), ""),
    "deny default with nested deny": (
        (_rule("d", "deny", ["fs:/srv/x/**"]),), 'decision = "deny"'),
}


@pytest.mark.parametrize("case", DOWNGRADE_ACCEPTED.values(), ids=DOWNGRADE_ACCEPTED.keys())
def test_non_downgrade_shapes_are_accepted(case):
    rules, defaults = case
    load_policy_text(_policy(*rules, defaults=defaults))


def test_downgrade_is_no_longer_a_lint_warning():
    assert not hasattr(LintCode, "ALIAS_DOWNGRADE_RISK")
    assert IssueCode.ALIAS_DOWNGRADE_RISK == "ALIAS_DOWNGRADE_RISK"


# --- Existing valid policies still load ---------------------------------------


def test_existing_baseline_policy_is_still_valid():
    from policy_fixtures import BASELINE_POLICY

    policy = load_policy_text(BASELINE_POLICY)
    assert len(policy.rules) == 10
    assert {issue.code for issue in lint_policy(policy)} <= {"HIGH_RISK_ALLOW"}


# --- db: and secret: identifier semantics -------------------------------------


@pytest.mark.parametrize(
    ("raw", "kind", "authority", "segments"),
    [
        ("db:crm", "db", "crm", ()),
        ("db:crm/salaries", "db", "crm", ("salaries",)),
        ("db:crm/public.salaries", "db", "crm", ("public.salaries",)),  # one opaque segment
        ("secret:kv/app/key", "secret", "", ("kv", "app", "key")),
        ("secret:kv/data/app/key", "secret", "", ("kv", "data", "app", "key")),
    ],
)
def test_db_and_secret_identifiers_are_opaque_names(raw, kind, authority, segments):
    ref = parse_resource(raw)
    assert (ref.kind.value, ref.authority, ref.segments) == (kind, authority, segments)
    # No schema, view, synonym or API-path knowledge: different spellings stay
    # different identifiers even when a backend treats them as the same object.


@pytest.mark.parametrize(
    "raw",
    [
        "db:CRM/salaries",  # uppercase rejected, not folded
        "db:crm/Salaries",
        'db:crm/"salaries"',  # quoted identifiers cannot be expressed
        "db:crm/public/salaries",  # at most database/table
        "db:crm/",
        "db:/salaries",
        "db:crm/sal aries",
        "secret:Kv/app",
        "secret:kv//app",
        "secret:kv/./app",
        "secret:kv/../app",
        "secret:/kv/app",
        "secret:kv/app/",
        "secret:" + "/".join(["s"] * 17),  # more than 16 segments
    ],
)
def test_db_and_secret_identifier_rejections(raw):
    with pytest.raises(ResourceError):
        parse_resource(raw)


def test_db_prefix_matches_by_segment_not_by_string():
    from rig_sentinel.policy.matching import parse_resource_pattern

    pattern = parse_resource_pattern("db:crm/**")
    assert pattern.matches(parse_resource("db:crm/salaries"))
    assert pattern.matches(parse_resource("db:crm/public.salaries"))
    assert not pattern.matches(parse_resource("db:crm2/salaries"))
    exact = parse_resource_pattern("db:crm/salaries")
    assert not exact.matches(parse_resource("db:crm/public.salaries"))


# ===========================================================================
# Ambiguous resource identifiers and traversal
# ===========================================================================


@pytest.mark.parametrize(
    "resource",
    [
        "fs:/srv/CON",
        "fs:/srv/con",
        "fs:/srv/nul.txt",
        "fs:/srv/Aux/x",
        "fs:/srv/COM1",
        "fs:/srv/lpt9.log",
        "fs:/srv/prn.tar.gz",
        "fs:/srv/secret/../secret/key",
        "fs:/srv/./secret/..",
        "fs:/srv/%73ecret/key",
        "fs:/srv\\secret\\key",
        "fs:/srv/secret/key::$DATA",
        "fs:/srv/secret/key.",
        "fs://server/share/key",
        "fs:/srv/" + "a" * 256,
    ],
)
def test_ambiguous_fs_identifiers_are_rejected(resource):
    with pytest.raises(ResourceError):
        parse_resource(resource)


@pytest.mark.parametrize(
    "resource",
    ["fs:/srv/console", "fs:/srv/null", "fs:/srv/com10", "fs:/srv/conf.d", "url:https://docs.example.com/con"],
)
def test_similar_but_unambiguous_names_are_accepted(resource):
    parse_resource(resource)


# ===========================================================================
# H-2: Unicode is out of scope and rejected (no normalization)
# ===========================================================================

UNICODE_VARIANTS = {
    "nfc_e_acute": "café",
    "nfd_e_combining": "café",
    "cyrillic_a": "cаfe",
    "greek_omicron": "infο",
    "fullwidth_c": "ｃafe",
    "zero_width_space": "ca​fe",
    "byte_order_mark": "﻿cafe",
    "rtl_override": "cafe‮",
    "no_break_space": "ca fe",
    "kelvin_sign": "Kfile",  # lowercases to ASCII 'k'
    "long_s": "ſecret",  # uppercases to ASCII 'S'
    "dotless_i": "admın",
}


def test_nfc_and_nfd_forms_are_distinct_and_both_rejected():
    import unicodedata

    assert unicodedata.normalize("NFC", UNICODE_VARIANTS["nfd_e_combining"]) == UNICODE_VARIANTS["nfc_e_acute"]
    for variant in ("nfc_e_acute", "nfd_e_combining"):
        with pytest.raises(ResourceError):
            parse_resource("fs:/srv/" + UNICODE_VARIANTS[variant])


@pytest.fixture(scope="module")
def unicode_engine():
    return PolicyEngine(
        load_policy_text(_policy(_rule("public", "allow", ["fs:/srv/**"], agents=["*"]))),
        clock=fixed_clock,
    )


@pytest.mark.parametrize("value", UNICODE_VARIANTS.values(), ids=UNICODE_VARIANTS.keys())
@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("agent", ReasonCode.INVALID_IDENTITY),
        ("tool", ReasonCode.INVALID_TOOL_ID),
        ("fs", ReasonCode.INVALID_RESOURCE),
        ("url_host", ReasonCode.INVALID_RESOURCE),
        ("url_path", ReasonCode.INVALID_RESOURCE),
        ("email", ReasonCode.INVALID_RESOURCE),
        ("label", ReasonCode.INVALID_REQUEST),
        ("operation", ReasonCode.UNKNOWN_OPERATION),
    ],
)
def test_unicode_in_requests_is_denied(unicode_engine, value, field, reason):
    request = {
        "agent": {"id": "bot"},
        "tool": {"id": "mcp://fs/read_file"},
        "operation": "read",
        "resource": "fs:/srv/x",
        "context": {"environment": "dev", "labels": []},
    }
    if field == "agent":
        request["agent"]["id"] = "bot-" + value
    elif field == "tool":
        request["tool"]["id"] = f"mcp://fs/{value}"
    elif field == "fs":
        request["resource"] = f"fs:/srv/{value}"
    elif field == "url_host":
        request["resource"] = f"url:https://{value}.example.com/"
    elif field == "url_path":
        request["resource"] = f"url:https://docs.example.com/{value}"
    elif field == "email":
        request["resource"] = f"email:{value}.example.com"
    elif field == "label":
        request["context"]["labels"] = [value]
    elif field == "operation":
        request["operation"] = "re" + value
    record = unicode_engine.evaluate(request)
    assert record.decision is Decision.DENY
    assert record.reason_code is reason


@pytest.mark.parametrize("value", UNICODE_VARIANTS.values(), ids=UNICODE_VARIANTS.keys())
@pytest.mark.parametrize("where", ["policy_id", "rule_id", "agent_pattern", "resource_pattern", "label"])
def test_unicode_in_policies_is_rejected(value, where):
    text = _policy(_rule("r", "allow", ["fs:/srv/**"]))
    if where == "policy_id":
        text = text.replace('policy_id = "hardening"', f'policy_id = "p{value}"')
    elif where == "rule_id":
        text = text.replace('id = "r"', f'id = "r{value}"')
    elif where == "agent_pattern":
        text = text.replace('agents = ["bot"]', f'agents = ["bot{value}"]')
    elif where == "resource_pattern":
        text = text.replace('"fs:/srv/**"', f'"fs:/srv/{value}/**"')
    elif where == "label":
        text += f'\n[rules.conditions]\nlabels_none = ["{value}"]\n'
    with pytest.raises(PolicyValidationError):
        load_policy_text(text)


# ===========================================================================
# H-4: identity and context are caller-asserted (no authentication)
# ===========================================================================


def test_assurance_is_taken_from_the_request_not_verified():
    engine = PolicyEngine(
        load_policy_text(_policy(
            _rule("auth-only", "allow", ["fs:/srv/**"], conditions='min_assurance = "authenticated"'),
        )),
        clock=fixed_clock,
    )
    base = {
        "tool": {"id": "mcp://fs/read_file"},
        "operation": "read",
        "resource": "fs:/srv/x",
        "context": {"environment": "dev"},
    }
    # The engine cannot tell who sent this: whoever builds the request decides
    # the assurance level. Authentication belongs to the enforcement adapter.
    claimed = engine.evaluate({**base, "agent": {"id": "bot", "assurance": "authenticated"}})
    asserted = engine.evaluate({**base, "agent": {"id": "bot", "assurance": "asserted"}})
    assert claimed.decision is Decision.ALLOW
    assert asserted.decision is Decision.DENY


@pytest.mark.parametrize("field", ["token", "signature", "credentials", "authenticated_by"])
def test_requests_carry_no_credential_fields(field):
    engine = PolicyEngine(load_policy_text(_policy(_rule("r", "allow", ["fs:/srv/**"]))), clock=fixed_clock)
    request = {
        "agent": {"id": "bot", field: "x"},
        "tool": {"id": "mcp://fs/read_file"},
        "operation": "read",
        "resource": "fs:/srv/x",
        "context": {"environment": "dev"},
    }
    assert engine.evaluate(request).reason_code is ReasonCode.INVALID_REQUEST


def test_context_labels_are_caller_asserted():
    engine = PolicyEngine(
        load_policy_text(_policy(
            _rule("read", "allow", ["fs:/srv/**"]),
            _rule("tainted", "deny", ["*"], agents=["*"], tools=["*"], operations=["*"],
                  conditions='labels_all = ["untrusted_content_present"]'),
        )),
        clock=fixed_clock,
    )
    # If the caller omits the label, the label-based deny cannot apply.
    assert _evaluate(engine, "fs:/srv/x").decision is Decision.ALLOW


# ===========================================================================
# Exception boundary: Exception -> DENY; other BaseException propagates
# ===========================================================================


@pytest.fixture()
def simple_engine():
    return PolicyEngine(load_policy_text(_policy(_rule("r", "allow", ["fs:/srv/**"]))), clock=fixed_clock)


@pytest.mark.parametrize("error", [RecursionError, MemoryError, ValueError, KeyError, ZeroDivisionError])
def test_exception_subclasses_become_deny(monkeypatch, simple_engine, error):
    def boom(*_args, **_kwargs):
        raise error()

    monkeypatch.setattr(engine_module, "rule_matches", boom)
    record = _evaluate(simple_engine, "fs:/srv/x")
    assert record.decision is Decision.DENY
    assert record.reason_code is ReasonCode.EVALUATION_ERROR
    assert record.error_type == error.__name__


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_base_exceptions_propagate(monkeypatch, simple_engine, error):
    def boom(*_args, **_kwargs):
        raise error()

    monkeypatch.setattr(engine_module, "rule_matches", boom)
    with pytest.raises(error):
        _evaluate(simple_engine, "fs:/srv/x")


def test_self_referencing_request_data_is_denied(simple_engine):
    labels: list = []
    labels.append(labels)  # self-referencing list
    request = {
        "agent": {"id": "bot"},
        "tool": {"id": "mcp://fs/read_file"},
        "operation": "read",
        "resource": "fs:/srv/x",
        "context": {"environment": "dev", "labels": labels},
    }
    assert simple_engine.evaluate(request).decision is Decision.DENY
