"""M1-H1: ``error_type`` must not carry text from untrusted exception classes.

Exceptions raised during evaluation can come from caller-supplied objects
(a mapping, a clock). Their class names, metaclass properties and comparison
methods are attacker-controlled, so the engine records a class name only for
Python's built-in ``Exception`` classes, matched by identity, and
``UnlistedError`` for everything else. Synthetic canary values only.
"""

import builtins
import os
import random
import re
import sys
from collections.abc import Mapping

import pytest
from policy_fixtures import baseline_engine, make_request

import rig_sentinel.policy.engine as engine_module
from rig_sentinel.policy import Decision, ReasonCode
from rig_sentinel.policy.canonical import canonical_json
from rig_sentinel.policy.decision import ENGINE_VERSION

CANARY = "sk-" + "test-" + "CANARY-" + "7f3a9c"  # synthetic, built from parts
SAFE_ERROR_TYPE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")  # e.g. _IncompleteInputError


def _raising_mapping(exc_class):
    """A request mapping that raises ``exc_class`` as soon as it is read."""

    class HostileRequest(Mapping):
        def __getitem__(self, key):
            raise exc_class()

        def __iter__(self):
            raise exc_class()

        def __len__(self):
            return 5

    return HostileRequest()


def _assert_unlisted_and_clean(record):
    assert record.decision is Decision.DENY
    assert record.reason_code is ReasonCode.EVALUATION_ERROR
    assert record.error_type == "UnlistedError"
    assert getattr(engine_module, "UNLISTED_ERROR_TYPE", None) == "UnlistedError"
    assert record.enforced is False
    for text in (repr(record), str(record), str(record.to_dict())):
        assert CANARY not in text
    raw = canonical_json(record.to_dict())
    assert CANARY.encode() not in raw


# --- Hostile class names ------------------------------------------------------------

HOSTILE_NAMES = {
    "canary with newline and ANSI escape": "Leak\n" + CANARY + "\x1b[31m",
    "canary only": CANARY,
    "bidi override and zero-width": "Err\u202e\u200b" + CANARY,
    "non-ASCII letters": "\u041e\u0448\u0438\u0431\u043a\u0430" + CANARY,
    "very long": "X" * 500 + CANARY,
    "empty": "",
    "spaces and quotes": 'a "b" \' c ' + CANARY,
    "carriage return and tab": "A\rB\t" + CANARY,  # CPython rejects NUL in class names
    "built-in name": "ValueError",
    "built-in name with canary": "ValueError" + CANARY,
}


@pytest.mark.parametrize("name", HOSTILE_NAMES.values(), ids=HOSTILE_NAMES.keys())
def test_hostile_exception_class_names_are_not_recorded(name):
    hostile_class = type(name, (Exception,), {})
    record = baseline_engine().evaluate(_raising_mapping(hostile_class))
    _assert_unlisted_and_clean(record)


@pytest.mark.parametrize("base", [ValueError, KeyError, RuntimeError, OSError])
def test_subclass_of_builtin_with_the_same_name_is_unlisted(base):
    spoof = type(base.__name__, (base,), {})
    record = baseline_engine().evaluate(_raising_mapping(spoof))
    _assert_unlisted_and_clean(record)


# --- Hostile metaclasses: nothing on the class may be consulted -----------------------


_PACKAGE_DIR = os.path.normcase(os.path.dirname(os.path.dirname(engine_module.__file__)))
_NAME_AND_COMPARISON_HOOKS = {"__name__", "__module__", "__eq__", "__hash__"}


class _AccessLog:
    """Records which metaclass hooks ran, and whether rig_sentinel code triggered them."""

    def __init__(self):
        self.events = []

    def note(self, hook):
        caller = sys._getframe(2)  # 0 = note, 1 = the hook, 2 = the code that triggered it
        path = os.path.normcase(os.path.abspath(caller.f_code.co_filename))
        self.events.append((hook, path.startswith(_PACKAGE_DIR)))

    def assert_engine_never_consulted_the_class(self):
        # CPython's own `raise` statement may call __subclasscheck__ in the raising
        # (caller-supplied) frame; that is outside the engine and outside its control.
        assert [hook for hook, _ in self.events if hook in _NAME_AND_COMPARISON_HOOKS] == []
        assert [hook for hook, from_package in self.events if from_package] == []


def _metaclass_that_records(log, *, name_behavior):
    class HostileMeta(type):
        @property
        def __name__(cls):
            log.note("__name__")
            return name_behavior()

        @property
        def __module__(cls):
            log.note("__module__")
            return name_behavior()

        def __eq__(cls, other):
            log.note("__eq__")
            return True  # would claim to equal ValueError if consulted

        def __hash__(cls):
            log.note("__hash__")
            return hash(ValueError)

        def __instancecheck__(cls, instance):
            log.note("__instancecheck__")
            return True

        def __subclasscheck__(cls, subclass):
            log.note("__subclasscheck__")
            return True

    return HostileMeta


def _raise(error):
    raise error


NAME_BEHAVIORS = {
    "name raises": lambda: _raise(RuntimeError("lookup failed " + CANARY)),
    "name is not a string": lambda: 12345,
    "name is a str subclass": lambda: type("Sneaky", (str,), {})("Sneaky\n" + CANARY),
    "name is ValueError": lambda: "ValueError",
}


@pytest.mark.parametrize("behavior", NAME_BEHAVIORS.values(), ids=NAME_BEHAVIORS.keys())
def test_hostile_metaclass_is_never_consulted_and_evaluate_returns_deny(behavior):
    log = _AccessLog()
    meta = _metaclass_that_records(log, name_behavior=behavior)
    hostile_class = meta("HostileError", (Exception,), {})
    log.events.clear()  # ignore anything Python itself did while creating the class

    escaped = False
    try:
        record = baseline_engine().evaluate(_raising_mapping(hostile_class))
    except BaseException:  # noqa: BLE001 - do not let pytest render the hostile class
        escaped = True
    if escaped:
        pytest.fail("evaluate() raised instead of returning DENY / EVALUATION_ERROR")

    _assert_unlisted_and_clean(record)
    log.assert_engine_never_consulted_the_class()


def test_metaclass_getattribute_is_never_consulted():
    log = _AccessLog()

    class TrapMeta(type):
        def __getattribute__(cls, attribute):
            log.events.append(attribute)
            raise RuntimeError("attribute trap " + CANARY)

    hostile_class = TrapMeta("TrapError", (Exception,), {})
    log.events.clear()
    escaped = False
    try:
        record = baseline_engine().evaluate(_raising_mapping(hostile_class))
    except BaseException:  # noqa: BLE001 - do not let pytest render the hostile class
        escaped = True
    if escaped:
        pytest.fail("evaluate() raised instead of returning DENY / EVALUATION_ERROR")
    _assert_unlisted_and_clean(record)
    assert log.events == []


def test_spoofed_dunder_class_is_ignored():
    class Disguised(Exception):
        @property
        def __class__(self):
            return ValueError  # isinstance() would be fooled; type() is not

    record = baseline_engine().evaluate(_raising_mapping(Disguised))
    _assert_unlisted_and_clean(record)


def test_multiple_inheritance_valueerror_subclass_with_hostile_metaclass_is_unlisted():
    # Valid under Python's metaclass rules: ValueError and the mixin both use `type`,
    # and the hostile metaclass derives from `type`. The class is a genuine ValueError
    # subclass that also claims the name "ValueError" and equality with ValueError.
    class _PlainMixin:
        pass

    log = _AccessLog()
    meta = _metaclass_that_records(log, name_behavior=lambda: "ValueError")
    hostile_class = meta("ValueError", (ValueError, _PlainMixin), {})
    assert type.__subclasscheck__(ValueError, hostile_class)  # real subclass, checked via `type`
    assert hostile_class is not ValueError
    log.events.clear()

    escaped = False
    try:
        record = baseline_engine().evaluate(_raising_mapping(hostile_class))
    except BaseException:  # noqa: BLE001 - do not let pytest render the hostile class
        escaped = True
    if escaped:
        pytest.fail("evaluate() raised instead of returning DENY / EVALUATION_ERROR")

    _assert_unlisted_and_clean(record)
    log.assert_engine_never_consulted_the_class()


def test_hostile_exception_from_clock_is_unlisted():
    hostile_class = type("ClockLeak\n" + CANARY, (Exception,), {})

    def clock():
        raise hostile_class()

    record = baseline_engine(clock=clock).evaluate(make_request())
    _assert_unlisted_and_clean(record)
    assert record.evaluated_at is None


def test_generated_class_names_always_give_a_safe_error_type():
    rng = random.Random(20261109)
    # Every code point except surrogates and NUL (CPython rejects NUL in class names).
    alphabet = [chr(code) for code in range(1, 0x110000) if not 0xD800 <= code <= 0xDFFF]
    engine = baseline_engine()
    for _ in range(300):
        name = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 80)))
        record = engine.evaluate(_raising_mapping(type(name, (Exception,), {})))
        assert record.reason_code is ReasonCode.EVALUATION_ERROR
        assert SAFE_ERROR_TYPE.fullmatch(record.error_type)
        assert record.error_type == "UnlistedError"


# --- Compatibility: built-ins and normal requests are unchanged -----------------------

BUILTIN_EXCEPTIONS = sorted(
    {
        obj
        for obj in vars(builtins).values()
        if isinstance(obj, type) and issubclass(obj, Exception)
    },
    key=lambda cls: cls.__name__,
)


def _instance_of(error):
    if error is ExceptionGroup:
        return ExceptionGroup("group", [ValueError()])
    return error.__new__(error)  # skip __init__: some built-ins require arguments


@pytest.mark.parametrize("error", BUILTIN_EXCEPTIONS, ids=lambda cls: cls.__name__)
def test_every_builtin_exception_keeps_its_name(monkeypatch, error):
    def boom(*_args, **_kwargs):
        raise _instance_of(error)

    monkeypatch.setattr(engine_module, "rule_matches", boom)
    record = baseline_engine().evaluate(make_request())
    assert record.decision is Decision.DENY
    assert record.reason_code is ReasonCode.EVALUATION_ERROR
    assert record.error_type == error.__name__
    assert SAFE_ERROR_TYPE.fullmatch(record.error_type)


def test_approved_table_holds_only_plain_builtin_classes_with_safe_names():
    table = engine_module._APPROVED_ERROR_TYPES
    assert len(table) == len(BUILTIN_EXCEPTIONS)  # every built-in, each listed once
    for cls, name in table:
        assert type(cls) is type and issubclass(cls, Exception)
        assert getattr(builtins, name) is cls
        assert SAFE_ERROR_TYPE.fullmatch(name)
    assert len({id(cls) for cls, _ in table}) == len(table)


def test_approved_table_ignores_hostile_objects_planted_in_builtins(monkeypatch):
    log = _AccessLog()
    meta = _metaclass_that_records(log, name_behavior=lambda: "Planted" + CANARY)
    monkeypatch.setattr(builtins, "PlantedMetaError", meta("PlantedMetaError", (Exception,), {}),
                        raising=False)
    monkeypatch.setattr(builtins, "PlantedNameError",
                        type("Planted\n" + CANARY, (Exception,), {}), raising=False)
    log.events.clear()

    table = engine_module._approved_error_types()

    names = [name for _, name in table]
    assert all(CANARY not in name and SAFE_ERROR_TYPE.fullmatch(name) for name in names)
    planted = (builtins.PlantedMetaError, builtins.PlantedNameError)
    assert not any(cls is bad for cls, _ in table for bad in planted)  # identity, not ==
    assert [hook for hook, _ in log.events if hook in _NAME_AND_COMPARISON_HOOKS] == []


def test_builtin_aliases_record_the_canonical_name(monkeypatch):
    def boom(*_args, **_kwargs):
        raise builtins.IOError()  # alias of OSError

    monkeypatch.setattr(engine_module, "rule_matches", boom)
    assert baseline_engine().evaluate(make_request()).error_type == "OSError"


# decision_digest values captured from the unmodified engine at main a73a424
# (fixed clock, baseline policy). They must not change.
GOLDEN_DIGESTS = {
    "allow": "6f3994782b59c4e2168cc3679bc340a5e8514fbf179f957c6b178fe064547df5",
    "default_deny": "af720fe27cff0add98cde73cdbc23db1373c027efcee84646063d7654ddea3f3",
    "invalid_resource": "82987cb647a6e1831ac8cc306a708d398ec7ea535258a600c95d37911125640c",
    "RuntimeError": "6d5efc902ffb551353c701d715f5880f31fbb79f57ac991187e5adf73bbecff5",
    "ValueError": "42a74162052248eb820dee6ffbd1157a91c31c240559dd85cda87b825a8bb649",
    "KeyError": "9985332ea429d55c7765155924e15db5de42c9cc71dd038d567343a1ea03eb13",
    "ZeroDivisionError": "932620ac5f2597cb60ca35bef5203f149dea11e7556f6d0f74df807e340d8e3e",
    "RecursionError": "66b44efb496b9b903b4cbbe6803b8875b24030b7043a346c1eade9563d2fc433",
    "MemoryError": "257fbab6e0766e2f6ccef9059763a2e72f9ea030c8eed7e783a4f76bd18aa0bd",
    "OSError": "5ed3c30db3156c7167b683a7cd05a099c575aa53bc194cf5744b4ddbcdb8b570",
}


def test_normal_decision_digests_are_unchanged():
    engine = baseline_engine()
    assert engine.evaluate(make_request()).decision_digest == GOLDEN_DIGESTS["allow"]
    assert (
        engine.evaluate(make_request(resource="db:helpdesk/users")).decision_digest
        == GOLDEN_DIGESTS["default_deny"]
    )
    assert (
        engine.evaluate(make_request(resource="fs:/a/../b")).decision_digest
        == GOLDEN_DIGESTS["invalid_resource"]
    )


@pytest.mark.parametrize(
    "error",
    [RuntimeError, ValueError, KeyError, ZeroDivisionError, RecursionError, MemoryError, OSError],
    ids=lambda cls: cls.__name__,
)
def test_builtin_failure_digests_are_unchanged(monkeypatch, error):
    def boom(*_args, **_kwargs):
        raise error()

    monkeypatch.setattr(engine_module, "rule_matches", boom)
    record = baseline_engine().evaluate(make_request())
    assert record.error_type == error.__name__
    assert record.decision_digest == GOLDEN_DIGESTS[error.__name__]


def test_engine_version_and_record_keys_are_unchanged():
    assert ENGINE_VERSION == "genesis-b2-m1"
    record = baseline_engine().evaluate(_raising_mapping(type("X", (Exception,), {})))
    assert list(record.to_dict()) == [
        "record_schema", "decision", "reason_code", "deciding_rule_ids", "matched_rule_ids",
        "policy_id", "policy_version", "policy_sha256", "schema_version", "engine_version",
        "request_digest", "evaluated_at", "protected", "approval", "error_type", "enforced",
        "decision_digest",
    ]


def test_base_exceptions_with_hostile_names_still_propagate():
    hostile_interrupt = type("Interrupt\n" + CANARY, (KeyboardInterrupt,), {})
    with pytest.raises(KeyboardInterrupt):
        baseline_engine().evaluate(_raising_mapping(hostile_interrupt))
