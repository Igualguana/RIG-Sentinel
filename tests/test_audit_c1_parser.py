"""Genesis B2-M2-C1: bounded canonical JSON pre-scan and strict parser (pure).

The pre-scan is a byte-level state machine (string, escape and \\uXXXX aware) that runs
before json.loads; json.loads then runs with duplicate-key, constant, float and integer hooks,
followed by a canonical round-trip check. Synthetic values only.
"""

import json

import pytest

from rig_sentinel.audit import bounded_json as bj
from rig_sentinel.audit.records import StorageError, StorageErrorCode
from rig_sentinel.policy.canonical import canonical_json


def code_of(fn, *args, **kwargs):
    with pytest.raises(StorageError) as info:
        fn(*args, **kwargs)
    error = info.value
    assert error.__context__ is None and error.__cause__ is None
    return error.code


@pytest.fixture
def no_json_loads(monkeypatch):
    calls = []

    def spy(*args, **kwargs):
        calls.append(1)
        raise AssertionError("json.loads must not be called")

    monkeypatch.setattr(bj.json, "loads", spy)
    return calls


# --- accepted canonical inputs --------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [{}, [], {"a": 1}, {"a": [1, 2, {"b": None}]}, {"k": "x\"y\\z\n\t\u0001\u007f\u00e9\u2028"},
     {"t": True, "f": False, "n": None}, {"neg": -12345678901234567}, [[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]],
     {"s": "{[\\\"]}"}],
    ids=["empty-obj", "empty-list", "simple", "nested", "escapes", "literals", "negative", "depth-16", "braces-in-string"],
)
def test_canonical_json_round_trips(value):
    data = canonical_json(value)
    assert bj.strict_canonical_loads(data, max_bytes=20_480) == value


def test_depth_sixteen_is_the_exact_limit():
    ok = b"[" * 16 + b"]" * 16
    assert bj.strict_canonical_loads(ok, max_bytes=20_480) == json.loads(ok)
    assert code_of(bj.strict_canonical_loads, b"[" * 17 + b"]" * 17, max_bytes=20_480) is StorageErrorCode.DEPTH_EXCEEDED


# --- nesting attacks (rejected before json.loads) ---------------------------------------------


@pytest.mark.parametrize("levels", [17, 65, 1_000, 10_000])
@pytest.mark.parametrize("opener, closer", [(b"[", b"]"), (b'{"a":', b"}")], ids=["arrays", "objects"])
def test_deep_nesting_is_rejected_before_json_loads(levels, opener, closer, no_json_loads):
    data = opener * levels + b"1" + closer * levels
    limit = max(len(data), 20_480)
    assert code_of(bj.strict_canonical_loads, data, max_bytes=limit) is StorageErrorCode.DEPTH_EXCEEDED
    assert no_json_loads == []


def test_one_hundred_thousand_levels_are_rejected_by_size_before_scanning(no_json_loads):
    data = b"[" * 100_000 + b"]" * 100_000
    assert code_of(bj.strict_canonical_loads, data, max_bytes=20_480) is StorageErrorCode.LINE_TOO_LONG
    assert no_json_loads == []


def test_one_hundred_thousand_levels_within_a_large_bound_hit_the_depth_limit(no_json_loads):
    data = b"[" * 100_000 + b"]" * 100_000
    assert code_of(bj.strict_canonical_loads, data, max_bytes=len(data)) is StorageErrorCode.DEPTH_EXCEEDED
    assert no_json_loads == []


@pytest.mark.parametrize(
    "inside",
    [b'"{{{{{{{{{{{{{{{{{{{{"', b'"\\"{{{{{{{{{{{{{{{{{{{"', b'"\\\\"', b'"\\u007b\\u005b"', b'"}]}]}]"'],
    ids=["braces", "after-escaped-quote", "escaped-backslash", "unicode-braces", "closers"],
)
def test_brackets_inside_strings_never_count_as_nesting(inside):
    # Pre-scan layer on its own: 15 real levels plus a string full of bracket characters.
    data = b"[" * 15 + inside + b"]" * 15
    bj.prescan(data, max_bytes=20_480)


def test_escaped_backslash_then_real_bracket_counts():
    data = b'["\\\\",' + b"[" * 16 + b"1" + b"]" * 16 + b"]"
    assert code_of(bj.prescan, data, max_bytes=20_480) is StorageErrorCode.DEPTH_EXCEEDED
    assert code_of(bj.strict_canonical_loads, data, max_bytes=20_480) is StorageErrorCode.DEPTH_EXCEEDED


def test_canonical_strings_with_bracket_characters_round_trip():
    value = ["{{{", "\"[[", "\\", "}]"]
    data = canonical_json([[[[[[[[[[[[[[[value]]]]]]]]]]]]]]])
    assert bj.strict_canonical_loads(data, max_bytes=20_480) == [[[[[[[[[[[[[[[value]]]]]]]]]]]]]]]


# --- lexical attacks ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data, expected",
    [
        (b'"abc', StorageErrorCode.UNTERMINATED),
        (b'"abc\\', StorageErrorCode.UNTERMINATED),
        (b'["a"', StorageErrorCode.UNTERMINATED),
        (b'"\\x"', StorageErrorCode.BAD_ESCAPE),
        (b'"\\u12"', StorageErrorCode.BAD_ESCAPE),
        (b'"\\uZZZZ"', StorageErrorCode.BAD_ESCAPE),
        (b'"\\u12g4"', StorageErrorCode.BAD_ESCAPE),
        (b'"a\x01b"', StorageErrorCode.BYTE_NOT_ALLOWED),
        (b'"a\tb"', StorageErrorCode.BYTE_NOT_ALLOWED),
        (b'{"a":1}\n', StorageErrorCode.BYTE_NOT_ALLOWED),
        (b'\xef\xbb\xbf{}', StorageErrorCode.BYTE_NOT_ALLOWED),
        ('"\u00e9"'.encode(), StorageErrorCode.BYTE_NOT_ALLOWED),
        (b'"\xc3\x28"', StorageErrorCode.BYTE_NOT_ALLOWED),
        (b'"\xc0\xaf"', StorageErrorCode.BYTE_NOT_ALLOWED),
        (b'"\x7f"', StorageErrorCode.BYTE_NOT_ALLOWED),
        (b'"\xff"', StorageErrorCode.BYTE_NOT_ALLOWED),
        (b"[1}", StorageErrorCode.UNBALANCED),
        (b"{]", StorageErrorCode.UNBALANCED),
        (b"]", StorageErrorCode.UNBALANCED),
        (b'{"a": 1}', StorageErrorCode.TOKEN_INVALID),
        (b"[1.5]", StorageErrorCode.TOKEN_INVALID),
        (b"[1E5]", StorageErrorCode.TOKEN_INVALID),
        (b"[+1]", StorageErrorCode.TOKEN_INVALID),
        (b"[" + b"9" * 21 + b"]", StorageErrorCode.NUMBER_TOO_LONG),
        (b'"' + b"a" * 4097 + b'"', StorageErrorCode.STRING_TOO_LONG),
        (b"", StorageErrorCode.MALFORMED_JSON),
    ],
    ids=["unterminated", "trailing-backslash", "open-array", "bad-escape", "short-unicode", "nonhex-unicode",
         "mixed-unicode", "control", "raw-tab", "newline", "bom", "utf8", "invalid-utf8", "overlong-utf8", "del",
         "ff", "mismatch-1", "mismatch-2", "lone-closer", "space", "float", "exponent", "plus", "long-number",
         "long-string", "empty"],
)
def test_lexical_attacks_are_rejected_before_json_loads(data, expected, no_json_loads):
    assert code_of(bj.strict_canonical_loads, data, max_bytes=20_480) is expected
    assert no_json_loads == []


# --- semantic attacks (after the pre-scan) -----------------------------------------------------


@pytest.mark.parametrize(
    "data, expected",
    [
        (b'{"a":1,"a":2}', StorageErrorCode.DUPLICATE_KEY),
        (b'{"a":{"b":1,"b":1}}', StorageErrorCode.DUPLICATE_KEY),
        (b"[NaN]", StorageErrorCode.TOKEN_INVALID),
        (b"[Infinity]", StorageErrorCode.TOKEN_INVALID),
        (b"[-Infinity]", StorageErrorCode.TOKEN_INVALID),
        (b"[tru]", StorageErrorCode.MALFORMED_JSON),
        (b"[01]", StorageErrorCode.MALFORMED_JSON),
        (b"[1,]", StorageErrorCode.MALFORMED_JSON),
        (b"{}{}", StorageErrorCode.MALFORMED_JSON),
        (b"[1][2]", StorageErrorCode.MALFORMED_JSON),
        (b"[" + b"9" * 20 + b"]", StorageErrorCode.NUMBER_TOO_LONG),
        (b"[1e5]", StorageErrorCode.TOKEN_INVALID),
        (b'{"b":1,"a":2}', StorageErrorCode.NON_CANONICAL),
        (b'["\\u0041"]', StorageErrorCode.NON_CANONICAL),
        (b'["\\/"]', StorageErrorCode.NON_CANONICAL),
        (b"[-0]", StorageErrorCode.NON_CANONICAL),
    ],
    ids=["duplicate", "nested-duplicate", "nan", "infinity", "neg-infinity", "bad-literal", "leading-zero",
         "trailing-comma", "trailing-object", "trailing-array", "twenty-digits", "lower-exponent", "key-order",
         "escaped-ascii", "escaped-slash", "negative-zero"],
)
def test_semantic_attacks_are_rejected(data, expected):
    assert code_of(bj.strict_canonical_loads, data, max_bytes=20_480) is expected


@pytest.mark.parametrize("bad", [None, "text", bytearray(b"{}"), memoryview(b"{}"), 1, type("B", (bytes,), {})(b"{}")])
def test_input_type_is_checked_first(bad):
    assert code_of(bj.strict_canonical_loads, bad, max_bytes=20_480) is StorageErrorCode.INPUT_TYPE_INVALID


def test_size_limit_is_checked_before_scanning(no_json_loads):
    assert code_of(bj.strict_canonical_loads, b"[" + b"1," * 20_000 + b"1]", max_bytes=20_480) is (
        StorageErrorCode.LINE_TOO_LONG)
    assert no_json_loads == []


def test_size_limit_is_inclusive():
    data = b'"' + b"a" * 4_000 + b'"'
    assert bj.strict_canonical_loads(data, max_bytes=len(data)) == "a" * 4_000
    assert code_of(bj.strict_canonical_loads, data, max_bytes=len(data) - 1) is StorageErrorCode.LINE_TOO_LONG


def test_string_limit_is_inclusive():
    data = b'"' + b"a" * 4_096 + b'"'
    assert bj.strict_canonical_loads(data, max_bytes=20_480) == "a" * 4_096


def test_number_limit_is_inclusive():
    data = b"[-" + b"9" * 18 + b"]"
    assert bj.strict_canonical_loads(data, max_bytes=20_480) == [-int("9" * 18)]


@pytest.mark.parametrize("bad", [0, -1, True, 1.0, None])
def test_max_bytes_must_be_a_positive_int(bad):
    assert code_of(bj.strict_canonical_loads, b"{}", max_bytes=bad) is StorageErrorCode.INPUT_TYPE_INVALID


def test_errors_never_echo_input():
    secret = b"zq-canary-parser-77"
    for data in (b'{"' + secret + b'":1,"' + secret + b'":2}', b'"' + secret + b"\x01" + b'"'):
        with pytest.raises(StorageError) as info:
            bj.strict_canonical_loads(data, max_bytes=20_480)
        assert secret.decode() not in str(info.value) + repr(info.value)
