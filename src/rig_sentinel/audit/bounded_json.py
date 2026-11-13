"""Bounded, strict parsing of canonical JSON lines (Genesis B2-M2-C1).

Pure and standard-library only. Every persisted line (record, anchor, checkpoint) is untrusted
input. It passes, in order:

1. an exact ``bytes`` type check and a size limit, checked before any scanning;
2. :func:`prescan`, a deterministic byte-level state machine (``OUT``/``STR``/``ESC``/``UHEX``)
   that restricts bytes to 0x20-0x7E, validates escapes and ``\\uXXXX`` sequences, bounds
   nesting depth, number length and string length, and counts brackets only outside strings.
   UTF-16 surrogate escapes must form well-ordered pairs (a high surrogate immediately followed
   by a low one); unpaired or reversed surrogates are refused (``SURROGATE_INVALID``, H1-01)
   because ``json.loads`` accepts them, the resulting strings are not valid Unicode text, and
   ``canonical_json`` is not injective over such strings. Valid pairs (for example emoji) remain
   accepted. String length is counted in raw bytes between the quotes (an escape counts 2 or 6);
3. ``json.loads`` with hooks that reject duplicate keys, ``NaN``/``Infinity``, floats and
   integers longer than 19 digits;
4. a canonical round-trip check: ``canonical_json(value)`` must equal the input bytes.

``json.loads`` therefore only ever sees input whose nesting depth and byte class are already
bounded. Errors carry a code only, never input bytes, and are raised without exception context.
"""

from __future__ import annotations

import json
from typing import Any

from rig_sentinel.audit.storage_errors import StorageError, StorageErrorCode
from rig_sentinel.policy.canonical import canonical_json

MAX_DEPTH = 16
MAX_NUMBER_CHARS = 20
MAX_STRING_BYTES = 4_096
MAX_INT_DIGITS = 19

_QUOTE = 0x22
_BACKSLASH = 0x5C
_OPENERS = {0x7B: 0x7D, 0x5B: 0x5D}  # '{' -> '}', '[' -> ']'
_CLOSERS = frozenset(_OPENERS.values())
_NUMBER_BYTES = frozenset(b"-0123456789")
_LITERAL_BYTES = frozenset(b"truefalsn")
_STRUCTURAL_BYTES = frozenset(b",:")
_SIMPLE_ESCAPES = frozenset(b'"\\/bfnrt')
_HEX_BYTES = frozenset(b"0123456789abcdefABCDEF")

_OUT, _STR, _ESC, _UHEX = 0, 1, 2, 3


def _require_input(data: object, max_bytes: object) -> bytes:
    if type(data) is not bytes or type(max_bytes) is not int or max_bytes <= 0:
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID)
    if len(data) > max_bytes:
        raise StorageError(StorageErrorCode.LINE_TOO_LONG)
    return data


def prescan(data: object, *, max_bytes: object) -> None:
    """Validate the byte structure of one JSON text without parsing it.

    Raises :class:`StorageError` with a specific code on the first violation; returns ``None``
    if the input is a single, balanced, lexically valid ASCII JSON text within all limits.
    """
    raw = _require_input(data, max_bytes)
    if not raw:
        raise StorageError(StorageErrorCode.MALFORMED_JSON)
    code = _scan(raw)
    if code is not None:
        raise StorageError(code)


def _hex_value(byte: int) -> int:
    return byte - 0x30 if byte <= 0x39 else (byte | 0x20) - 0x57


def _scan(raw: bytes) -> StorageErrorCode | None:
    state = _OUT
    stack: list[int] = []
    number_run = 0
    string_bytes = 0
    hex_left = 0
    unit = 0  # value of the \uXXXX escape being read
    expect_low = False  # a high surrogate escape must be followed immediately by a low one
    for byte in raw:
        if byte < 0x20 or byte > 0x7E:
            return StorageErrorCode.BYTE_NOT_ALLOWED
        if state == _OUT:
            if byte in _NUMBER_BYTES:
                number_run += 1
                if number_run > MAX_NUMBER_CHARS:
                    return StorageErrorCode.NUMBER_TOO_LONG
                continue
            number_run = 0
            if byte == _QUOTE:
                state = _STR
                string_bytes = 0
            elif byte in _OPENERS:
                if len(stack) >= MAX_DEPTH:
                    return StorageErrorCode.DEPTH_EXCEEDED
                stack.append(_OPENERS[byte])
            elif byte in _CLOSERS:
                if not stack or stack.pop() != byte:
                    return StorageErrorCode.UNBALANCED
            elif byte not in _STRUCTURAL_BYTES and byte not in _LITERAL_BYTES:
                return StorageErrorCode.TOKEN_INVALID
        else:
            if state == _STR and byte == _QUOTE:
                if expect_low:
                    return StorageErrorCode.SURROGATE_INVALID  # high surrogate at the end of a string
                state = _OUT  # the closing quote is not part of the string
                continue
            string_bytes += 1
            if string_bytes > MAX_STRING_BYTES:
                return StorageErrorCode.STRING_TOO_LONG
            if state == _STR:
                if byte == _BACKSLASH:
                    state = _ESC
                elif expect_low:
                    return StorageErrorCode.SURROGATE_INVALID  # high surrogate followed by a plain byte
            elif state == _ESC:
                if byte == 0x75:  # 'u'
                    state = _UHEX
                    hex_left = 4
                    unit = 0
                elif expect_low:
                    return StorageErrorCode.SURROGATE_INVALID  # high surrogate followed by another escape
                elif byte in _SIMPLE_ESCAPES:
                    state = _STR
                else:
                    return StorageErrorCode.BAD_ESCAPE
            else:  # _UHEX
                if byte not in _HEX_BYTES:
                    return StorageErrorCode.BAD_ESCAPE
                unit = unit * 16 + _hex_value(byte)
                hex_left -= 1
                if hex_left == 0:
                    state = _STR
                    if 0xDC00 <= unit <= 0xDFFF:  # low surrogate: valid only right after a high one
                        if not expect_low:
                            return StorageErrorCode.SURROGATE_INVALID
                        expect_low = False
                    elif expect_low:
                        return StorageErrorCode.SURROGATE_INVALID  # high surrogate not followed by a low one
                    elif 0xD800 <= unit <= 0xDBFF:
                        expect_low = True
    if state != _OUT or stack:
        return StorageErrorCode.UNTERMINATED
    return None


class _Rejected(Exception):
    def __init__(self, code: StorageErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _Rejected(StorageErrorCode.DUPLICATE_KEY)
        result[key] = value
    return result


def _constant(_name: str) -> Any:
    raise _Rejected(StorageErrorCode.TOKEN_INVALID)


def _float(_text: str) -> Any:
    raise _Rejected(StorageErrorCode.TOKEN_INVALID)


def _int(text: str) -> int:
    digits = text[1:] if text.startswith("-") else text
    if len(digits) > MAX_INT_DIGITS:
        raise _Rejected(StorageErrorCode.NUMBER_TOO_LONG)
    return int(text)


def strict_canonical_loads(data: object, *, max_bytes: object) -> Any:
    """Parse one canonical JSON text under all C1 bounds; return the value.

    The input must be exact ``bytes`` of at most ``max_bytes`` and must equal
    ``canonical_json`` of its own value. No newline is accepted; callers strip the single
    terminating ``\\n`` of a line first.
    """
    prescan(data, max_bytes=max_bytes)
    raw: bytes = data  # type: ignore[assignment]
    code: StorageErrorCode | None = None
    value: Any = None
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_float=_float,
            parse_int=_int,
        )
    except _Rejected as rejected:
        code = rejected.code
    except (ValueError, RecursionError):
        code = StorageErrorCode.MALFORMED_JSON
    if code is not None:
        raise StorageError(code)  # outside the handler: no exception context
    if _canonical_or_none(value) != raw:
        raise StorageError(StorageErrorCode.NON_CANONICAL)
    return value


def _canonical_or_none(value: Any) -> bytes | None:
    try:
        return canonical_json(value)
    except (ValueError, TypeError, RecursionError):
        return None
