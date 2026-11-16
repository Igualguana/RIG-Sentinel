"""Key files for K_chain, K_auth and K_ref (Genesis B2-M2-C2-B).

Format (D-C2-1): one ASCII line, at most 256 bytes::

    rig-sentinel-key/v1 <purpose> <material: 64 lowercase hex> <key_id: 32 lowercase hex>\\n

``purpose`` is ``ref``, ``auth`` or ``chain``. K_eref is never stored; it is derived from K_ref
exactly as in P2.

**Authentication comes only from the pin.** Every load requires ``expected_key_id``. It must come
from a trusted source independent of the key file: change-controlled deployment configuration,
an operator custody record, or a segment header the caller has already authenticated. Never the
key file itself or anything its writer controls. The key id embedded in the file is a checksum
that detects truncation and corruption; anyone able to write the file can write a matching id
for their own material, so it does **not** authenticate the key.

No fallback, no generation on load, no environment variables, no automatic repair. All I/O goes
through :mod:`rig_sentinel.audit.safepath`; this module imports no I/O modules.

Limitations (not addressed by C2-B): key files are plaintext at rest and in backups, readable by
the writer's own account and by administrators; key material lives in Python ``bytes`` that
can't be reliably zeroized.
"""

from __future__ import annotations

import hmac
import re
import secrets
from dataclasses import dataclass

from rig_sentinel.audit.errors import AuditError
from rig_sentinel.audit.keys import KEY_BYTES, AuditKey, KeyPurpose
from rig_sentinel.audit.records import require_independent_keys
from rig_sentinel.audit.safepath import SafeDirectory
from rig_sentinel.audit.storage_errors import StorageError, StorageErrorCode

__all__ = [
    "KEY_FILE_SCHEMA",
    "MAX_KEY_FILE_BYTES",
    "KeyFileRef",
    "KeySet",
    "create_key_file",
    "load_key_file",
    "load_key_set",
    "load_keyring",
    "parse_key_file",
]

KEY_FILE_SCHEMA = "rig-sentinel-key/v1"
MAX_KEY_FILE_BYTES = 256
_STORED_PURPOSES = {KeyPurpose.REF: "ref", KeyPurpose.AUTH: "auth", KeyPurpose.CHAIN: "chain"}
_LINE_RE = re.compile(rb"rig-sentinel-key/v1 (ref|auth|chain) ([0-9a-f]{64}) ([0-9a-f]{32})\n")
_KEY_ID_RE = re.compile(r"[0-9a-f]{32}")


def _label(purpose: KeyPurpose) -> str:
    return "keyfile:" + _STORED_PURPOSES[purpose]


def _require_purpose(purpose: object) -> KeyPurpose:
    if type(purpose) is not KeyPurpose:
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "keyfile:purpose")
    if purpose not in _STORED_PURPOSES:
        raise StorageError(StorageErrorCode.KEY_PURPOSE_MISMATCH, "keyfile:purpose")  # ENGINE_REF is never stored
    return purpose


def _require_key_id(value: object, label: str) -> str:
    if type(value) is not str or _KEY_ID_RE.fullmatch(value) is None:
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, label)
    return value


def _require_distrusted(values: object) -> frozenset[str]:
    if type(values) not in (frozenset, set):
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "keyfile:distrusted")
    items = tuple(values)  # type: ignore[arg-type]
    for item in items:
        _require_key_id(item, "keyfile:distrusted")
    return frozenset(items)


def format_key_line(purpose: KeyPurpose, material: bytes) -> bytes:
    """Build the canonical key-file line (used by :func:`create_key_file` and by tests)."""
    key = AuditKey(_require_purpose(purpose), material)
    return (f"{KEY_FILE_SCHEMA} {_STORED_PURPOSES[purpose]} {material.hex()} {key.key_id}\n").encode("ascii")


def parse_key_file(data: object, purpose: object) -> AuditKey:
    """Strictly parse key-file bytes for ``purpose``. Checks the embedded checksum id only."""
    checked = _require_purpose(purpose)
    label = _label(checked)
    if type(data) is not bytes or len(data) > MAX_KEY_FILE_BYTES:
        raise StorageError(StorageErrorCode.KEY_FILE_FORMAT, label)
    match = _LINE_RE.fullmatch(data)
    if match is None:
        raise StorageError(StorageErrorCode.KEY_FILE_FORMAT, label)
    stored_purpose, material_hex, embedded_id = (part.decode("ascii") for part in match.groups())
    if stored_purpose != _STORED_PURPOSES[checked]:
        raise StorageError(StorageErrorCode.KEY_FILE_FORMAT, label + ":purpose")
    material = bytes.fromhex(material_hex)
    failed = False
    key: AuditKey | None = None
    try:
        key = AuditKey(checked, material)  # refuses all-zero material
    except AuditError:
        failed = True
    del material
    if failed or key is None or len(material_hex) != 2 * KEY_BYTES:
        raise StorageError(StorageErrorCode.KEY_FILE_FORMAT, label)
    if not hmac.compare_digest(key.key_id, embedded_id):
        raise StorageError(StorageErrorCode.KEY_FILE_FORMAT, label + ":checksum")
    return key


def load_key_file(
    directory: SafeDirectory,
    name: object,
    purpose: object,
    *,
    expected_key_id: object,
    distrusted_key_ids: object = frozenset(),
) -> AuditKey:
    """Load one key file and authenticate it against the mandatory trusted pin.

    ``expected_key_id`` has no default: a load without a trusted pin is impossible.
    """
    checked = _require_purpose(purpose)
    label = _label(checked)
    pin = _require_key_id(expected_key_id, label + ":pin")
    distrusted = _require_distrusted(distrusted_key_ids)
    if type(directory) is not SafeDirectory:
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "keyfile:directory")
    if pin in distrusted:
        raise StorageError(StorageErrorCode.KEY_ID_MISMATCH, label + ":distrusted")  # before any I/O
    data = directory.read_private_file(name, max_bytes=MAX_KEY_FILE_BYTES)
    key = parse_key_file(data, checked)
    del data
    if not hmac.compare_digest(key.key_id, pin):
        raise StorageError(StorageErrorCode.KEY_ID_MISMATCH, label + ":pin")
    return key


@dataclass(frozen=True)
class KeyFileRef:
    """A key file name and its trusted pin (from configuration, never from the key directory)."""

    name: str
    expected_key_id: str

    def __post_init__(self) -> None:
        if type(self.name) is not str:
            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "keyfile:name")
        _require_key_id(self.expected_key_id, "keyfile:pin")


@dataclass(frozen=True)
class KeySet:
    """K_auth and K_chain (and optionally K_ref), each authenticated by its pin and independent."""

    auth: AuditKey
    chain: AuditKey
    ref: AuditKey | None


def _require_ref(value: object) -> KeyFileRef:
    if type(value) is not KeyFileRef:
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "keyfile:ref")
    return value


def load_key_set(
    directory: SafeDirectory,
    *,
    auth: object,
    chain: object,
    ref: object = None,
    distrusted_key_ids: object = frozenset(),
) -> KeySet:
    """Load K_auth, K_chain and optionally K_ref, then refuse shared material (incl. K_eref)."""
    auth_ref, chain_ref = _require_ref(auth), _require_ref(chain)
    ref_ref = None if ref is None else _require_ref(ref)
    auth_key = load_key_file(directory, auth_ref.name, KeyPurpose.AUTH, expected_key_id=auth_ref.expected_key_id,
                             distrusted_key_ids=distrusted_key_ids)
    chain_key = load_key_file(directory, chain_ref.name, KeyPurpose.CHAIN,
                              expected_key_id=chain_ref.expected_key_id, distrusted_key_ids=distrusted_key_ids)
    ref_key = None
    if ref_ref is not None:
        ref_key = load_key_file(directory, ref_ref.name, KeyPurpose.REF, expected_key_id=ref_ref.expected_key_id,
                                distrusted_key_ids=distrusted_key_ids)
    require_independent_keys(chain_key, auth_key, ref_key)
    return KeySet(auth=auth_key, chain=chain_key, ref=ref_key)


def load_keyring(
    directory: SafeDirectory,
    refs: object,
    purpose: object,
    *,
    distrusted_key_ids: object = frozenset(),
) -> dict[str, AuditKey]:
    """Load several pinned keys of one purpose (e.g. retired K_chain keys) as an exact-dict keyring."""
    checked = _require_purpose(purpose)
    if type(refs) is not tuple or not refs or len(refs) > 64:
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "keyfile:refs")
    ring: dict[str, AuditKey] = {}
    for item in refs:
        file_ref = _require_ref(item)
        key = load_key_file(directory, file_ref.name, checked, expected_key_id=file_ref.expected_key_id,
                            distrusted_key_ids=distrusted_key_ids)
        if key.key_id in ring:
            raise StorageError(StorageErrorCode.KEY_ID_MISMATCH, _label(checked) + ":duplicate")
        ring[key.key_id] = key
    return ring


def create_key_file(directory: SafeDirectory, name: object, purpose: object) -> str:
    """Generate a new independent key and write it exclusively. Returns only the public key id.

    The operator records the returned id in the trusted pin source. The file is never overwritten.

    **Windows: refused** (``UNSUPPORTED_PLATFORM``, H2 finding R3) before any key material is generated
    or any filesystem call is made. Provision Windows keys out of band (see the C2-B reports).
    """
    checked = _require_purpose(purpose)
    if type(directory) is not SafeDirectory:
        raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, "keyfile:directory")
    directory.require_private_create()  # before any secret exists
    material = secrets.token_bytes(KEY_BYTES)
    line = format_key_line(checked, material)
    key_id = AuditKey(checked, material).key_id
    del material
    directory.create_private_file(name, line)
    del line
    return key_id
