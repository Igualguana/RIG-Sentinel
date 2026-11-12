"""In-memory audit keys (M2-B).

Two independent 256-bit keys with separate purposes:

* ``K_ref`` (:attr:`KeyPurpose.REF`) pseudonymizes sensitive references with
  HMAC-SHA-256.
* ``K_auth`` (:attr:`KeyPurpose.AUTH`) authenticates audit envelopes with
  HMAC-SHA-256.

A key can only be used for its own purpose. Key material is never part of
``repr()``, ``str()``, errors, events or receipts, and keys refuse to be
pickled. Python cannot make memory private: code running in the same process
can still read the material. Persistent key files, rotation and erasure are
out of scope for M2-B.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from enum import StrEnum

from rig_sentinel.audit.errors import AuditError, AuditErrorCode

KEY_BYTES = 32
_SEPARATOR = bytes(1)
_KEY_ID_DOMAIN = b"rig.audit-key-id/v1"
_KEY_DERIVE_DOMAIN = b"rig.audit-key-derive/v1"
_DERIVED = object()  # private capability: only derive_engine_ref_key() may build ENGINE_REF keys


class KeyPurpose(StrEnum):
    REF = "ref"
    AUTH = "auth"
    ENGINE_REF = "engine-ref"  # B2-P2: derived from K_ref; keys engine references only


class AuditKey:
    """A 256-bit HMAC key bound to one purpose. Immutable; compared by identity."""

    __slots__ = ("_purpose", "_material", "_key_id")

    def __init__(self, purpose: KeyPurpose, material: bytes, *, _derivation: object = None) -> None:
        if type(purpose) is not KeyPurpose:
            raise AuditError(AuditErrorCode.KEY_INVALID, "purpose")
        if purpose is KeyPurpose.ENGINE_REF and _derivation is not _DERIVED:
            raise AuditError(AuditErrorCode.KEY_INVALID, "purpose")  # no raw-bytes constructor
        if type(material) is not bytes or len(material) != KEY_BYTES:
            raise AuditError(AuditErrorCode.KEY_INVALID, "material")
        if material == bytes(KEY_BYTES):
            raise AuditError(AuditErrorCode.KEY_INVALID, "material")
        key_id = hashlib.sha256(
            _KEY_ID_DOMAIN
            + _SEPARATOR
            + purpose.value.encode("ascii")
            + _SEPARATOR
            + material
        ).hexdigest()[:32]
        object.__setattr__(self, "_purpose", purpose)
        object.__setattr__(self, "_material", material)
        object.__setattr__(self, "_key_id", key_id)

    @classmethod
    def generate(cls, purpose: KeyPurpose) -> AuditKey:
        """Create a new random key from the operating system's CSPRNG."""
        return cls(purpose, secrets.token_bytes(KEY_BYTES))

    @classmethod
    def from_bytes(cls, purpose: KeyPurpose, material: bytes) -> AuditKey:
        """Wrap exactly 32 bytes of existing key material."""
        return cls(purpose, material)

    @property
    def purpose(self) -> KeyPurpose:
        return self._purpose

    @property
    def key_id(self) -> str:
        """A 128-bit fingerprint of the purpose and material; safe to publish."""
        return self._key_id

    def _hmac_hex(self, purpose: KeyPurpose, message: bytes) -> str:
        if purpose is not self._purpose:
            raise AuditError(AuditErrorCode.KEY_PURPOSE_MISMATCH, "key")
        return hmac.new(self._material, message, hashlib.sha256).hexdigest()

    def _same_material(self, other: AuditKey) -> bool:
        return hmac.compare_digest(self._material, other._material)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("AuditKey is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("AuditKey is immutable")

    def __repr__(self) -> str:
        return f"AuditKey(purpose={self._purpose.value!r}, key_id={self._key_id!r})"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: object) -> object:
        raise TypeError("audit keys cannot be pickled")

    def __copy__(self) -> AuditKey:
        return self

    def __deepcopy__(self, memo: object) -> AuditKey:
        return self


def derive_engine_ref_key(ref_key: AuditKey) -> AuditKey:
    """Derive K_eref = HMAC-SHA-256(K_ref, ``rig.audit-key-derive/v1`` NUL ``engine-ref``) (B2-P2).

    The result has purpose ``ENGINE_REF`` and keys only engine references in projections.
    It gives purpose and domain separation, not independent compromise: whoever holds
    K_ref can derive it.
    """
    if type(ref_key) is not AuditKey:
        raise AuditError(AuditErrorCode.KEY_INVALID, "ref")
    if ref_key.purpose is not KeyPurpose.REF:
        raise AuditError(AuditErrorCode.KEY_PURPOSE_MISMATCH, "ref")
    material = hmac.new(
        ref_key._material, _KEY_DERIVE_DOMAIN + _SEPARATOR + b"engine-ref", hashlib.sha256
    ).digest()
    return AuditKey(KeyPurpose.ENGINE_REF, material, _derivation=_DERIVED)


@dataclass(frozen=True)
class AuditKeys:
    """The keys available to an audit builder. Either key may be absent.

    Without ``ref`` the builder stores no pseudonyms at all (mode
    ``no-ref-key``). Without ``auth`` envelopes carry no authenticator.
    """

    ref: AuditKey | None = None
    auth: AuditKey | None = None

    def __post_init__(self) -> None:
        if self.ref is not None and (
            type(self.ref) is not AuditKey or self.ref.purpose is not KeyPurpose.REF
        ):
            raise AuditError(AuditErrorCode.KEY_PURPOSE_MISMATCH, "ref")
        if self.auth is not None and (
            type(self.auth) is not AuditKey or self.auth.purpose is not KeyPurpose.AUTH
        ):
            raise AuditError(AuditErrorCode.KEY_PURPOSE_MISMATCH, "auth")
        if (
            self.ref is not None
            and self.auth is not None
            and self.ref._same_material(self.auth)
        ):
            raise AuditError(AuditErrorCode.KEYS_NOT_INDEPENDENT, "keys")
