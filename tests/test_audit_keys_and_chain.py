"""M2-B keys, digests, pseudonyms and MACs: known answers, separation, no disclosure."""

import copy
import hashlib
import hmac
import pickle

import pytest
from audit_fixtures import AUTH_MATERIAL, REF_MATERIAL, auth_key, ref_key

from rig_sentinel.audit import AuditError, AuditErrorCode, AuditKey, AuditKeys, KeyPurpose, keyring
from rig_sentinel.audit.chain import (
    EVENT_DIGEST_DOMAIN,
    MAC_DOMAIN,
    REF_DOMAIN,
    compute_mac,
    event_digest,
    hmac_sha256_hex,
    macs_equal,
    pseudonym,
)
from rig_sentinel.policy.canonical import canonical_json

NUL = bytes(1)


# --- Known-answer tests -----------------------------------------------------------


def test_hmac_sha256_rfc4231_test_case_1():
    assert hmac_sha256_hex(bytes([0x0B] * 20), b"Hi There") == (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )


def test_hmac_sha256_rfc4231_test_case_2():
    assert hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?") == (
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )


def test_key_id_matches_documented_construction_and_vector():
    expected = hashlib.sha256(b"rig.audit-key-id/v1" + NUL + b"ref" + NUL + REF_MATERIAL).hexdigest()[:32]
    assert ref_key().key_id == expected == "9d412c730e45f9598a59c8a5729a1ad0"
    assert auth_key().key_id == "d60ed3d44675121c2ba81cc2dcca65eb"


def test_pseudonym_matches_documented_construction_and_vector():
    message = f"{REF_DOMAIN}/session".encode() + NUL + b"s-1"
    expected = hmac.new(REF_MATERIAL, message, hashlib.sha256).hexdigest()[:32]
    assert pseudonym(ref_key(), "session", "s-1") == expected == "7b2ad141ba39271c6a85663da9d7f920"


def test_mac_matches_documented_construction_and_vector():
    key = auth_key()
    message = MAC_DOMAIN.encode() + NUL + key.key_id.encode() + NUL + canonical_json({"a": 1})
    expected = hmac.new(AUTH_MATERIAL, message, hashlib.sha256).hexdigest()
    assert compute_mac(key, {"a": 1}) == expected == (
        "bfcc310ed99838bfcd04a9ef7ae4850c76ca53028cae3569fb02dde79d2d4771"
    )


def test_event_digest_matches_documented_construction_and_vector():
    expected = hashlib.sha256(EVENT_DIGEST_DOMAIN.encode() + NUL + canonical_json({"a": 1})).hexdigest()
    assert event_digest({"a": 1}) == expected == (
        "3a7498836101e20f9e611d232e6c378c2ac4339d3b2df31d32ee001e8fc12057"
    )


# --- Domain and key separation ----------------------------------------------------


def test_pseudonym_namespaces_are_separated():
    key = ref_key()
    assert pseudonym(key, "session", "x1") != pseudonym(key, "request", "x1")
    assert pseudonym(key, "session", "x1") == pseudonym(key, "session", "x1")


def test_pseudonym_is_not_an_unkeyed_hash():
    unkeyed = hashlib.sha256(b"s-1").hexdigest()[:32]
    domain_unkeyed = hashlib.sha256(f"{REF_DOMAIN}/session".encode() + NUL + b"s-1").hexdigest()[:32]
    assert pseudonym(ref_key(), "session", "s-1") not in {unkeyed, domain_unkeyed}


def test_different_ref_keys_give_unlinkable_pseudonyms():
    other = AuditKey.from_bytes(KeyPurpose.REF, bytes(range(101, 133)))
    assert pseudonym(ref_key(), "session", "s-1") != pseudonym(other, "session", "s-1")


def test_keys_are_purpose_bound():
    with pytest.raises(AuditError) as info:
        compute_mac(ref_key(), {"a": 1})
    assert info.value.code is AuditErrorCode.KEY_PURPOSE_MISMATCH
    with pytest.raises(AuditError) as info:
        pseudonym(auth_key(), "session", "s-1")
    assert info.value.code is AuditErrorCode.KEY_PURPOSE_MISMATCH


def test_same_material_for_both_purposes_has_different_key_ids_but_is_refused_together():
    a = AuditKey.from_bytes(KeyPurpose.REF, REF_MATERIAL)
    b = AuditKey.from_bytes(KeyPurpose.AUTH, REF_MATERIAL)
    assert a.key_id != b.key_id
    with pytest.raises(AuditError) as info:
        AuditKeys(ref=a, auth=b)
    assert info.value.code is AuditErrorCode.KEYS_NOT_INDEPENDENT


def test_keys_container_rejects_swapped_purposes():
    with pytest.raises(AuditError) as info:
        AuditKeys(ref=auth_key())
    assert info.value.code is AuditErrorCode.KEY_PURPOSE_MISMATCH
    with pytest.raises(AuditError):
        AuditKeys(auth=ref_key())


def test_keyring_accepts_only_auth_keys():
    key = auth_key()
    ring = keyring([key])
    assert list(ring) == [key.key_id] and ring[key.key_id] is key
    with pytest.raises(AuditError):
        keyring([ref_key()])


# --- Invalid keys ------------------------------------------------------------------


@pytest.mark.parametrize(
    "material",
    [b"", bytes(31), bytes(33), bytes(32), "x" * 32, bytearray(range(1, 33)), None, 12345],
    ids=["empty", "31-bytes", "33-bytes", "all-zero", "str", "bytearray", "none", "int"],
)
def test_invalid_key_material_is_rejected(material):
    with pytest.raises(AuditError) as info:
        AuditKey.from_bytes(KeyPurpose.AUTH, material)
    assert info.value.code is AuditErrorCode.KEY_INVALID


def test_invalid_purpose_is_rejected():
    with pytest.raises(AuditError):
        AuditKey("auth", AUTH_MATERIAL)  # a plain string is not a KeyPurpose


def test_generated_keys_are_random_and_valid():
    a, b = AuditKey.generate(KeyPurpose.REF), AuditKey.generate(KeyPurpose.REF)
    assert a.key_id != b.key_id
    assert len(a.key_id) == 32


# --- No key disclosure -------------------------------------------------------------


def _material_forms(material):
    return [material.hex(), repr(material), str(material), material.hex().upper()]


def test_key_repr_str_and_errors_never_contain_material():
    key = auth_key()
    for text in (repr(key), str(key), repr(AuditKeys(ref=ref_key(), auth=key))):
        for form in _material_forms(AUTH_MATERIAL) + _material_forms(REF_MATERIAL):
            assert form not in text
    with pytest.raises(AuditError) as info:
        pseudonym(key, "session", "s-1")
    for form in _material_forms(AUTH_MATERIAL):
        assert form not in str(info.value)


def test_keys_are_immutable_and_cannot_be_pickled():
    key = auth_key()
    with pytest.raises(AttributeError):
        key._material = bytes(range(32))
    with pytest.raises(AttributeError):
        key.purpose = KeyPurpose.REF
    with pytest.raises(TypeError):
        pickle.dumps(key)
    assert copy.copy(key) is key and copy.deepcopy(key) is key


# --- Constant-time comparison -------------------------------------------------------


def test_macs_equal_rejects_malformed_values():
    good = "a" * 64
    assert macs_equal(good, "a" * 64)
    for bad in ("b" * 64, "a" * 63, None, 64, b"a" * 64, "a" * 63 + chr(0xE9)):
        assert not macs_equal(good, bad)
