"""Genesis B2-M2-C2-B: key files and the minimum safe-path layer.

Test tiers:
* Portable (every platform): the strict parser, pure path and name rules, the API contract,
  including the mandatory trusted pin.
* Windows FAT32 refusal (real filesystem, runs on a FAT32 temp directory): nothing is written.
* Windows logic with the named-stream probe MOCKED (synthetic key material only). These exercise
  the Windows code path on a FAT32 volume. They are NOT evidence of Windows/NTFS support.
* NTFS integration: only with an authorized native NTFS directory (RIG_SENTINEL_NTFS_TEST_DIR).
* POSIX integration: only on Linux/macOS, in a private directory under the home directory.
"""

import copy
import errno
import hashlib
import hmac
import os
import pickle
import stat
import sys

import pytest
from audit_fixtures import AUTH_MATERIAL, REF_MATERIAL

from rig_sentinel.audit import AuditKey, KeyPurpose
from rig_sentinel.audit import keyfile as kf
from rig_sentinel.audit import safepath as sp
from rig_sentinel.audit.records import StorageError, StorageErrorCode
from rig_sentinel.audit.safepath import SafeDirectory, WindowsAttestation

NUL = bytes(1)
CHAIN_MATERIAL = bytes(range(200, 232))
EREF_MATERIAL = hmac.new(REF_MATERIAL, b"rig.audit-key-derive/v1" + NUL + b"engine-ref", hashlib.sha256).digest()
ATTESTED = WindowsAttestation(local_fixed_ntfs=True, acl_recipe_applied=True, dedicated_account=True)
IS_WINDOWS = os.name == "nt"
IS_POSIX = sp._platform() == "posix"
NTFS_DIR = os.environ.get("RIG_SENTINEL_NTFS_TEST_DIR")


def code_of(fn, *args, **kwargs):
    with pytest.raises(StorageError) as info:
        fn(*args, **kwargs)
    assert info.value.__context__ is None and info.value.__cause__ is None
    return info.value.code


def key_id(purpose, material):
    return hashlib.sha256(b"rig.audit-key-id/v1" + NUL + purpose + NUL + material).hexdigest()[:32]


def line(purpose=b"chain", material=CHAIN_MATERIAL, embedded=None):
    embedded = key_id(purpose, material) if embedded is None else embedded
    return b"rig-sentinel-key/v1 " + purpose + b" " + material.hex().encode() + b" " + embedded.encode() + b"\n"


CHAIN_ID = key_id(b"chain", CHAIN_MATERIAL)
AUTH_ID = key_id(b"auth", AUTH_MATERIAL)
REF_ID = key_id(b"ref", REF_MATERIAL)


# --- Portable: strict parser ---------------------------------------------------------------------


@pytest.mark.parametrize("purpose, stored, material", [(KeyPurpose.CHAIN, b"chain", CHAIN_MATERIAL),
                                                         (KeyPurpose.AUTH, b"auth", AUTH_MATERIAL),
                                                         (KeyPurpose.REF, b"ref", REF_MATERIAL)])
def test_valid_lines_parse_for_each_purpose(purpose, stored, material):
    data = line(stored, material)
    assert 122 <= len(data) <= 124 and data.isascii()
    key = kf.parse_key_file(data, purpose)
    assert key.purpose is purpose and key.key_id == key_id(stored, material)
    assert kf.format_key_line(purpose, material) == data


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d[:-1],
        lambda d: d[:-1] + b"\r\n",
        lambda d: d + b"\n",
        lambda d: b"\xef\xbb\xbf" + d,
        lambda d: d.replace(b" ", b"  ", 1),
        lambda d: d.replace(b" ", b"\t", 1),
        lambda d: d.upper(),
        lambda d: d.replace(b"/v1", b"/v2"),
        lambda d: d.replace(b" chain ", b" engine-ref "),
        lambda d: d[:40] + d[42:],
        lambda d: d + b"x",
        lambda d: b" " + d,
        lambda d: d[:-2] + b" \n",
        lambda d: d * 3,
        lambda d: b"",
    ],
    ids=["no-newline", "crlf", "two-newlines", "bom", "double-space", "tab", "uppercase", "wrong-version",
         "engine-ref", "short-material", "trailing-byte", "leading-space", "trailing-space", "oversize", "empty"],
)
def test_malformed_lines_are_refused(mutate):
    assert code_of(kf.parse_key_file, mutate(line()), KeyPurpose.CHAIN) is StorageErrorCode.KEY_FILE_FORMAT


def test_embedded_id_is_only_a_checksum():
    other = bytes(range(160, 192))
    # A correct checksum for the attacker's own material parses fine: the checksum does not authenticate.
    forged = line(b"chain", other)
    assert kf.parse_key_file(forged, KeyPurpose.CHAIN).key_id == key_id(b"chain", other)
    # A checksum that doesn't match the material is refused.
    mismatched = line(b"chain", other, embedded=CHAIN_ID)
    assert code_of(kf.parse_key_file, mismatched, KeyPurpose.CHAIN) is StorageErrorCode.KEY_FILE_FORMAT


@pytest.mark.parametrize("stored, requested", [(b"auth", KeyPurpose.CHAIN), (b"chain", KeyPurpose.AUTH),
                                               (b"ref", KeyPurpose.CHAIN)])
def test_purpose_is_bound_exactly(stored, requested):
    assert code_of(kf.parse_key_file, line(stored), requested) is StorageErrorCode.KEY_FILE_FORMAT


def test_purpose_binding_is_independent_of_the_checksum():
    # Stored purpose "auth" with a checksum computed for "chain": only the purpose check refuses it.
    data = line(b"auth", CHAIN_MATERIAL, embedded=key_id(b"chain", CHAIN_MATERIAL))
    assert code_of(kf.parse_key_file, data, KeyPurpose.CHAIN) is StorageErrorCode.KEY_FILE_FORMAT


def test_material_hex_must_be_lowercase():
    data = line().replace(CHAIN_MATERIAL.hex().encode(), CHAIN_MATERIAL.hex().upper().encode())
    assert data != line()
    assert code_of(kf.parse_key_file, data, KeyPurpose.CHAIN) is StorageErrorCode.KEY_FILE_FORMAT


def test_oversized_input_never_reaches_the_pattern(monkeypatch):
    class Spy:
        def fullmatch(self, data):
            raise AssertionError("pattern used on oversized input")

    monkeypatch.setattr(kf, "_LINE_RE", Spy())
    assert code_of(kf.parse_key_file, line() + b"x" * 200, KeyPurpose.CHAIN) is StorageErrorCode.KEY_FILE_FORMAT


def test_all_zero_material_is_refused():
    zero = bytes(32)
    assert code_of(kf.parse_key_file, line(b"chain", zero), KeyPurpose.CHAIN) is StorageErrorCode.KEY_FILE_FORMAT


@pytest.mark.parametrize("purpose, expected", [(KeyPurpose.ENGINE_REF, StorageErrorCode.KEY_PURPOSE_MISMATCH),
                                               ("chain", StorageErrorCode.INPUT_TYPE_INVALID),
                                               (None, StorageErrorCode.INPUT_TYPE_INVALID)])
def test_purpose_argument_is_strict(purpose, expected):
    assert code_of(kf.parse_key_file, line(), purpose) is expected


def test_parser_errors_never_echo_material():
    for data in (line()[:-1], line(b"auth"), line(b"chain", CHAIN_MATERIAL, embedded="0" * 32)):
        with pytest.raises(StorageError) as info:
            kf.parse_key_file(data, KeyPurpose.CHAIN)
        text = str(info.value) + repr(info.value) + repr(info.value.args)
        assert CHAIN_MATERIAL.hex() not in text and CHAIN_ID not in text


# --- Portable: path and name rules ------------------------------------------------------------------


@pytest.mark.parametrize("path", ["C:\\keys", "C:\\a\\b c\\rig-keys", "d:\\x"])
def test_windows_paths_accepted(path):
    assert sp.check_windows_path(path)


@pytest.mark.parametrize(
    "path",
    ["\\\\server\\share\\keys", "\\\\?\\C:\\keys", "\\\\.\\C:\\keys", "C:keys", "C:\\", "C:/keys", "C:\\keys/x",
     "C:\\keys:stream", "C:\\keys::$DATA", "C:\\keys.", "C:\\keys ", "C:\\a\\..\\b", "C:\\a\\.\\b", "C:\\a\\\\b",
     "C:\\CON", "C:\\con.txt", "C:\\a\\COM1", "C:\\LPT9.log", "C:\\COM" + chr(0xB9), "C:\\LPT" + chr(0xB3) + ".x",
     "C:\\CONIN$", "C:\\conout$", "C:\\CLOCK$", "C:\\NUL .txt", "C:\\a*", "C:\\a?", "C:\\a<b", "C:\\a|b",
     "C:\\a\x01b", "C:\\" + "a" * 300, "keys", "", None, b"C:\\keys"],
)
def test_windows_paths_refused(path):
    assert code_of(sp.check_windows_path, path) is StorageErrorCode.UNSAFE_PATH


@pytest.mark.skipif(not hasattr(os.path, "isreserved"), reason="os.path.isreserved needs Python 3.13+ on Windows")
@pytest.mark.parametrize("name", ["NUL", "con.txt", "COM1", "LPT9.log", "COM" + chr(0xB9), "conin$", "CONOUT$",
                                  "aux.tar.gz", "Prn"])
def test_reserved_list_agrees_with_the_standard_library(name):
    assert os.path.isreserved(name) and sp._is_reserved(name)


@pytest.mark.parametrize("path", ["/srv/rig/keys", "/home/op/.rig-keys", "/a"])
def test_posix_paths_accepted(path):
    assert sp.check_posix_path(path)


@pytest.mark.parametrize("path", ["srv/keys", "/", "//x", "/a//b", "/a/./b", "/a/../b", "/a/", "/a\x00b", "/a\x1fb",
                                  "/" + "/".join(["d"] * 65), "/" + "a" * 4100, None, b"/srv"])
def test_posix_paths_refused(path):
    assert code_of(sp.check_posix_path, path) is StorageErrorCode.UNSAFE_PATH


@pytest.mark.parametrize("name", ["chain.key", "auth-2026_11.key", "k.key", "a" * 63 + ".key"])
def test_key_file_names_accepted(name):
    assert sp.check_file_name(name) == name


@pytest.mark.parametrize("name", ["Chain.key", "chain.KEY", "chain", "a.b.key", "-a.key", "con.key", "nul.key",
                                  "com1.key", "../x.key", "x.key ", "x.key.", "a" * 64 + ".key", "", None,
                                  "x:y.key", "x\\y.key", "x/y.key"])
def test_key_file_names_refused(name):
    assert code_of(sp.check_file_name, name) is StorageErrorCode.UNSAFE_PATH


# --- Portable: API contract -----------------------------------------------------------------------


def fake_directory():
    """A SafeDirectory instance that has not opened anything (contract tests only)."""
    return SafeDirectory(_kind="posix", _role="keys", _fd=None, _path=None, _identities=())


def test_expected_key_id_is_mandatory():
    with pytest.raises(TypeError):
        kf.load_key_file(fake_directory(), "chain.key", KeyPurpose.CHAIN)  # pylint: disable=missing-kwoa


@pytest.mark.parametrize("pin", [None, "", "A" * 32, "a" * 31, "g" * 32, 123, b"a" * 32, CHAIN_ID + " "])
def test_malformed_pins_are_refused_before_io(pin, monkeypatch):
    monkeypatch.setattr(SafeDirectory, "read_private_file", lambda *a, **k: pytest.fail("I/O before pin check"))
    assert code_of(kf.load_key_file, fake_directory(), "chain.key", KeyPurpose.CHAIN, expected_key_id=pin) is (
        StorageErrorCode.INPUT_TYPE_INVALID)


def test_distrusted_pin_is_refused_before_io(monkeypatch):
    monkeypatch.setattr(SafeDirectory, "read_private_file", lambda *a, **k: pytest.fail("I/O for distrusted key"))
    assert code_of(kf.load_key_file, fake_directory(), "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID,
                   distrusted_key_ids=frozenset({CHAIN_ID})) is StorageErrorCode.KEY_ID_MISMATCH


@pytest.mark.parametrize("distrusted", [[CHAIN_ID], {"X" * 32}, CHAIN_ID, None])
def test_distrust_list_is_strict(distrusted):
    assert code_of(kf.load_key_file, fake_directory(), "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID,
                   distrusted_key_ids=distrusted) is StorageErrorCode.INPUT_TYPE_INVALID


def _serve(monkeypatch, files):
    def read(self, name, *, max_bytes):
        sp.check_file_name(name)
        if name not in files:
            raise StorageError(StorageErrorCode.KEY_FILE_MISSING, "file:open")
        return files[name]
    monkeypatch.setattr(SafeDirectory, "read_private_file", read)


def test_pin_mismatch_and_substitution_are_refused(monkeypatch):
    attacker = bytes(range(160, 192))
    _serve(monkeypatch, {"chain.key": line(b"chain", attacker)})  # well-formed substitute with a valid checksum
    assert code_of(kf.load_key_file, fake_directory(), "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID) is (
        StorageErrorCode.KEY_ID_MISMATCH)
    _serve(monkeypatch, {"chain.key": line()})
    key = kf.load_key_file(fake_directory(), "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID)
    assert key.key_id == CHAIN_ID and key.purpose is KeyPurpose.CHAIN


def test_key_set_requires_pins_and_independence(monkeypatch):
    files = {"auth.key": line(b"auth", AUTH_MATERIAL), "chain.key": line(), "ref.key": line(b"ref", REF_MATERIAL),
             "eref-chain.key": line(b"chain", EREF_MATERIAL), "auth-chain.key": line(b"chain", AUTH_MATERIAL)}
    _serve(monkeypatch, files)
    ok = kf.load_key_set(fake_directory(), auth=kf.KeyFileRef("auth.key", AUTH_ID),
                         chain=kf.KeyFileRef("chain.key", CHAIN_ID), ref=kf.KeyFileRef("ref.key", REF_ID))
    assert (ok.auth.key_id, ok.chain.key_id, ok.ref.key_id) == (AUTH_ID, CHAIN_ID, REF_ID)
    for name, material in (("eref-chain.key", EREF_MATERIAL), ("auth-chain.key", AUTH_MATERIAL)):
        assert code_of(kf.load_key_set, fake_directory(), auth=kf.KeyFileRef("auth.key", AUTH_ID),
                       chain=kf.KeyFileRef(name, key_id(b"chain", material)),
                       ref=kf.KeyFileRef("ref.key", REF_ID)) is StorageErrorCode.KEYS_NOT_INDEPENDENT
    with pytest.raises(StorageError):
        kf.KeyFileRef("chain.key", None)
    assert code_of(kf.load_key_set, fake_directory(), auth=("auth.key", AUTH_ID),
                   chain=kf.KeyFileRef("chain.key", CHAIN_ID)) is StorageErrorCode.INPUT_TYPE_INVALID


def test_keyring_loads_pinned_retired_keys(monkeypatch):
    older = bytes(range(100, 132))
    _serve(monkeypatch, {"chain.key": line(), "chain-old.key": line(b"chain", older)})
    ring = kf.load_keyring(fake_directory(), (kf.KeyFileRef("chain.key", CHAIN_ID),
                                              kf.KeyFileRef("chain-old.key", key_id(b"chain", older))),
                           KeyPurpose.CHAIN)
    assert set(ring) == {CHAIN_ID, key_id(b"chain", older)} and type(ring) is dict
    assert code_of(kf.load_keyring, fake_directory(), [kf.KeyFileRef("chain.key", CHAIN_ID)], KeyPurpose.CHAIN) is (
        StorageErrorCode.INPUT_TYPE_INVALID)
    assert code_of(kf.load_keyring, fake_directory(), (kf.KeyFileRef("chain.key", CHAIN_ID),) * 2,
                   KeyPurpose.CHAIN) is StorageErrorCode.KEY_ID_MISMATCH


def test_safe_directory_is_opaque_and_not_copyable():
    directory = fake_directory()
    assert repr(directory) == "SafeDirectory(role='keys', closed=False)"
    with pytest.raises(TypeError):
        pickle.dumps(directory)
    with pytest.raises(TypeError):
        copy.copy(directory)
    directory.close()
    assert code_of(directory.read_private_file, "chain.key", max_bytes=256) is StorageErrorCode.STORAGE_UNAVAILABLE


@pytest.mark.parametrize("role", ["audit", None, b"keys"])
def test_unknown_roles_are_refused(role):
    assert code_of(SafeDirectory.open, "/x", role=role) is StorageErrorCode.INPUT_TYPE_INVALID


def test_unsupported_platform_fails_closed(monkeypatch):
    monkeypatch.setattr(sp, "_platform", lambda: None)
    assert code_of(SafeDirectory.open, "/srv/keys", role="keys") is StorageErrorCode.UNSUPPORTED_PLATFORM


@pytest.mark.parametrize(
    "number, missing, expected",
    [(errno.ENOENT, StorageErrorCode.KEY_FILE_MISSING, StorageErrorCode.KEY_FILE_MISSING),
     (errno.ELOOP, StorageErrorCode.KEY_FILE_MISSING, StorageErrorCode.UNSAFE_PATH),
     (errno.ENOTDIR, StorageErrorCode.KEY_FILE_MISSING, StorageErrorCode.UNSAFE_PATH),
     (errno.EEXIST, StorageErrorCode.STORAGE_UNAVAILABLE, StorageErrorCode.KEY_FILE_EXISTS),
     (errno.EACCES, StorageErrorCode.KEY_FILE_MISSING, StorageErrorCode.STORAGE_UNAVAILABLE),
     (errno.EIO, StorageErrorCode.KEY_FILE_MISSING, StorageErrorCode.STORAGE_UNAVAILABLE)],
)
def test_errno_mapping(number, missing, expected):
    assert sp._map_os_error(OSError(number, "zq-canary /secret/path"), missing=missing) is expected


def test_keyfile_module_does_no_direct_io():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(kf))
    names = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    assert names.isdisjoint({"os", "io", "pathlib", "fcntl", "msvcrt", "sys"})


# --- Windows: real FAT32 refusal (nothing written) -------------------------------------------------


def _private_dir(tmp_path):
    target = tmp_path / "keys"
    target.mkdir()
    return str(target)


windows_only = pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only")


def _is_stream_capable(path):
    st = os.stat(path)
    return sp._windows_stream_probe(path, (st.st_dev, st.st_ino)) is None


@windows_only
def test_windows_requires_a_complete_attestation(tmp_path):
    path = _private_dir(tmp_path)
    assert code_of(SafeDirectory.open, path, role="keys") is StorageErrorCode.ATTESTATION_REQUIRED
    partial = WindowsAttestation(local_fixed_ntfs=True, acl_recipe_applied=False, dedicated_account=True)
    assert code_of(SafeDirectory.open, path, role="keys", windows_attestation=partial) is (
        StorageErrorCode.ATTESTATION_REQUIRED)
    truthy = WindowsAttestation(local_fixed_ntfs=1, acl_recipe_applied=True, dedicated_account=True)
    assert code_of(SafeDirectory.open, path, role="keys", windows_attestation=truthy) is (
        StorageErrorCode.ATTESTATION_REQUIRED)


@windows_only
def test_fat32_is_refused_before_anything_is_written(tmp_path):
    path = _private_dir(tmp_path)
    if _is_stream_capable(path):
        pytest.skip("temp directory is on a stream-capable filesystem; this test needs FAT32/exFAT")
    with pytest.raises(StorageError) as info:
        SafeDirectory.open(path, role="keys", windows_attestation=ATTESTED)
    # Real FAT32: the probe fails and the directory identity is unchanged, so the capability is reported
    # (not tampering).
    assert (info.value.code, info.value.path) == (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "directory:filesystem")
    assert os.listdir(path) == []


@windows_only
def test_short_name_alias_is_refused(tmp_path):
    import _winapi

    long_dir = tmp_path / "averylongdirectoryname_for_alias"
    long_dir.mkdir()
    short = _winapi.GetShortPathName(str(long_dir)) if hasattr(_winapi, "GetShortPathName") else str(long_dir)
    if short == str(long_dir):
        pytest.skip("no 8.3 alias generated on this volume")
    assert code_of(SafeDirectory.open, short, role="keys", windows_attestation=ATTESTED) is StorageErrorCode.UNSAFE_PATH


@windows_only
def test_mapped_network_drive_is_refused():
    drives = [d for d in (os.listdrives() if hasattr(os, "listdrives") else [])
              if os.path.realpath(d).startswith("\\\\")]
    if not drives:
        pytest.skip("no mapped network drive on this machine")
    assert code_of(SafeDirectory.open, drives[0] + "rig-keys-not-created", role="keys",
                   windows_attestation=ATTESTED) is StorageErrorCode.UNSAFE_PATH


# --- H2 / R3: Windows key-file creation is disabled (fail closed, before any secret exists) ---------


def _nt_directory():
    """A Windows-kind SafeDirectory that has opened nothing (contract tests on every platform)."""
    return SafeDirectory(_kind="nt", _role="keys", _fd=None, _path="C:\\keys", _identities=((1, 2),))


def test_windows_creation_refusal_is_platform_independent(monkeypatch):
    monkeypatch.setattr(kf.secrets, "token_bytes", lambda n: pytest.fail("secret generated on a refused path"))
    monkeypatch.setattr(kf, "format_key_line", lambda *a, **k: pytest.fail("secret serialized on a refused path"))
    directory = _nt_directory()
    for purpose in (KeyPurpose.CHAIN, KeyPurpose.AUTH, KeyPurpose.REF):
        with pytest.raises(StorageError) as info:
            kf.create_key_file(directory, "chain.key", purpose)
        assert (info.value.code, info.value.path) == (StorageErrorCode.UNSUPPORTED_PLATFORM, "file:create-windows")
        assert info.value.__context__ is None and info.value.__cause__ is None
    assert code_of(directory.require_private_create) is StorageErrorCode.UNSUPPORTED_PLATFORM
    assert code_of(directory.create_private_file, "chain.key", line()) is StorageErrorCode.UNSUPPORTED_PLATFORM
    # The refusal comes before any validation of the request (nothing about it is processed).
    assert code_of(directory.create_private_file, "CON", None) is StorageErrorCode.UNSUPPORTED_PLATFORM
    assert fake_directory().require_private_create() is None  # POSIX kind: creation stays available
    closed = fake_directory()
    closed.close()
    assert code_of(closed.require_private_create) is StorageErrorCode.STORAGE_UNAVAILABLE


def test_no_windows_write_path_remains():
    assert not hasattr(sp, "_windows_create") and not hasattr(sp, "_windows_remove_if_same")
    import inspect

    source = inspect.getsource(sp)
    assert "O_CREAT" not in source.split("def _windows_component_identities")[1]  # no create flag in Windows code


@windows_only
def test_windows_key_creation_touches_nothing(tmp_path, monkeypatch):
    path = _private_dir(tmp_path)
    monkeypatch.setattr(sp, "_windows_stream_probe", lambda directory, identity: None)  # mock: open on FAT32
    directory = SafeDirectory.open(path, role="keys", windows_attestation=ATTESTED)
    calls = []
    for name in ("open", "stat", "lstat", "fstat", "write", "fsync", "unlink", "replace", "rename", "mkdir"):
        real = getattr(sp.os, name)
        monkeypatch.setattr(sp.os, name, (lambda real, name: lambda *a, **k: calls.append(name) or real(*a, **k))(
            real, name))
    monkeypatch.setattr(kf.secrets, "token_bytes", lambda n: pytest.fail("secret generated on a refused path"))
    for purpose in (KeyPurpose.CHAIN, KeyPurpose.AUTH, KeyPurpose.REF):
        assert code_of(kf.create_key_file, directory, purpose.value + ".key", purpose) is (
            StorageErrorCode.UNSUPPORTED_PLATFORM)
    assert code_of(directory.create_private_file, "chain.key", line()) is StorageErrorCode.UNSUPPORTED_PLATFORM
    assert calls == []  # no filesystem call at all on the refused path
    monkeypatch.undo()
    assert os.listdir(path) == []  # no key, empty or temporary file
    directory.close()


@windows_only
def test_create_on_real_fat32_writes_nothing(tmp_path, monkeypatch):
    path = _private_dir(tmp_path)
    if _is_stream_capable(path):
        pytest.skip("needs FAT32/exFAT")
    monkeypatch.setattr(sp, "_windows_stream_probe", lambda directory, identity: None)
    directory = SafeDirectory.open(path, role="keys", windows_attestation=ATTESTED)
    monkeypatch.undo()
    assert code_of(kf.create_key_file, directory, "chain.key", KeyPurpose.CHAIN) is StorageErrorCode.UNSUPPORTED_PLATFORM
    assert os.listdir(path) == []
    directory.close()


# --- H2 / R1: classification of stream-probe outcomes (portable; filesystem calls mocked) ------------


class _StatLike:
    def __init__(self, dev, ino):
        self.st_dev, self.st_ino = dev, ino


def test_probe_reports_an_unsupported_capability(monkeypatch):
    def failing(path, *args, **kwargs):
        raise OSError(errno.EINVAL, "zq-canary invalid name")  # what FAT32 returns (WinError 123)

    monkeypatch.setattr(sp.os, "stat", failing)
    assert sp._windows_stream_probe("C:\\keys", (1, 2)) is StorageErrorCode.UNSUPPORTED_FILESYSTEM


def test_probe_reports_an_identity_mismatch(monkeypatch):
    monkeypatch.setattr(sp.os, "stat", lambda path, *a, **k: _StatLike(1, 3))
    assert sp._windows_stream_probe("C:\\keys", (1, 2)) is StorageErrorCode.UNSAFE_PATH
    monkeypatch.setattr(sp.os, "stat", lambda path, *a, **k: _StatLike(9, 2))
    assert sp._windows_stream_probe("C:\\keys", (1, 2)) is StorageErrorCode.UNSAFE_PATH
    monkeypatch.setattr(sp.os, "stat", lambda path, *a, **k: _StatLike(1, 2))
    assert sp._windows_stream_probe("C:\\keys", (1, 2)) is None


@pytest.mark.parametrize(
    "probe, components, expected",
    [
        (None, "same", None),
        (StorageErrorCode.UNSAFE_PATH, "same", (StorageErrorCode.UNSAFE_PATH, "directory:changed")),
        (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "same",
         (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "directory:filesystem")),
        (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "changed", (StorageErrorCode.UNSAFE_PATH, "directory:changed")),
        (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "vanished", (StorageErrorCode.UNSAFE_PATH, "directory:changed")),
        (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "reparse", (StorageErrorCode.UNSAFE_PATH, "directory:changed")),
    ],
    ids=["supported", "mismatch", "capability-unchanged-identity", "capability-plus-changed-identity",
         "capability-plus-vanished-component", "capability-plus-new-reparse-point"],
)
def test_probe_problem_classification(probe, components, expected, monkeypatch):
    identities = ((1, 10), (1, 11))

    def component_identities(path, parts):
        if components == "same":
            return identities
        if components == "changed":
            return ((1, 10), (1, 99))
        if components == "vanished":
            raise FileNotFoundError(errno.ENOENT, "zq-canary gone")
        raise StorageError(StorageErrorCode.UNSAFE_PATH, "directory:reparse")

    monkeypatch.setattr(sp, "_windows_stream_probe", lambda directory, identity: probe)
    monkeypatch.setattr(sp, "_windows_component_identities", component_identities)
    assert sp._windows_probe_problem("C:\\a\\keys", identities) == expected


# --- Windows logic with the stream probe MOCKED (synthetic material; NOT evidence of NTFS support) ----


@pytest.fixture
def mocked_windows_dir(tmp_path, monkeypatch):
    if not IS_WINDOWS:
        pytest.skip("Windows-only")
    monkeypatch.setattr(sp, "_windows_stream_probe", lambda directory, identity: None)
    path = _private_dir(tmp_path)
    directory = SafeDirectory.open(path, role="keys", windows_attestation=ATTESTED)
    yield path, directory
    directory.close()


def _write(path, name, data):
    with open(os.path.join(path, name), "wb") as handle:
        handle.write(data)


def test_mocked_windows_load_and_refusals(mocked_windows_dir):
    path, directory = mocked_windows_dir
    _write(path, "chain.key", line())
    _write(path, "auth.key", line(b"auth", AUTH_MATERIAL))
    _write(path, "big.key", line() + b"x" * 200)
    assert kf.load_key_file(directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID).key_id == CHAIN_ID
    assert code_of(kf.load_key_file, directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=AUTH_ID) is (
        StorageErrorCode.KEY_ID_MISMATCH)
    assert code_of(kf.load_key_file, directory, "auth.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID) is (
        StorageErrorCode.KEY_FILE_FORMAT)
    assert code_of(kf.load_key_file, directory, "big.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID) is (
        StorageErrorCode.KEY_FILE_FORMAT)
    assert code_of(kf.load_key_file, directory, "missing.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID) is (
        StorageErrorCode.KEY_FILE_MISSING)
    os.mkdir(os.path.join(path, "dir.key"))
    assert code_of(kf.load_key_file, directory, "dir.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID) is (
        StorageErrorCode.KEY_FILE_UNSAFE)
    with pytest.raises(TypeError):
        kf.load_key_file(directory, "chain.key", KeyPurpose.CHAIN)  # pin still mandatory on Windows
    assert code_of(kf.load_key_file, directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID,
                   distrusted_key_ids=frozenset({CHAIN_ID})) is StorageErrorCode.KEY_ID_MISMATCH


def test_mocked_windows_identity_mismatch_during_read_is_unsafe_path(mocked_windows_dir, monkeypatch):
    path, directory = mocked_windows_dir
    _write(path, "chain.key", line())
    monkeypatch.setattr(sp, "_windows_stream_probe", lambda directory, identity: StorageErrorCode.UNSAFE_PATH)
    with pytest.raises(StorageError) as info:
        kf.load_key_file(directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID)
    assert (info.value.code, info.value.path) == (StorageErrorCode.UNSAFE_PATH, "directory:changed")


def test_mocked_windows_capability_loss_during_read_is_unsupported(mocked_windows_dir, monkeypatch):
    path, directory = mocked_windows_dir
    _write(path, "chain.key", line())
    monkeypatch.setattr(sp, "_windows_stream_probe",
                        lambda directory, identity: StorageErrorCode.UNSUPPORTED_FILESYSTEM)
    with pytest.raises(StorageError) as info:
        kf.load_key_file(directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID)
    assert (info.value.code, info.value.path) == (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "directory:filesystem")


def test_mocked_windows_identity_mismatch_at_open_is_unsafe_path(tmp_path, monkeypatch):
    if not IS_WINDOWS:
        pytest.skip("Windows-only")
    path = _private_dir(tmp_path)
    monkeypatch.setattr(sp, "_windows_stream_probe", lambda directory, identity: StorageErrorCode.UNSAFE_PATH)
    with pytest.raises(StorageError) as info:
        SafeDirectory.open(path, role="keys", windows_attestation=ATTESTED)
    assert (info.value.code, info.value.path) == (StorageErrorCode.UNSAFE_PATH, "directory:changed")


def test_mocked_windows_growth_during_read_is_refused(mocked_windows_dir, monkeypatch):
    path, directory = mocked_windows_dir
    _write(path, "chain.key", line())
    real_read = os.read

    def growing(fd, n):
        data = real_read(fd, n)
        if data:
            with open(os.path.join(path, "chain.key"), "ab") as handle:
                handle.write(b"x")
        return data

    monkeypatch.setattr(sp.os, "read", growing)
    assert code_of(kf.load_key_file, directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID) in (
        StorageErrorCode.KEY_FILE_UNSAFE, StorageErrorCode.KEY_FILE_FORMAT)


def test_mocked_windows_size_change_after_read_is_refused(mocked_windows_dir, monkeypatch):
    # The read returns the original, valid line, but the file grew meanwhile: only the stability
    # check (fstat before and after) can refuse it.
    path, directory = mocked_windows_dir
    _write(path, "chain.key", line())
    served = []

    def read_once(fd, n):
        if served:
            return b""
        served.append(1)
        with open(os.path.join(path, "chain.key"), "ab") as handle:
            handle.write(b"x")
        return line()

    monkeypatch.setattr(sp.os, "read", read_once)
    assert code_of(kf.load_key_file, directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID) is (
        StorageErrorCode.KEY_FILE_UNSAFE)


def test_mocked_windows_directory_removed_after_open_is_refused(mocked_windows_dir):
    path, directory = mocked_windows_dir
    os.rename(path, path + "-moved")
    assert code_of(kf.load_key_file, directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID) is (
        StorageErrorCode.UNSAFE_PATH)


def _with_reparse_attribute(st):
    """A copy of a real stat result with FILE_ATTRIBUTE_REPARSE_POINT set (mock; not evidence)."""
    return os.stat_result(tuple(st)[:10], {"st_file_attributes": st.st_file_attributes
                                           | stat.FILE_ATTRIBUTE_REPARSE_POINT,
                                           "st_reparse_tag": 0x9000001A})


def test_mocked_windows_non_surrogate_reparse_key_file_is_refused(mocked_windows_dir, monkeypatch):
    # Reparse points that do not redirect the name (e.g. cloud placeholders, dedup) look like regular
    # files; only the attribute check refuses them. Such files can't be created without special
    # drivers, so the attribute is mocked here.
    path, directory = mocked_windows_dir
    _write(path, "chain.key", line())
    full = os.path.join(path, "chain.key")
    real_lstat = os.lstat
    monkeypatch.setattr(sp.os, "lstat", lambda p, *a, **k: _with_reparse_attribute(real_lstat(p, *a, **k))
                        if p == full else real_lstat(p, *a, **k))
    assert code_of(kf.load_key_file, directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID) is (
        StorageErrorCode.KEY_FILE_UNSAFE)


def test_mocked_windows_non_surrogate_reparse_directory_is_refused(tmp_path, monkeypatch):
    if not IS_WINDOWS:
        pytest.skip("Windows-only")
    monkeypatch.setattr(sp, "_windows_stream_probe", lambda directory, identity: None)
    path = _private_dir(tmp_path)
    real_lstat = os.lstat
    monkeypatch.setattr(sp.os, "lstat", lambda p, *a, **k: _with_reparse_attribute(real_lstat(p, *a, **k))
                        if p == path else real_lstat(p, *a, **k))
    assert code_of(SafeDirectory.open, path, role="keys", windows_attestation=ATTESTED) is StorageErrorCode.UNSAFE_PATH


def test_mocked_windows_errors_contain_no_paths(mocked_windows_dir):
    path, directory = mocked_windows_dir
    for call in (lambda: kf.load_key_file(directory, "missing.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID),
                 lambda: SafeDirectory.open(path + "\\nope", role="keys", windows_attestation=ATTESTED),
                 lambda: kf.create_key_file(directory, "chain.key", KeyPurpose.CHAIN)):
        with pytest.raises(StorageError) as info:
            call()
        text = str(info.value) + repr(info.value) + repr(info.value.args)
        assert path not in text and os.path.basename(os.path.dirname(path)) not in text


# --- NTFS integration (native NTFS only; authorized directory required) -----------------------------
#
# Founder authorization (B2-M2-C2-B NTFS): synthetic keys and isolated test data only; no ACL or system
# changes. Since H2, Windows key creation is refused, so these tests plant synthetic key files with plain
# test-side writes. The attestation object is test-only: the ACL recipe was NOT applied, so these tests
# validate code behaviour on native NTFS, not ACL protection.


ntfs_only = pytest.mark.skipif(not (IS_WINDOWS and NTFS_DIR),
                               reason="needs an authorized native NTFS directory (RIG_SENTINEL_NTFS_TEST_DIR)")


def _synthetic_material(seed):
    return hashlib.sha256(b"rig-c2b-ntfs-synthetic-" + seed.encode()).digest()


def _plant(directory_path, name, purpose=b"chain", seed="1"):
    """Write a synthetic key file with a plain test-side write; return its key id."""
    material = _synthetic_material(seed)
    with open(os.path.join(directory_path, name), "wb") as handle:
        handle.write(line(purpose, material))
    return key_id(purpose, material)


def _remove_tree(path):
    """Delete test data without ever descending into a junction or symlink."""
    for entry in os.scandir(path):
        full = entry.path
        st = os.lstat(full)
        if st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            if entry.is_dir(follow_symlinks=False) or stat.S_ISDIR(st.st_mode):
                os.rmdir(full)  # removes the junction/link itself, never its target
            else:
                os.unlink(full)
        elif stat.S_ISDIR(st.st_mode):
            _remove_tree(full)
        else:
            os.chmod(full, stat.S_IWRITE)
            os.unlink(full)
    os.rmdir(path)


@pytest.fixture
def ntfs_dir(monkeypatch):
    monkeypatch.setattr(kf.secrets, "token_bytes", lambda n: pytest.fail("no key generation on Windows"))
    base = os.path.join(NTFS_DIR, "rig-c2b-" + os.urandom(6).hex())
    os.mkdir(base)
    yield base
    _remove_tree(base)


@ntfs_only
def test_ntfs_stream_probe_classifies_the_directory(ntfs_dir):
    st = os.stat(ntfs_dir)
    assert sp._windows_stream_probe(ntfs_dir, (st.st_dev, st.st_ino)) is None
    assert sp._windows_stream_probe(ntfs_dir, (st.st_dev, st.st_ino + 1)) is StorageErrorCode.UNSAFE_PATH


@ntfs_only
def test_ntfs_key_creation_is_refused_before_any_write(ntfs_dir):
    with SafeDirectory.open(ntfs_dir, role="keys", windows_attestation=ATTESTED) as directory:
        for purpose in (KeyPurpose.CHAIN, KeyPurpose.AUTH, KeyPurpose.REF):
            assert code_of(kf.create_key_file, directory, purpose.value + ".key", purpose) is (
                StorageErrorCode.UNSUPPORTED_PLATFORM)
        assert code_of(directory.create_private_file, "chain.key", line()) is StorageErrorCode.UNSUPPORTED_PLATFORM
    assert os.listdir(ntfs_dir) == []


@ntfs_only
def test_ntfs_load_planted_synthetic_key(ntfs_dir):
    pinned = _plant(ntfs_dir, "chain.key")
    with SafeDirectory.open(ntfs_dir, role="keys", windows_attestation=ATTESTED) as directory:
        assert kf.load_key_file(directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=pinned).key_id == pinned
        assert code_of(kf.load_key_file, directory, "chain.key", KeyPurpose.CHAIN, expected_key_id="0" * 32) is (
            StorageErrorCode.KEY_ID_MISMATCH)


@ntfs_only
def test_ntfs_key_set_loads_independent_synthetic_keys(ntfs_dir):
    auth_id = _plant(ntfs_dir, "auth.key", b"auth", "2")
    chain_id = _plant(ntfs_dir, "chain.key", b"chain", "3")
    with SafeDirectory.open(ntfs_dir, role="keys", windows_attestation=ATTESTED) as directory:
        keys = kf.load_key_set(directory, auth=kf.KeyFileRef("auth.key", auth_id),
                               chain=kf.KeyFileRef("chain.key", chain_id))
        assert (keys.auth.key_id, keys.chain.key_id) == (auth_id, chain_id)


@ntfs_only
def test_ntfs_hard_link_is_refused(ntfs_dir):
    pinned = _plant(ntfs_dir, "chain.key")
    os.link(os.path.join(ntfs_dir, "chain.key"), os.path.join(ntfs_dir, "chain-link.key"))
    assert os.stat(os.path.join(ntfs_dir, "chain.key")).st_nlink == 2
    with SafeDirectory.open(ntfs_dir, role="keys", windows_attestation=ATTESTED) as directory:
        assert code_of(kf.load_key_file, directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=pinned) is (
            StorageErrorCode.KEY_FILE_UNSAFE)


@ntfs_only
def test_ntfs_junction_components_are_refused(ntfs_dir):
    import _winapi

    target = os.path.join(ntfs_dir, "target")
    os.mkdir(target)
    junction = os.path.join(ntfs_dir, "junction")
    _winapi.CreateJunction(target, junction)
    inner = os.path.join(junction, "inner")
    os.mkdir(inner)
    for path in (junction, inner):  # junction as the final component and as an ancestor
        assert code_of(SafeDirectory.open, path, role="keys", windows_attestation=ATTESTED) is (
            StorageErrorCode.UNSAFE_PATH)


@ntfs_only
def test_ntfs_junction_inserted_after_open_is_refused(ntfs_dir):
    import _winapi

    keys = os.path.join(ntfs_dir, "keys")
    os.mkdir(keys)
    other = os.path.join(ntfs_dir, "other")
    os.mkdir(other)
    pinned = _plant(keys, "chain.key")
    with SafeDirectory.open(keys, role="keys", windows_attestation=ATTESTED) as directory:
        os.rename(keys, keys + "-orig")
        _winapi.CreateJunction(other, keys)
        assert code_of(kf.load_key_file, directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=pinned) is (
            StorageErrorCode.UNSAFE_PATH)
        assert code_of(kf.create_key_file, directory, "auth.key", KeyPurpose.AUTH) is (
            StorageErrorCode.UNSUPPORTED_PLATFORM)
        assert os.listdir(other) == []


@ntfs_only
def test_ntfs_symlinked_key_file_is_refused(ntfs_dir):
    pinned = _plant(ntfs_dir, "chain.key")
    try:
        os.symlink(os.path.join(ntfs_dir, "chain.key"), os.path.join(ntfs_dir, "alias.key"))
    except OSError:
        pytest.skip("creating symlinks needs Developer Mode or SeCreateSymbolicLinkPrivilege")
    with SafeDirectory.open(ntfs_dir, role="keys", windows_attestation=ATTESTED) as directory:
        assert code_of(kf.load_key_file, directory, "alias.key", KeyPurpose.CHAIN, expected_key_id=pinned) is (
            StorageErrorCode.KEY_FILE_UNSAFE)


@ntfs_only
def test_ntfs_swapped_final_file_is_caught_by_identity(ntfs_dir, monkeypatch):
    pinned = _plant(ntfs_dir, "chain.key", seed="4")
    _plant(ntfs_dir, "other.key", seed="5")
    with SafeDirectory.open(ntfs_dir, role="keys", windows_attestation=ATTESTED) as directory:
        real_open = os.open

        def swapping_open(file, flags, *args, **kwargs):
            if str(file).endswith("\\chain.key"):
                os.replace(os.path.join(ntfs_dir, "other.key"), os.path.join(ntfs_dir, "chain.key"))
            return real_open(file, flags, *args, **kwargs)

        monkeypatch.setattr(sp.os, "open", swapping_open)
        assert code_of(kf.load_key_file, directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=pinned) is (
            StorageErrorCode.UNSAFE_PATH)


@ntfs_only
def test_ntfs_alternate_stream_does_not_change_loading(ntfs_dir):
    pinned = _plant(ntfs_dir, "chain.key")
    with open(os.path.join(ntfs_dir, "chain.key") + ":hidden", "wb") as handle:
        handle.write(b"zq-canary-stream " * 100)
    with SafeDirectory.open(ntfs_dir, role="keys", windows_attestation=ATTESTED) as directory:
        assert kf.load_key_file(directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=pinned).key_id == pinned
        assert code_of(kf.load_key_file, directory, "chain.key:hidden", KeyPurpose.CHAIN, expected_key_id=pinned) is (
            StorageErrorCode.UNSAFE_PATH)


@ntfs_only
def test_ntfs_open_key_file_cannot_be_replaced(ntfs_dir):
    _plant(ntfs_dir, "chain.key", seed="6")
    _plant(ntfs_dir, "other.key", seed="7")
    fd = os.open(os.path.join(ntfs_dir, "chain.key"), os.O_RDONLY | os.O_BINARY)
    try:
        with pytest.raises(PermissionError):
            os.replace(os.path.join(ntfs_dir, "other.key"), os.path.join(ntfs_dir, "chain.key"))
    finally:
        os.close(fd)


@ntfs_only
def test_ntfs_short_name_alias_is_refused(ntfs_dir):
    import _winapi

    long_dir = os.path.join(ntfs_dir, "averylongdirectoryname_for_alias")
    os.mkdir(long_dir)
    short = _winapi.GetShortPathName(long_dir) if hasattr(_winapi, "GetShortPathName") else long_dir
    if short == long_dir:
        pytest.skip("8.3 short names are not generated on this NTFS volume")
    assert code_of(SafeDirectory.open, short, role="keys", windows_attestation=ATTESTED) is StorageErrorCode.UNSAFE_PATH


# --- NTFS race evidence (R1 classification, R2 residual, R3 path unreachable) -------------------------


def _swap_hooks(keys_dir, attacker_dir):
    import _winapi

    def swap():
        os.rename(keys_dir, keys_dir + "-orig")
        _winapi.CreateJunction(attacker_dir, keys_dir)

    def restore():
        os.rmdir(keys_dir)  # removes the junction only
        os.rename(keys_dir + "-orig", keys_dir)

    return swap, restore


def _read_race_setup(ntfs_dir):
    keys = os.path.join(ntfs_dir, "keys")
    attacker = os.path.join(ntfs_dir, "attacker")
    os.mkdir(keys)
    os.mkdir(attacker)
    pinned = _plant(keys, "chain.key", seed="8")
    attacker_material = hashlib.sha256(b"rig-c2b-ntfs-attacker").digest()
    with open(os.path.join(attacker, "chain.key"), "wb") as handle:
        handle.write(line(b"chain", attacker_material))
    return keys, attacker, pinned, key_id(b"chain", attacker_material)


@ntfs_only
def test_ntfs_two_flip_read_race_is_detected_as_unsafe_path(ntfs_dir, monkeypatch):
    """R1 (H2): swap an ancestor before the file lstat and restore after the post-read lstat. The in-read
    stream probe resolves to a different directory and the read is refused as UNSAFE_PATH (previously
    reported as the misleading UNSUPPORTED_FILESYSTEM)."""
    keys, attacker, pinned, _attacker_id = _read_race_setup(ntfs_dir)
    full = keys + "\\chain.key"
    swap, restore = _swap_hooks(keys, attacker)
    real_lstat = os.lstat
    calls = []

    def racing_lstat(path, *args, **kwargs):
        if path == full:
            calls.append(1)
            if len(calls) == 1:
                swap()
                return real_lstat(path, *args, **kwargs)
            result = real_lstat(path, *args, **kwargs)
            restore()
            return result
        return real_lstat(path, *args, **kwargs)

    with SafeDirectory.open(keys, role="keys", windows_attestation=ATTESTED) as directory:
        monkeypatch.setattr(sp.os, "lstat", racing_lstat)
        with pytest.raises(StorageError) as info:
            kf.load_key_file(directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=pinned)
        monkeypatch.setattr(sp.os, "lstat", real_lstat)
    assert (info.value.code, info.value.path) == (StorageErrorCode.UNSAFE_PATH, "directory:changed")
    if len(calls) == 1:
        restore()  # the read stopped before the second lstat: undo the swap
    assert os.path.isdir(keys) and not os.path.exists(keys + "-orig")


@ntfs_only
def test_ntfs_four_flip_read_race_is_stopped_only_by_the_pin(ntfs_dir, monkeypatch):
    """R2 (residual, unchanged by H2): swap before the file lstat, restore before the stream probe, swap
    before the post-read lstat, restore before the final component re-check. The filesystem checks do
    not detect this; the mandatory pin refuses the substituted key."""
    keys, attacker, pinned, attacker_id = _read_race_setup(ntfs_dir)
    full = keys + "\\chain.key"
    swap, restore = _swap_hooks(keys, attacker)
    real_lstat, real_stat = os.lstat, os.stat

    def run(expected_pin):
        state = {"swapped": False, "lstat_calls": 0}

        def flip(to_swapped):
            if state["swapped"] != to_swapped:
                (swap if to_swapped else restore)()
                state["swapped"] = to_swapped

        def racing_lstat(path, *args, **kwargs):
            if path == full:
                state["lstat_calls"] += 1
                flip(True)
                result = real_lstat(path, *args, **kwargs)
                if state["lstat_calls"] == 2:
                    flip(False)  # restore before the final component re-check
                return result
            return real_lstat(path, *args, **kwargs)

        def racing_stat(path, *args, **kwargs):
            if str(path).endswith("::$INDEX_ALLOCATION"):
                flip(False)  # restore just before the stream probe
            return real_stat(path, *args, **kwargs)

        with SafeDirectory.open(keys, role="keys", windows_attestation=ATTESTED) as directory:
            monkeypatch.setattr(sp.os, "lstat", racing_lstat)
            monkeypatch.setattr(sp.os, "stat", racing_stat)
            try:
                return kf.load_key_file(directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=expected_pin)
            finally:
                monkeypatch.setattr(sp.os, "lstat", real_lstat)
                monkeypatch.setattr(sp.os, "stat", real_stat)
                flip(False)

    with pytest.raises(StorageError) as info:
        run(pinned)
    assert info.value.code is StorageErrorCode.KEY_ID_MISMATCH  # refused by the pin, not by filesystem checks
    assert run(attacker_id).key_id == attacker_id  # the race itself goes undetected
    assert os.path.isdir(keys) and not os.path.exists(keys + "-orig")


@ntfs_only
def test_ntfs_create_race_path_is_unreachable(ntfs_dir, monkeypatch):
    """R3 (H2): the race demonstrated before H2 (an ancestor swapped around the exclusive create) needs
    the Windows create path. Creation is now refused before any filesystem call, so the race hooks never
    run and nothing is written anywhere. This shows the path is unreachable through the API; it does not
    show that Windows filesystem races are impossible."""
    keys = os.path.join(ntfs_dir, "keys")
    attacker = os.path.join(ntfs_dir, "attacker")
    os.mkdir(keys)
    os.mkdir(attacker)
    swap, _restore = _swap_hooks(keys, attacker)
    triggered = []
    real_open = os.open

    def racing_open(path, flags, *args, **kwargs):
        if flags & os.O_CREAT:
            triggered.append(1)
            swap()
        return real_open(path, flags, *args, **kwargs)

    with SafeDirectory.open(keys, role="keys", windows_attestation=ATTESTED) as directory:
        monkeypatch.setattr(sp.os, "open", racing_open)
        assert code_of(kf.create_key_file, directory, "chain.key", KeyPurpose.CHAIN) is (
            StorageErrorCode.UNSUPPORTED_PLATFORM)
        monkeypatch.setattr(sp.os, "open", real_open)
    assert triggered == [] and os.listdir(attacker) == [] and os.listdir(keys) == []


# --- POSIX integration (Linux/macOS) ------------------------------------------------------------


posix_only = pytest.mark.skipif(not IS_POSIX, reason="POSIX-only")


@pytest.fixture
def posix_dir():
    import shutil
    import tempfile

    home = os.path.realpath(os.path.expanduser("~"))
    base = tempfile.mkdtemp(prefix="rig-c2b-", dir=home)
    os.chmod(base, 0o700)
    yield base
    shutil.rmtree(base, ignore_errors=True)


@posix_only
def test_posix_create_and_load_with_pin(posix_dir):
    old = os.umask(0)
    try:
        with SafeDirectory.open(posix_dir, role="keys") as directory:
            pinned = kf.create_key_file(directory, "chain.key", KeyPurpose.CHAIN)
            assert stat.S_IMODE(os.stat(os.path.join(posix_dir, "chain.key")).st_mode) == 0o600
            assert kf.load_key_file(directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=pinned).key_id == pinned
            assert code_of(kf.create_key_file, directory, "chain.key", KeyPurpose.CHAIN) is (
                StorageErrorCode.KEY_FILE_EXISTS)
    finally:
        os.umask(old)


@posix_only
def test_posix_symlinks_are_refused(posix_dir):
    real = os.path.join(posix_dir, "real")
    os.mkdir(real, 0o700)
    link_dir = os.path.join(posix_dir, "linkdir")
    os.symlink(real, link_dir)
    assert code_of(SafeDirectory.open, link_dir, role="keys") is StorageErrorCode.UNSAFE_PATH
    with SafeDirectory.open(real, role="keys") as directory:
        pinned = kf.create_key_file(directory, "chain.key", KeyPurpose.CHAIN)
        os.symlink(os.path.join(real, "chain.key"), os.path.join(real, "alias.key"))
        assert code_of(kf.load_key_file, directory, "alias.key", KeyPurpose.CHAIN, expected_key_id=pinned) is (
            StorageErrorCode.UNSAFE_PATH)


@posix_only
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660])
def test_posix_unsafe_key_modes_are_refused(posix_dir, mode):
    with SafeDirectory.open(posix_dir, role="keys") as directory:
        pinned = kf.create_key_file(directory, "chain.key", KeyPurpose.CHAIN)
        os.chmod(os.path.join(posix_dir, "chain.key"), mode)
        assert code_of(kf.load_key_file, directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=pinned) is (
            StorageErrorCode.KEY_FILE_UNSAFE)


@posix_only
def test_posix_unsafe_directories_are_refused(posix_dir):
    os.chmod(posix_dir, 0o750)
    assert code_of(SafeDirectory.open, posix_dir, role="keys") is StorageErrorCode.UNSAFE_PERMISSIONS
    os.chmod(posix_dir, 0o700)
    inner = os.path.join(posix_dir, "inner")
    os.mkdir(inner, 0o700)
    os.chmod(posix_dir, 0o777)
    try:
        assert code_of(SafeDirectory.open, inner, role="keys") is StorageErrorCode.UNSAFE_PERMISSIONS
    finally:
        os.chmod(posix_dir, 0o700)


@posix_only
def test_posix_hard_link_and_fifo_are_refused(posix_dir):
    with SafeDirectory.open(posix_dir, role="keys") as directory:
        pinned = kf.create_key_file(directory, "chain.key", KeyPurpose.CHAIN)
        os.link(os.path.join(posix_dir, "chain.key"), os.path.join(posix_dir, "copy.key"))
        assert code_of(kf.load_key_file, directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=pinned) is (
            StorageErrorCode.KEY_FILE_UNSAFE)
        os.mkfifo(os.path.join(posix_dir, "fifo.key"), 0o600)
        assert code_of(kf.load_key_file, directory, "fifo.key", KeyPurpose.CHAIN, expected_key_id=pinned) is (
            StorageErrorCode.KEY_FILE_UNSAFE)  # O_NONBLOCK: no hang


@posix_only
def test_posix_held_directory_survives_rename(posix_dir):
    inner = os.path.join(posix_dir, "inner")
    os.mkdir(inner, 0o700)
    with SafeDirectory.open(inner, role="keys") as directory:
        pinned = kf.create_key_file(directory, "chain.key", KeyPurpose.CHAIN)
        os.rename(inner, inner + "-moved")
        os.mkdir(inner, 0o700)  # attacker-style replacement at the old path
        assert kf.load_key_file(directory, "chain.key", KeyPurpose.CHAIN, expected_key_id=pinned).key_id == pinned


@posix_only
def test_posix_non_canonical_path_is_refused(posix_dir):
    assert code_of(SafeDirectory.open, posix_dir + "/../" + os.path.basename(posix_dir), role="keys") is (
        StorageErrorCode.UNSAFE_PATH)


@posix_only
@pytest.mark.skipif(sys.platform != "linux" or not os.path.isdir("/tmp"), reason="Linux /tmp check")
def test_posix_world_writable_ancestor_is_refused():
    import tempfile

    base = tempfile.mkdtemp(dir="/tmp")
    try:
        os.chmod(base, 0o700)
        if stat.S_IMODE(os.stat("/tmp").st_mode) & 0o002:
            assert code_of(SafeDirectory.open, base, role="keys") is StorageErrorCode.UNSAFE_PERMISSIONS
    finally:
        os.rmdir(base)


# --- Errors never contain material, ids or paths ----------------------------------------------------


def test_key_material_never_appears_in_errors_or_repr(monkeypatch):
    _serve(monkeypatch, {"chain.key": line(), "bad.key": line()[:-1]})
    key = kf.load_key_file(fake_directory(), "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID)
    assert CHAIN_MATERIAL.hex() not in repr(key) + str(key)
    for name, pin in (("bad.key", CHAIN_ID), ("chain.key", AUTH_ID)):
        with pytest.raises(StorageError) as info:
            kf.load_key_file(fake_directory(), name, KeyPurpose.CHAIN, expected_key_id=pin)
        text = str(info.value) + repr(info.value) + repr(info.value.args)
        assert CHAIN_MATERIAL.hex() not in text and CHAIN_ID not in text and AUTH_ID not in text


def test_audit_key_material_matches_the_file(monkeypatch):
    _serve(monkeypatch, {"chain.key": line()})
    key = kf.load_key_file(fake_directory(), "chain.key", KeyPurpose.CHAIN, expected_key_id=CHAIN_ID)
    assert key._same_material(AuditKey.from_bytes(KeyPurpose.CHAIN, CHAIN_MATERIAL))
