"""Genesis B2-M2-C2-C: secure filesystem operations for audit storage (safepath.py).

Test tiers (mocked tests are never evidence of native platform behaviour):
* Portable: pure name tables, limits, mountinfo parsing, privacy, object hygiene, static checks.
* Mocked: Windows-kind and incapable-POSIX objects with every OS call patched to fail, proving
  that write operations refuse before touching the filesystem; mountinfo policy with fake inputs.
* POSIX native (Linux/macOS CI): real descriptor-relative operations in a private directory under
  the home directory, including fault injection at named steps.
* Linux native: real /proc/self/mountinfo and descriptor-leak counting.
* NTFS native: only with an authorized native NTFS directory (RIG_SENTINEL_NTFS_TEST_DIR); Windows
  audit storage is read-only, so these tests plant synthetic files with the test's own I/O.
* Windows FAT32: the audit root is refused before anything is written.
All data is synthetic.
"""

import ast
import copy
import errno
import inspect
import os
import pickle
import random
import stat
import sys

import pytest

from rig_sentinel.audit import safepath as sp
from rig_sentinel.audit.safepath import (
    ANCHOR_NAME,
    ANCHOR_TEMP_NAME,
    AuditDirectory,
    ChainDirectory,
    CreatedToken,
    Durability,
    ListResult,
    MountEntry,
    SafeAppendFile,
    SafeDirectory,
    SafeReadFile,
    WindowsAttestation,
    check_chain_directory_name,
    check_chain_member_name,
    filesystem_type,
    parse_mountinfo,
)
from rig_sentinel.audit.storage_errors import StorageError, StorageErrorCode

IS_WINDOWS = os.name == "nt"
IS_POSIX_WRITE = sp._platform() == "posix" and sp._posix_write_capable()
IS_LINUX = sys.platform == "linux"
NTFS_DIR = os.environ.get("RIG_SENTINEL_NTFS_TEST_DIR")
ATTESTED = WindowsAttestation(local_fixed_ntfs=True, acl_recipe_applied=True, dedicated_account=True)
CHAIN = "chain-" + "0123456789abcdef" * 2
OTHER_CHAIN = "chain-" + "f" * 32
LINE = b'{"synthetic":"record"}\n'

posix_only = pytest.mark.skipif(not IS_POSIX_WRITE, reason="POSIX-only")
linux_only = pytest.mark.skipif(not (IS_POSIX_WRITE and IS_LINUX), reason="Linux-only")
windows_only = pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only")
ntfs_only = pytest.mark.skipif(not (IS_WINDOWS and NTFS_DIR),
                               reason="needs an authorized native NTFS directory (RIG_SENTINEL_NTFS_TEST_DIR)")


def error_of(fn, *args, **kwargs):
    with pytest.raises(StorageError) as info:
        fn(*args, **kwargs)
    assert info.value.__context__ is None and info.value.__cause__ is None
    return info.value


def code_of(fn, *args, **kwargs):
    return error_of(fn, *args, **kwargs).code


def pair_of(fn, *args, **kwargs):
    error = error_of(fn, *args, **kwargs)
    return (error.code, error.path)


# --- Portable: name tables -------------------------------------------------------------------------------


@pytest.mark.parametrize("name", [CHAIN, OTHER_CHAIN, "chain-" + "0" * 32])
def test_chain_directory_names_accepted(name):
    assert check_chain_directory_name(name) == name


@pytest.mark.parametrize("name", ["chain-" + "0" * 31, "chain-" + "0" * 33, "chain-" + "A" * 32, "Chain-" + "0" * 32,
                                  "chain-" + "0" * 31 + "g", "chain_" + "0" * 32, "../" + CHAIN, CHAIN + "/x",
                                  CHAIN + "\x00", "", None, b"chain-" + b"0" * 32, "keys", "chain.key"])
def test_chain_directory_names_refused(name):
    assert pair_of(check_chain_directory_name, name) == (StorageErrorCode.UNSAFE_PATH, "path:chain-name")


@pytest.mark.parametrize("kind, name", [
    ("segment", "seg-0.jsonl"), ("segment", "seg-1.jsonl"), ("segment", "seg-9007199254740991.jsonl"),
    ("readable", "seg-12.jsonl"), ("readable", ANCHOR_NAME), ("readable", ANCHOR_TEMP_NAME),
    ("readable", ".seq_anchor.q0"), ("readable", ".seq_anchor.q7"),
    ("quarantine", ".seq_anchor.q3"), ("quarantine-source", ANCHOR_NAME), ("quarantine-source", ANCHOR_TEMP_NAME),
])
def test_chain_member_names_accepted(kind, name):
    assert check_chain_member_name(name, kind=kind) == name


@pytest.mark.parametrize("kind, name", [
    ("segment", "seg-01.jsonl"), ("segment", "seg-.jsonl"), ("segment", "seg-1.JSONL"), ("segment", "seg-1.jsonl.tmp"),
    ("segment", "seg-12345678901234567.jsonl"), ("segment", "seg--1.jsonl"), ("segment", ANCHOR_NAME),
    ("segment", "../seg-1.jsonl"), ("segment", "seg-1.jsonl/"), ("segment", "chain.key"),
    ("readable", ".writer.lock"), ("readable", ".seq_anchor.q8"), ("readable", ".seq_anchor.q"),
    ("readable", "a.key"), ("readable", "NUL"), ("readable", ".seq_anchor:stream"),
    ("quarantine", ANCHOR_NAME), ("quarantine", ".seq_anchor.q10"),
    ("quarantine-source", "seg-1.jsonl"), ("quarantine-source", ".seq_anchor.q0"),
    ("unknown-kind", "seg-1.jsonl"), ("segment", None), ("segment", b"seg-1.jsonl"),
])
def test_chain_member_names_refused(kind, name):
    assert pair_of(check_chain_member_name, name, kind=kind) == (StorageErrorCode.UNSAFE_PATH, "path:member-name")


def test_no_kind_ever_accepts_a_key_file_name():
    for kind in ("segment", "readable", "quarantine", "quarantine-source"):
        for name in ("chain.key", "auth.key", "seg-1.key", ".seq_anchor.key"):
            assert code_of(check_chain_member_name, name, kind=kind) is StorageErrorCode.UNSAFE_PATH
    assert not sp._is_listed_member("chain.key")


# --- Portable: key and audit operations can never mix ------------------------------------------------------


C2C_WRITE_METHODS = ("create_exclusive", "open_append", "replace_atomically", "link_no_replace", "remove_created")


def test_key_directories_expose_no_audit_operations():
    for method in C2C_WRITE_METHODS + ("open_read", "open_chain", "list_names", "sync"):
        assert not hasattr(SafeDirectory, method)
    for cls in (AuditDirectory, ChainDirectory):
        for method in ("read_private_file", "create_private_file", "require_private_create"):
            assert not hasattr(cls, method)
    assert not issubclass(AuditDirectory, SafeDirectory) and not issubclass(ChainDirectory, SafeDirectory)


def test_key_directory_roles_are_unchanged():
    # The audit root is a separate class; SafeDirectory still accepts only "keys" (C2-B behaviour).
    for role in ("audit", "audit_root", "chain"):
        assert code_of(SafeDirectory.open, "/x", role=role) is StorageErrorCode.INPUT_TYPE_INVALID


def test_existing_key_file_codes_are_unchanged():
    expected = {"KEY_FILE_MISSING": "key_file_missing", "KEY_FILE_UNSAFE": "key_file_unsafe",
                "KEY_FILE_FORMAT": "key_file_format", "KEY_FILE_EXISTS": "key_file_exists",
                "KEY_ID_MISMATCH": "key_id_mismatch", "UNSAFE_PATH": "unsafe_path",
                "STORAGE_UNAVAILABLE": "storage_unavailable", "UNSUPPORTED_PLATFORM": "unsupported_platform"}
    for name, value in expected.items():
        assert StorageErrorCode[name].value == value
    for name in ("FILE_MISSING", "FILE_UNSAFE", "FILE_EXISTS", "PARTIAL_WRITE", "DURABILITY_FAILED",
                 "DURABILITY_UNCERTAIN", "ENTRY_LIMIT_EXCEEDED", "FILE_TOO_LARGE"):
        assert StorageErrorCode[name].value == name.lower()


# --- Mocked: Windows and incapable POSIX refuse every write before any OS call -----------------------------


OS_FUNCTIONS = ("open", "close", "mkdir", "link", "unlink", "replace", "rename", "stat", "lstat", "fstat", "write",
                "read", "fsync", "scandir", "dup", "fchmod", "chmod", "remove", "rmdir")


class _ForbiddenOsCall(Exception):
    """Raised (and recorded) if code under test touches the OS while the guard is active."""


class _OsGuard:
    def __init__(self):
        self.active = False
        self.calls = []

    def wrap(self, fn):
        def guarded(*args, **kwargs):
            self.active = True
            try:
                return fn(*args, **kwargs)
            finally:
                self.active = False

        return guarded


@pytest.fixture
def no_os(monkeypatch):
    """Every os function patched to fail, but only inside calls wrapped with ``no_os.wrap``."""
    guard = _OsGuard()
    for name in OS_FUNCTIONS:
        real = getattr(sp.os, name, None)
        if real is None:
            continue

        def patched(*args, _name=name, _real=real, **kwargs):
            if guard.active:
                guard.calls.append(_name)
                raise _ForbiddenOsCall(_name)
            return _real(*args, **kwargs)

        monkeypatch.setattr(sp.os, name, patched)
    yield guard
    assert guard.calls == [], guard.calls


def _chain(kind, fd=-1):
    return ChainDirectory(_kind=kind, _fd=fd, _path="C:\\audit\\" + CHAIN if kind == "nt" else "/a/" + CHAIN,
                          _identities=((1, 2),) if kind == "nt" else ())


def _audit(kind, fd=-1):
    return AuditDirectory(_kind=kind, _fd=fd, _path="C:\\audit" if kind == "nt" else "/a",
                          _identities=((1, 2),) if kind == "nt" else ())


def _write_calls(chain):
    return [
        lambda: chain.create_exclusive("seg-1.jsonl", max_size=1024),
        lambda: chain.create_exclusive("NUL", max_size=None),  # refused before validation too
        lambda: chain.open_append("seg-1.jsonl", max_size=1024),
        lambda: chain.replace_atomically(ANCHOR_NAME, LINE, max_bytes=1024),
        lambda: chain.replace_atomically(None, None, max_bytes=None),
        lambda: chain.link_no_replace(ANCHOR_NAME, ".seq_anchor.q0"),
        lambda: chain.remove_created(None),
        lambda: chain.sync(),
    ]


def test_windows_chain_writes_refuse_before_any_os_call(no_os):
    chain = _chain("nt")
    for call in _write_calls(chain):
        assert pair_of(no_os.wrap(call)) == (StorageErrorCode.UNSUPPORTED_PLATFORM, "file:write-windows")
    audit = _audit("nt")
    for name in (CHAIN, "bad"):
        assert pair_of(no_os.wrap(audit.open_chain), name, create=True) == (StorageErrorCode.UNSUPPORTED_PLATFORM,
                                                                             "file:write-windows")
    assert pair_of(no_os.wrap(audit.sync)) == (StorageErrorCode.UNSUPPORTED_PLATFORM, "file:write-windows")


def test_incapable_posix_refuses_writes_before_any_os_call(no_os, monkeypatch):
    monkeypatch.setattr(sp, "_posix_write_capable", lambda: False)
    for call in _write_calls(_chain("posix")):
        assert pair_of(no_os.wrap(call)) == (StorageErrorCode.UNSUPPORTED_PLATFORM, "file:write-platform")
    assert code_of(no_os.wrap(_audit("posix").open_chain), CHAIN, create=True) is StorageErrorCode.UNSUPPORTED_PLATFORM


def test_closed_directories_refuse_everything(no_os):
    for kind in ("posix", "nt"):
        chain = _chain(kind, fd=None)
        chain.close()
        for call in _write_calls(chain)[:1] + [lambda: chain.open_read("seg-1.jsonl", max_size=8),
                                                lambda: chain.list_names()]:
            assert code_of(no_os.wrap(call)) is StorageErrorCode.STORAGE_UNAVAILABLE


def test_open_chain_create_flag_must_be_a_bool(no_os):
    assert pair_of(no_os.wrap(_audit("posix").open_chain), CHAIN, create=1) == (StorageErrorCode.INPUT_TYPE_INVALID,
                                                                                 "directory:create")


@pytest.mark.parametrize("call, expected", [
    (lambda c: c.create_exclusive("seg-01.jsonl", max_size=8), (StorageErrorCode.UNSAFE_PATH, "path:member-name")),
    (lambda c: c.create_exclusive("seg-1.jsonl", max_size=0), (StorageErrorCode.INPUT_TYPE_INVALID, "file:max-size")),
    (lambda c: c.create_exclusive("seg-1.jsonl", max_size=True), (StorageErrorCode.INPUT_TYPE_INVALID, "file:max-size")),
    (lambda c: c.create_exclusive("seg-1.jsonl", max_size=(1 << 40) + 1),
     (StorageErrorCode.INPUT_TYPE_INVALID, "file:max-size")),
    (lambda c: c.open_append(ANCHOR_NAME, max_size=8), (StorageErrorCode.UNSAFE_PATH, "path:member-name")),
    (lambda c: c.replace_atomically("seg-1.jsonl", LINE, max_bytes=64), (StorageErrorCode.UNSAFE_PATH, "path:member-name")),
    (lambda c: c.replace_atomically(ANCHOR_TEMP_NAME, LINE, max_bytes=64),
     (StorageErrorCode.UNSAFE_PATH, "path:member-name")),
    (lambda c: c.replace_atomically(ANCHOR_NAME, "text", max_bytes=64), (StorageErrorCode.INPUT_TYPE_INVALID, "file:data")),
    (lambda c: c.replace_atomically(ANCHOR_NAME, b"", max_bytes=64), (StorageErrorCode.INPUT_TYPE_INVALID, "file:data")),
    (lambda c: c.replace_atomically(ANCHOR_NAME, LINE, max_bytes=4), (StorageErrorCode.FILE_TOO_LARGE, "file:limit")),
    (lambda c: c.replace_atomically(ANCHOR_NAME, LINE, max_bytes=(1 << 20) + 1),
     (StorageErrorCode.INPUT_TYPE_INVALID, "file:max-size")),
    (lambda c: c.link_no_replace("seg-1.jsonl", ".seq_anchor.q0"), (StorageErrorCode.UNSAFE_PATH, "path:member-name")),
    (lambda c: c.link_no_replace(ANCHOR_NAME, ".seq_anchor.q9"), (StorageErrorCode.UNSAFE_PATH, "path:member-name")),
    (lambda c: c.remove_created("token"), (StorageErrorCode.INPUT_TYPE_INVALID, "token:type")),
    (lambda c: c.list_names(max_entries=0), (StorageErrorCode.INPUT_TYPE_INVALID, "directory:max-entries")),
    (lambda c: c.open_read("chain.key", max_size=8), (StorageErrorCode.UNSAFE_PATH, "path:member-name")),
    (lambda c: c.open_read("seg-1.jsonl", max_size=-1), (StorageErrorCode.INPUT_TYPE_INVALID, "file:max-size")),
])
def test_requests_are_validated_before_any_os_call(call, expected, no_os, monkeypatch):
    monkeypatch.setattr(sp, "_posix_write_capable", lambda: True)
    assert pair_of(no_os.wrap(call), _chain("posix")) == expected


def test_closed_token_is_refused_before_any_os_call(no_os, monkeypatch):
    monkeypatch.setattr(sp, "_posix_write_capable", lambda: True)
    token = CreatedToken(_fd=-1, _dfd=-1, _name="seg-1.jsonl", _identity=(1, 2))
    token._closed = True  # closed without touching descriptors
    assert pair_of(no_os.wrap(_chain("posix").remove_created), token) == (StorageErrorCode.FILE_UNSAFE,
                                                                           "token:closed")


# --- Portable: static guarantees ---------------------------------------------------------------------------


WRITE_PRIMITIVES = {"os.write", "os.replace", "os.rename", "os.link", "os.unlink", "os.mkdir", "os.fchmod",
                    "os.remove", "os.rmdir", "os.chmod", "os.truncate", "os.ftruncate"}


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _dotted(node.value)
        return f"{inner}.{node.attr}" if inner else None
    return None


def _scopes_using(tree, predicate):
    found = set()

    def visit(node, scope):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.ClassDef)):
                visit(child, scope + [child.name])
                continue
            if predicate(child):
                found.add(".".join(scope))
            visit(child, scope)

    visit(tree, [])
    return found


def test_write_primitives_live_only_in_posix_code():
    tree = ast.parse(inspect.getsource(sp))
    writers = _scopes_using(tree, lambda n: isinstance(n, ast.Call) and _dotted(n.func) in WRITE_PRIMITIVES)
    creators = _scopes_using(tree, lambda n: isinstance(n, ast.Attribute) and n.attr == "O_CREAT")
    allowed = {
        # C2-B (unchanged): POSIX key-file creation
        "_write_all", "_posix_create", "_posix_remove_if_same",
        # C2-C POSIX primitives, reachable only after _require_posix_write
        "_posix_unlink_if_ours", "_posix_open_child", "_posix_open_member", "_posix_create_member",
        "_posix_write_fully", "_posix_replace", "_posix_link_no_replace",
        # POSIX-only handle (constructed only by ChainDirectory.create_exclusive / open_append)
        "SafeAppendFile.append",
    }
    assert writers <= allowed, writers - allowed
    assert creators <= {"_posix_create", "_posix_create_member", "_posix_replace"}, creators
    assert not any("windows" in scope.lower() for scope in writers | creators)


def test_every_write_method_refuses_first():
    for cls, methods in ((ChainDirectory, C2C_WRITE_METHODS + ("sync",)), (AuditDirectory, ("sync",))):
        for method in methods:
            function = getattr(cls, method)
            body = ast.parse(inspect.getsource(function).strip()).body[0].body
            if isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                body = body[1:]
            assert ast.unparse(body[0]) == "self._require_posix_write()", (cls.__name__, method)


def test_append_handles_are_constructed_only_by_posix_guarded_methods():
    tree = ast.parse(inspect.getsource(sp))
    builders = _scopes_using(tree, lambda n: isinstance(n, ast.Call) and _dotted(n.func) == "SafeAppendFile")
    assert builders == {"ChainDirectory.create_exclusive", "ChainDirectory.open_append"}


# --- Portable: Linux mountinfo parsing ----------------------------------------------------------------------


SAMPLE = (
    b"22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
    b"23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw\n"
    b"40 22 8:1 /srv/data /mnt/bind rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
    b"41 22 0:50 / /mnt/nfs rw master:7 - nfs4 server:/export rw,vers=4.2\n"
    b"42 22 0:51 / /mnt/with\\040space rw - fuse.sshfs user@host: rw\n"
    b"43 22 8:17 / /media/usb rw - vfat /dev/sdb1 rw\n"
    b"44 22 0:60 / /var/lib/docker/overlay rw - overlay overlay rw,lowerdir=/x\n"
)


def test_mountinfo_sample_parses():
    entries = parse_mountinfo(SAMPLE)
    assert len(entries) == 7
    assert entries[0] == MountEntry(8, 1, b"/", b"ext4")
    assert entries[4].mount_point == b"/mnt/with space" and entries[4].fstype == b"fuse.sshfs"


@pytest.mark.parametrize("major, minor, path, expected", [
    (8, 1, b"/home/svc/audit", b"ext4"),
    (8, 1, b"/mnt/bind/audit", b"ext4"),  # bind mount of the same device: longest prefix wins
    (0, 50, b"/mnt/nfs/audit", b"nfs4"),
    (0, 51, b"/mnt/with space/a", b"fuse.sshfs"),
    (8, 17, b"/media/usb", b"vfat"),
    (0, 60, b"/var/lib/docker/overlay/x", b"overlay"),
])
def test_filesystem_type_selection(major, minor, path, expected):
    assert filesystem_type(parse_mountinfo(SAMPLE), major, minor, path) == expected


@pytest.mark.parametrize("major, minor, path, label", [
    (9, 9, b"/home", "mountinfo:device"),  # device not listed (e.g. a btrfs subvolume): fail closed
    (0, 50, b"/srv/elsewhere", "mountinfo:device"),  # device listed but path not under its mount point
    (0, 50, b"/mnt/nfsx", "mountinfo:device"),  # prefix must end at a component boundary
])
def test_filesystem_type_fails_closed(major, minor, path, label):
    assert pair_of(filesystem_type, parse_mountinfo(SAMPLE), major, minor, path) == (
        StorageErrorCode.UNSUPPORTED_FILESYSTEM, label)


def test_filesystem_type_refuses_ambiguous_ties():
    data = b"1 0 0:9 / /a rw - ext4 x rw\n2 0 0:9 / /a rw - nfs y rw\n"
    assert pair_of(filesystem_type, parse_mountinfo(data), 0, 9, b"/a/b") == (
        StorageErrorCode.UNSUPPORTED_FILESYSTEM, "mountinfo:ambiguous")


@pytest.mark.parametrize("data", [
    b"", b"22 1 8:1 / / rw - ext4 /dev/sda1 rw",  # no trailing newline
    b"\n", b"22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\n",  # empty line
    b"22 1 8:1 / / rw ext4 /dev/sda1 rw\n",  # no separator
    b"22 1 8:1 / / - ext4 /dev/sda1 rw\n",  # separator before the optional-field position
    b"22 1 8:1 / / rw - ext4 /dev/sda1\n",  # missing super options
    b"22 1 8:1 / / rw - ext4 /dev/sda1 rw extra\n",
    b"22  1 8:1 / / rw - ext4 /dev/sda1 rw\n",  # double space
    b"x 1 8:1 / / rw - ext4 /dev/sda1 rw\n", b"22 1 8-1 / / rw - ext4 /dev/sda1 rw\n",
    b"22 1 8:1 / relative rw - ext4 /dev/sda1 rw\n",
    b"22 1 8:1 / /a\\04 rw - ext4 /dev/sda1 rw\n", b"22 1 8:1 / /a\\x41 rw - ext4 /dev/sda1 rw\n",
    b"22 1 8:1 / /a\\000 rw - ext4 /dev/sda1 rw\n", b"22 1 8:1 / /a\\ rw - ext4 /dev/sda1 rw\n",
    b"22 1 8:1 / / rw - EXT4 /dev/sda1 rw\n", b"22 1 8:1 / / rw - e*t4 /dev/sda1 rw\n",
    b"22 1 8:1 / /\xc3\xa9 rw - ext4 /dev/sda1 rw\n", b"22 1 8:1 / /\ta rw - ext4 /dev/sda1 rw\n",
    b"22 1 8:1 / /" + b"a" * 9000 + b" rw - ext4 /dev/sda1 rw\n",
    b"22 1 8:1 / / rw - ext4 /dev/sda1 rw\n" * 10_001,
    b"a" * ((1 << 20) + 1) + b"\n", "22 1 8:1 / / rw - ext4 x rw\n", None,
])
def test_malformed_or_hostile_mountinfo_fails_closed(data):
    assert code_of(parse_mountinfo, data) is StorageErrorCode.UNSUPPORTED_FILESYSTEM


def test_mountinfo_fuzz_only_parses_or_fails_closed():
    rng = random.Random(20261117)
    alphabet = b"0123456789: /-\\abcxyz\n\t"
    for _ in range(2000):
        data = bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 120)))
        try:
            parse_mountinfo(data)
        except StorageError as error:
            assert error.code is StorageErrorCode.UNSUPPORTED_FILESYSTEM and error.__context__ is None


PREVIOUSLY_REFUSED = (b"nfs", b"nfs4", b"cifs", b"smb3", b"smbfs", b"fuse", b"fuseblk", b"fuse.sshfs", b"vfat",
                      b"exfat", b"msdos", b"9p", b"ceph", b"glusterfs", b"afs")
SUPPORTED = (b"ext4", b"ext3", b"xfs", b"btrfs", b"zfs", b"f2fs", b"apfs", b"overlay", b"devtmpfs")


@pytest.mark.parametrize("fstype, refused", [(t, True) for t in PREVIOUSLY_REFUSED + (b"tmpfs", b"ramfs")]
                         + [(t, False) for t in SUPPORTED])
def test_refused_filesystem_table(fstype, refused):
    assert sp._is_refused_filesystem(fstype) is refused


def test_h2_refused_set_is_a_strict_superset_of_h1():
    assert set(PREVIOUSLY_REFUSED) - {b"fuse.sshfs"} <= sp._REFUSED_FILESYSTEMS
    assert {b"tmpfs", b"ramfs"} <= sp._REFUSED_FILESYSTEMS
    assert not any(t in sp._REFUSED_FILESYSTEMS for t in SUPPORTED)


MEMORY_MOUNTS = (
    b"22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
    b"60 22 0:70 / /run/audit rw,nosuid shared:30 - tmpfs tmpfs rw,size=1024k,mode=700\n"
    b"61 22 0:71 / /mnt/ram rw - ramfs ramfs rw\n"
    b"62 22 0:72 / /dev rw - devtmpfs udev rw,size=1g\n"
)


@pytest.mark.parametrize("minor, path", [(70, "/run/audit/store"), (71, "/mnt/ram/store")])
def test_mocked_linux_policy_refuses_tmpfs_and_ramfs(monkeypatch, minor, path):
    _mocked_linux(monkeypatch, MEMORY_MOUNTS)
    monkeypatch.setattr(sp.os, "minor", lambda dev: minor, raising=False)
    assert sp._linux_filesystem_problem(FAKE_FD, path) == (StorageErrorCode.UNSUPPORTED_FILESYSTEM,
                                                            "directory:filesystem")


@pytest.mark.parametrize("major, minor, path, fstype", [(0, 70, b"/run/audit/x", b"tmpfs"),
                                                         (0, 71, b"/mnt/ram/x", b"ramfs")])
def test_memory_backed_mounts_parse_as_their_type(major, minor, path, fstype):
    assert filesystem_type(parse_mountinfo(MEMORY_MOUNTS), major, minor, path) == fstype


@pytest.mark.parametrize("fstype", PREVIOUSLY_REFUSED)
def test_mocked_linux_policy_still_refuses_previous_types(monkeypatch, fstype):
    _mocked_linux(monkeypatch, b"22 1 8:1 / / rw - ext4 r rw\n41 22 0:50 / /m rw - " + fstype + b" s rw\n")
    assert sp._linux_filesystem_problem(FAKE_FD, "/m/audit") == (StorageErrorCode.UNSUPPORTED_FILESYSTEM,
                                                                  "directory:filesystem")


@pytest.mark.parametrize("fstype", SUPPORTED)
def test_mocked_linux_policy_accepts_supported_types(monkeypatch, fstype):
    _mocked_linux(monkeypatch, b"22 1 8:1 / / rw - ext4 r rw\n41 22 0:50 / /m rw - " + fstype + b" s rw\n")
    assert sp._linux_filesystem_problem(FAKE_FD, "/m/audit") is None


def test_mountinfo_limits_are_unchanged():
    assert (sp.MAX_MOUNTINFO_BYTES, sp.MAX_MOUNTINFO_LINES, sp.MAX_MOUNTINFO_LINE_BYTES) == (1 << 20, 10_000, 8_192)
    one = b"22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
    assert len(parse_mountinfo(one * 10_000)) == 10_000  # exactly at the line limit: accepted
    assert code_of(parse_mountinfo, one * 10_001) is StorageErrorCode.UNSUPPORTED_FILESYSTEM
    head, tail = b"22 1 8:1 / /", b" rw - ext4 x rw"
    at_limit = head + b"a" * (8_192 - len(head) - len(tail)) + tail + b"\n"
    assert len(at_limit) - 1 == 8_192 and parse_mountinfo(at_limit)
    over = head + b"a" * (8_193 - len(head) - len(tail)) + tail + b"\n"
    assert code_of(parse_mountinfo, over) is StorageErrorCode.UNSUPPORTED_FILESYSTEM
    assert code_of(parse_mountinfo, b"x" * ((1 << 20) + 1)) is StorageErrorCode.UNSUPPORTED_FILESYSTEM


def test_key_directories_never_consult_mountinfo():
    # C2-B key files are unchanged by the mountinfo policy (D-C2C-4b): SafeDirectory never calls it.
    tree = ast.parse(inspect.getsource(SafeDirectory))
    called = {_dotted(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert not called & {"_linux_filesystem_problem", "_read_mountinfo", "parse_mountinfo", "filesystem_type"}
    source = inspect.getsource(sp)
    for name in ("_posix_open_directory", "_posix_read", "_posix_create", "_windows_read", "_windows_open_directory"):
        assert "_linux_filesystem_problem" not in inspect.getsource(getattr(sp, name)), name
    assert source.count("_linux_filesystem_problem(") == 3  # definition + audit root + chain directory


@pytest.mark.parametrize("system", ["Darwin", "FreeBSD", "OpenBSD", "SunOS"])
def test_non_linux_posix_never_reads_mountinfo(monkeypatch, system):
    monkeypatch.setattr(sp.os, "uname", lambda: _Uname(system), raising=False)
    monkeypatch.setattr(sp, "_read_mountinfo", lambda: pytest.fail("mountinfo read on " + system))
    monkeypatch.setattr(sp, "parse_mountinfo", lambda data: pytest.fail("mountinfo parsed on " + system))
    assert sp._linux_filesystem_problem(FAKE_FD, "/srv/audit") is None


class _Uname:
    def __init__(self, name):
        self.sysname = name


class _Dev:
    st_dev = 1234


FAKE_FD = 987654  # a descriptor number that is never open; only it gets the fake stat


def _mocked_linux(monkeypatch, data):
    real_fstat = os.fstat
    monkeypatch.setattr(sp.os, "uname", lambda: _Uname("Linux"), raising=False)
    monkeypatch.setattr(sp.os, "fstat", lambda fd: _Dev() if fd == FAKE_FD else real_fstat(fd))
    monkeypatch.setattr(sp.os, "major", lambda dev: 0, raising=False)
    monkeypatch.setattr(sp.os, "minor", lambda dev: 50, raising=False)
    monkeypatch.setattr(sp, "_read_mountinfo", data if callable(data) else lambda: data)


def test_mocked_linux_policy_refuses_network_storage(monkeypatch):
    _mocked_linux(monkeypatch, SAMPLE)
    assert sp._linux_filesystem_problem(FAKE_FD, "/mnt/nfs/audit") == (StorageErrorCode.UNSUPPORTED_FILESYSTEM,
                                                                  "directory:filesystem")


def test_mocked_linux_policy_fails_closed_when_unreadable_or_malformed(monkeypatch):
    def unreadable():
        raise PermissionError(errno.EACCES, "denied")

    _mocked_linux(monkeypatch, unreadable)
    assert sp._linux_filesystem_problem(FAKE_FD, "/mnt/nfs/audit") == (StorageErrorCode.UNSUPPORTED_FILESYSTEM,
                                                                  "mountinfo:unreadable")
    _mocked_linux(monkeypatch, b"garbage\n")
    assert sp._linux_filesystem_problem(FAKE_FD, "/mnt/nfs/audit") == (StorageErrorCode.UNSUPPORTED_FILESYSTEM,
                                                                  "mountinfo:line")


def test_mocked_non_linux_posix_has_no_mountinfo_policy(monkeypatch):
    monkeypatch.setattr(sp.os, "uname", lambda: _Uname("Darwin"), raising=False)
    monkeypatch.setattr(sp, "_read_mountinfo", lambda: pytest.fail("mountinfo read on macOS"))
    assert sp._linux_filesystem_problem(FAKE_FD, "/Users/svc/audit") is None


# --- Portable: privacy and object hygiene ------------------------------------------------------------------


def _objects():
    token = CreatedToken(_fd=-1, _dfd=-1, _name="seg-1.jsonl", _identity=(7, 8))
    token._closed = True
    st = os.stat_result((0o100600, 5, 6, 1, 0, 0, 0, 0, 0, 0))
    append = SafeAppendFile(_fd=-1, _dfd=-1, _name="seg-1.jsonl", _st=st, _max=8, _created=True)
    append._closed = True
    reader = SafeReadFile(_kind="posix", _fd=-1, _st=st, _max=8, _name="seg-1.jsonl", _dfd=-1)
    reader._closed = True
    return [_audit("posix", fd=None), _chain("nt"), token, append, reader]


def test_objects_refuse_pickle_and_copy_and_hide_everything_in_repr():
    for obj in _objects():
        with pytest.raises(TypeError):
            pickle.dumps(obj)
        with pytest.raises(TypeError):
            copy.copy(obj)
        with pytest.raises(TypeError):
            copy.deepcopy(obj)
        text = repr(obj) + str(obj)
        for secret in ("/a", "audit", "C:", "seg-1", "jsonl", "chain-", "7", "8"):
            assert secret not in text.replace("audit_root", "")


def test_closed_handles_refuse_use_without_os_calls(no_os):
    _, _, token, append, reader = _objects()
    wrap = no_os.wrap
    assert pair_of(wrap(append.append), LINE) == (StorageErrorCode.STORAGE_UNAVAILABLE, "file:closed")
    assert pair_of(wrap(append.sync)) == (StorageErrorCode.STORAGE_UNAVAILABLE, "file:closed")
    assert pair_of(wrap(append.verify_name)) == (StorageErrorCode.STORAGE_UNAVAILABLE, "file:closed")
    assert pair_of(wrap(append.created_token)) == (StorageErrorCode.INPUT_TYPE_INVALID, "token:not-created")
    assert pair_of(wrap(reader.read), 4) == (StorageErrorCode.STORAGE_UNAVAILABLE, "file:closed")
    assert pair_of(wrap(reader.verify_unchanged)) == (StorageErrorCode.STORAGE_UNAVAILABLE, "file:closed")
    wrap(token.close)()  # idempotent, no descriptor touched


def test_error_messages_carry_codes_and_fixed_labels_only():
    for fn, args in ((check_chain_directory_name, ("/home/alice/secret",)),
                     (parse_mountinfo, (b"22 1 8:1 / /home/alice rw\n",))):
        error = error_of(fn, *args)
        assert "alice" not in str(error) and "home" not in str(error)


def test_durability_levels():
    assert sp._weakest(Durability.FULLFSYNC, Durability.FULLFSYNC) is Durability.FULLFSYNC
    assert sp._weakest(Durability.FULLFSYNC, Durability.FSYNC) is Durability.FSYNC
    assert ListResult(("a",), 1).other_entries == 1


# --- POSIX native ---------------------------------------------------------------------------------------------


@pytest.fixture
def audit_root():
    import shutil
    import tempfile

    home = os.path.realpath(os.path.expanduser("~"))
    base = tempfile.mkdtemp(prefix="rig-c2c-", dir=home)
    os.chmod(base, 0o700)
    yield base
    shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def chain(audit_root):
    with AuditDirectory.open(audit_root) as audit:
        directory = audit.open_chain(CHAIN, create=True)
    yield directory, os.path.join(audit_root, CHAIN)
    directory.close()


def _mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


@posix_only
def test_posix_chain_directory_is_created_private_under_restrictive_umask(audit_root):
    old = os.umask(0o277)
    try:
        with AuditDirectory.open(audit_root) as audit:
            audit.open_chain(CHAIN, create=True).close()
            assert _mode(os.path.join(audit_root, CHAIN)) == 0o700
            audit.open_chain(CHAIN, create=True).close()  # existing: opened with the same checks
            assert audit.list_names() == ListResult((CHAIN,), 0)
            assert audit.sync() in (Durability.FSYNC, Durability.FULLFSYNC)
    finally:
        os.umask(old)


@posix_only
def test_posix_existing_unsafe_chain_directory_is_refused_and_never_chmodded(audit_root):
    path = os.path.join(audit_root, CHAIN)
    os.mkdir(path, 0o700)
    os.chmod(path, 0o750)
    with AuditDirectory.open(audit_root) as audit:
        for create in (False, True):
            assert pair_of(audit.open_chain, CHAIN, create=create) == (StorageErrorCode.UNSAFE_PERMISSIONS,
                                                                        "directory:child")
    assert _mode(path) == 0o750


@posix_only
def test_posix_symlinked_audit_root_and_chain_directory_are_refused(audit_root):
    real = os.path.join(audit_root, "real")
    os.mkdir(real, 0o700)
    link = os.path.join(audit_root, "link")
    os.symlink(real, link)
    assert pair_of(AuditDirectory.open, link) == (StorageErrorCode.UNSAFE_PATH, "path:not-canonical")
    os.mkdir(os.path.join(real, "target"), 0o700)
    os.symlink(os.path.join(real, "target"), os.path.join(audit_root, CHAIN))
    with AuditDirectory.open(audit_root) as audit:
        for create in (False, True):
            assert pair_of(audit.open_chain, CHAIN, create=create) == (StorageErrorCode.UNSAFE_PATH, "directory:child")


@posix_only
def test_posix_held_chain_directory_survives_replacement(chain, audit_root):
    directory, path = chain
    os.rename(path, path + "-moved")
    os.mkdir(path, 0o700)  # attacker-style replacement at the old name
    with directory.create_exclusive("seg-0.jsonl", max_size=1024) as segment:
        segment.append(LINE)
    assert os.listdir(path) == [] and os.listdir(path + "-moved") == ["seg-0.jsonl"]


@posix_only
def test_posix_segment_create_append_sync_and_read(chain):
    directory, path = chain
    old = os.umask(0o277)
    try:
        segment = directory.create_exclusive("seg-0.jsonl", max_size=1024)
    finally:
        os.umask(old)
    with segment:
        segment.append(LINE)
        segment.append(LINE)
        assert segment.size == 2 * len(LINE)
        assert segment.sync() in (Durability.FSYNC, Durability.FULLFSYNC)
        segment.verify_name()
    assert _mode(os.path.join(path, "seg-0.jsonl")) == 0o600
    assert directory.sync() in (Durability.FSYNC, Durability.FULLFSYNC)
    with directory.open_append("seg-0.jsonl", max_size=1024) as reopened:
        assert reopened.size == 2 * len(LINE)
        reopened.append(LINE)
    with directory.open_read("seg-0.jsonl", max_size=1024) as reader:
        data = b""
        while True:
            chunk = reader.read(7)
            if not chunk:
                break
            data += chunk
        reader.verify_unchanged()
    assert data == LINE * 3
    assert pair_of(directory.create_exclusive, "seg-0.jsonl", max_size=1024) == (StorageErrorCode.FILE_EXISTS,
                                                                                  "file:create")


@posix_only
def test_posix_symlink_fifo_and_directory_members_are_refused(chain):
    directory, path = chain
    os.symlink("/etc/passwd", os.path.join(path, "seg-1.jsonl"))
    os.mkfifo(os.path.join(path, "seg-2.jsonl"), 0o600)
    os.mkdir(os.path.join(path, "seg-3.jsonl"), 0o700)
    assert code_of(directory.open_append, "seg-1.jsonl", max_size=64) is StorageErrorCode.UNSAFE_PATH
    assert code_of(directory.open_read, "seg-1.jsonl", max_size=64) is StorageErrorCode.UNSAFE_PATH
    assert code_of(directory.create_exclusive, "seg-1.jsonl", max_size=64) is StorageErrorCode.FILE_EXISTS
    assert code_of(directory.open_append, "seg-2.jsonl", max_size=64) is StorageErrorCode.FILE_UNSAFE  # never blocks
    assert pair_of(directory.open_read, "seg-2.jsonl", max_size=64) == (StorageErrorCode.FILE_UNSAFE, "file:type")
    assert code_of(directory.open_append, "seg-3.jsonl", max_size=64) is StorageErrorCode.FILE_UNSAFE
    assert pair_of(directory.open_read, "seg-3.jsonl", max_size=64) == (StorageErrorCode.FILE_UNSAFE, "file:type")


@posix_only
def test_posix_unsafe_member_permissions_and_missing_files(chain):
    directory, path = chain
    member = os.path.join(path, "seg-4.jsonl")
    with open(member, "wb") as handle:
        handle.write(LINE)
    os.chmod(member, 0o640)
    assert pair_of(directory.open_read, "seg-4.jsonl", max_size=64) == (StorageErrorCode.FILE_UNSAFE,
                                                                         "file:permissions")
    assert _mode(member) == 0o640  # never chmod-ed
    assert pair_of(directory.open_read, "seg-5.jsonl", max_size=64) == (StorageErrorCode.FILE_MISSING, "file:open")
    os.chmod(member, 0o600)
    assert pair_of(directory.open_read, "seg-4.jsonl", max_size=4) == (StorageErrorCode.FILE_TOO_LARGE, "file:limit")


@posix_only
def test_posix_hard_link_after_open_seals_the_segment(chain):
    directory, path = chain
    with directory.create_exclusive("seg-0.jsonl", max_size=1024) as segment:
        segment.append(LINE)
        os.link(os.path.join(path, "seg-0.jsonl"), os.path.join(path, "copy"))
        assert pair_of(segment.append, LINE) == (StorageErrorCode.FILE_UNSAFE, "file:links")
        assert segment.sealed
        assert pair_of(segment.append, LINE) == (StorageErrorCode.FILE_UNSAFE, "file:sealed")
    assert pair_of(directory.open_append, "seg-0.jsonl", max_size=1024) == (StorageErrorCode.FILE_UNSAFE, "file:links")


@posix_only
def test_posix_foreign_append_and_truncation_are_detected(chain):
    directory, path = chain
    member = os.path.join(path, "seg-0.jsonl")
    with directory.create_exclusive("seg-0.jsonl", max_size=1024) as segment:
        segment.append(LINE)
        with open(member, "ab") as foreign:
            foreign.write(b"x")
        assert pair_of(segment.append, LINE) == (StorageErrorCode.FILE_UNSAFE, "file:changed")
    with directory.open_append("seg-0.jsonl", max_size=1024) as segment:
        os.truncate(member, 3)
        assert pair_of(segment.append, LINE) == (StorageErrorCode.FILE_UNSAFE, "file:changed")


@posix_only
def test_posix_renamed_or_replaced_segment_is_detected(chain):
    directory, path = chain
    member = os.path.join(path, "seg-0.jsonl")
    with directory.create_exclusive("seg-0.jsonl", max_size=1024) as segment:
        os.rename(member, member + ".old")
        assert pair_of(segment.verify_name) == (StorageErrorCode.FILE_UNSAFE, "file:replaced")
        with open(member, "wb"):
            pass
        assert pair_of(segment.verify_name) == (StorageErrorCode.FILE_UNSAFE, "file:replaced")


@posix_only
def test_posix_short_write_seals_the_handle(chain, monkeypatch):
    directory, path = chain
    with directory.create_exclusive("seg-0.jsonl", max_size=1024) as segment:
        real_write = os.write
        monkeypatch.setattr(sp.os, "write", lambda fd, data: real_write(fd, bytes(data[:3])))
        assert pair_of(segment.append, LINE) == (StorageErrorCode.PARTIAL_WRITE, "file:partial")
        monkeypatch.setattr(sp.os, "write", real_write)
        assert segment.sealed and segment.size == 3
        assert pair_of(segment.append, LINE) == (StorageErrorCode.FILE_UNSAFE, "file:sealed")


@posix_only
def test_posix_sync_failure_seals_and_reports_durability_failed(chain, monkeypatch):
    directory, path = chain
    with directory.create_exclusive("seg-0.jsonl", max_size=1024) as segment:
        segment.append(LINE)

        def failing(fd):
            raise OSError(errno.EIO, "synthetic")

        monkeypatch.setattr(sp.os, "fsync", failing)
        assert pair_of(segment.sync) == (StorageErrorCode.DURABILITY_FAILED, "file:sync")
        assert segment.sealed
        assert pair_of(directory.sync) == (StorageErrorCode.DURABILITY_UNCERTAIN, "directory:sync")


@posix_only
def test_posix_append_limit_does_not_seal(chain):
    directory, path = chain
    with directory.create_exclusive("seg-0.jsonl", max_size=len(LINE) + 1) as segment:
        segment.append(LINE)
        assert pair_of(segment.append, LINE) == (StorageErrorCode.FILE_TOO_LARGE, "file:limit")
        assert not segment.sealed
        segment.append(b"\n")
        assert pair_of(segment.append, b"") == (StorageErrorCode.INPUT_TYPE_INVALID, "file:data")


@posix_only
def test_posix_read_detects_growth_and_change(chain):
    directory, path = chain
    member = os.path.join(path, "seg-0.jsonl")
    with directory.create_exclusive("seg-0.jsonl", max_size=1024) as segment:
        segment.append(LINE)
    with directory.open_read("seg-0.jsonl", max_size=len(LINE)) as reader:
        with open(member, "ab") as foreign:
            foreign.write(b"more")
        assert pair_of(reader.verify_unchanged) == (StorageErrorCode.FILE_UNSAFE, "file:changed")
        assert reader.read(len(LINE)) == LINE
        assert pair_of(reader.read, 64) == (StorageErrorCode.FILE_TOO_LARGE, "file:limit")


def _swap_after(monkeypatch, attribute, target, path, *, make_dir=False, calls=1):
    """Wrap ``sp.os.<attribute>`` (or ``sp.<attribute>``): after the n-th real call, a same-credential
    attacker moves ``target`` away and puts a fresh object with the same name in its place (race injection)."""
    owner = sp if attribute.startswith("_") else sp.os
    real = getattr(owner, attribute)
    seen = []

    def wrapper(*args, **kwargs):
        result = real(*args, **kwargs)
        seen.append(1)
        if len(seen) == calls:
            full = os.path.join(path, target)
            os.rename(full, full + ".moved")
            if make_dir:
                os.mkdir(full, 0o700)
            else:
                with open(full, "wb") as handle:
                    handle.write(b"attacker")
                os.chmod(full, 0o600)
        return result

    monkeypatch.setattr(owner, attribute, wrapper)


@posix_only
def test_posix_chain_directory_swapped_right_after_open_is_detected(audit_root, monkeypatch):
    with AuditDirectory.open(audit_root) as audit:
        audit.open_chain(CHAIN, create=True).close()
        real_open = os.open
        seen = []

        def wrapper(name, flags, *args, **kwargs):
            fd = real_open(name, flags, *args, **kwargs)
            if name == CHAIN and not seen:
                seen.append(1)
                os.rename(os.path.join(audit_root, CHAIN), os.path.join(audit_root, CHAIN + "-moved"))
                os.mkdir(os.path.join(audit_root, CHAIN), 0o700)
            return fd

        monkeypatch.setattr(sp.os, "open", wrapper)
        assert pair_of(audit.open_chain, CHAIN) == (StorageErrorCode.UNSAFE_PATH, "directory:changed")


@posix_only
def test_posix_member_swapped_right_after_open_is_detected(chain, monkeypatch):
    directory, path = chain
    with directory.create_exclusive("seg-0.jsonl", max_size=64):
        pass
    real_open = os.open
    seen = []

    def wrapper(name, flags, *args, **kwargs):
        fd = real_open(name, flags, *args, **kwargs)
        if name == "seg-0.jsonl" and not seen:
            seen.append(1)
            member = os.path.join(path, "seg-0.jsonl")
            os.rename(member, member + ".moved")
            with open(member, "wb"):
                pass
        return fd

    monkeypatch.setattr(sp.os, "open", wrapper)
    assert pair_of(directory.open_read, "seg-0.jsonl", max_size=64) == (StorageErrorCode.FILE_UNSAFE, "file:changed")


@posix_only
def test_posix_temp_swapped_before_replace_is_detected_and_not_deleted(chain, monkeypatch):
    directory, path = chain
    directory.replace_atomically(ANCHOR_NAME, b"old\n", max_bytes=64)
    _swap_after(monkeypatch, "_sync_level", ANCHOR_TEMP_NAME, path)  # after the temp's own sync
    assert pair_of(directory.replace_atomically, ANCHOR_NAME, b"new\n", max_bytes=64) == (StorageErrorCode.FILE_UNSAFE,
                                                                                           "file:changed")
    with open(os.path.join(path, ANCHOR_NAME), "rb") as handle:
        assert handle.read() == b"old\n"
    assert os.path.exists(os.path.join(path, ANCHOR_TEMP_NAME))  # the substitute is never deleted


@posix_only
def test_posix_anchor_swapped_right_after_replace_is_detected(chain, monkeypatch):
    directory, path = chain
    _swap_after(monkeypatch, "replace", ANCHOR_NAME, path)
    assert pair_of(directory.replace_atomically, ANCHOR_NAME, b"new\n", max_bytes=64) == (StorageErrorCode.FILE_UNSAFE,
                                                                                           "file:replaced")


@posix_only
def test_posix_filesystem_refusal_is_enforced_when_opening(audit_root, monkeypatch):
    refused = (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "directory:filesystem")
    monkeypatch.setattr(sp, "_linux_filesystem_problem", lambda fd, path: refused)
    assert pair_of(AuditDirectory.open, audit_root) == refused
    monkeypatch.setattr(sp, "_linux_filesystem_problem", lambda fd, path: refused if path.endswith(CHAIN) else None)
    with AuditDirectory.open(audit_root) as audit:
        assert pair_of(audit.open_chain, CHAIN, create=True) == refused


@posix_only
def test_posix_key_directories_ignore_the_audit_filesystem_policy(audit_root, monkeypatch):
    # D-C2C-4b: even if the audit policy would refuse this filesystem, C2-B key directories open as before.
    monkeypatch.setattr(sp, "_linux_filesystem_problem",
                        lambda fd, path: (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "directory:filesystem"))
    with SafeDirectory.open(audit_root, role="keys") as directory:
        assert repr(directory) == "SafeDirectory(role='keys', closed=False)"
    assert code_of(AuditDirectory.open, audit_root) is StorageErrorCode.UNSUPPORTED_FILESYSTEM


@posix_only
def test_posix_anchor_replacement(chain):
    directory, path = chain
    anchor = os.path.join(path, ANCHOR_NAME)
    old = os.umask(0o277)
    try:
        assert directory.replace_atomically(ANCHOR_NAME, b'{"anchor":1}\n', max_bytes=1024) in (
            Durability.FSYNC, Durability.FULLFSYNC)
    finally:
        os.umask(old)
    directory.replace_atomically(ANCHOR_NAME, b'{"anchor":2}\n', max_bytes=1024)
    with open(anchor, "rb") as handle:
        assert handle.read() == b'{"anchor":2}\n'  # inode numbers may be reused, so content is the evidence
    assert _mode(anchor) == 0o600 and os.stat(anchor).st_nlink == 1
    assert not os.path.lexists(os.path.join(path, ANCHOR_TEMP_NAME))


@posix_only
@pytest.mark.parametrize("planted", ["file", "symlink", "directory", "fifo"])
def test_posix_planted_temp_is_never_reused_or_deleted(chain, planted):
    directory, path = chain
    temp = os.path.join(path, ANCHOR_TEMP_NAME)
    if planted == "file":
        with open(temp, "wb") as handle:
            handle.write(b"orphan")
    elif planted == "symlink":
        os.symlink("/etc/passwd", temp)
    elif planted == "directory":
        os.mkdir(temp, 0o700)
    else:
        os.mkfifo(temp, 0o600)
    assert pair_of(directory.replace_atomically, ANCHOR_NAME, LINE, max_bytes=1024) == (
        StorageErrorCode.FILE_EXISTS, "file:temp-exists")
    assert os.path.lexists(temp) and not os.path.lexists(os.path.join(path, ANCHOR_NAME))


@posix_only
@pytest.mark.parametrize("target", ["directory", "symlink", "hardlink"])
def test_posix_unsafe_anchor_target_is_never_replaced(chain, target):
    directory, path = chain
    anchor = os.path.join(path, ANCHOR_NAME)
    if target == "directory":
        os.mkdir(anchor, 0o700)
    elif target == "symlink":
        os.symlink("/etc/passwd", anchor)
    else:
        directory.replace_atomically(ANCHOR_NAME, LINE, max_bytes=1024)
        os.link(anchor, os.path.join(path, "extra"))
    assert pair_of(directory.replace_atomically, ANCHOR_NAME, b"new\n", max_bytes=1024) == (
        StorageErrorCode.FILE_UNSAFE, "file:target")
    assert not os.path.lexists(os.path.join(path, ANCHOR_TEMP_NAME))  # our temp was removed
    assert os.path.lexists(anchor)


@posix_only
def test_posix_directory_sync_failure_after_replace_is_uncertain_not_rolled_back(chain, monkeypatch):
    directory, path = chain
    directory.replace_atomically(ANCHOR_NAME, b"old\n", max_bytes=1024)
    real_sync = sp._sync_level
    calls = []

    def second_fails(fd):
        calls.append(fd)
        if len(calls) == 2:
            raise OSError(errno.EIO, "synthetic")
        return real_sync(fd)

    monkeypatch.setattr(sp, "_sync_level", second_fails)
    assert pair_of(directory.replace_atomically, ANCHOR_NAME, b"new\n", max_bytes=1024) == (
        StorageErrorCode.DURABILITY_UNCERTAIN, "directory:sync-after-replace")
    with open(os.path.join(path, ANCHOR_NAME), "rb") as handle:
        assert handle.read() == b"new\n"  # the replacement is visible: never reported as durable or undone


@posix_only
def test_posix_temp_sync_or_replace_failure_leaves_anchor_unchanged(chain, monkeypatch):
    directory, path = chain
    directory.replace_atomically(ANCHOR_NAME, b"old\n", max_bytes=1024)

    def failing_sync(fd):
        raise OSError(errno.EIO, "synthetic")

    monkeypatch.setattr(sp, "_sync_level", failing_sync)
    assert pair_of(directory.replace_atomically, ANCHOR_NAME, b"new\n", max_bytes=1024) == (
        StorageErrorCode.DURABILITY_FAILED, "file:sync")
    monkeypatch.undo()

    def failing_replace(*args, **kwargs):
        raise OSError(errno.EIO, "synthetic")

    monkeypatch.setattr(sp.os, "replace", failing_replace)
    assert pair_of(directory.replace_atomically, ANCHOR_NAME, b"new\n", max_bytes=1024) == (
        StorageErrorCode.STORAGE_UNAVAILABLE, "file:replace")
    with open(os.path.join(path, ANCHOR_NAME), "rb") as handle:
        assert handle.read() == b"old\n"
    assert not os.path.lexists(os.path.join(path, ANCHOR_TEMP_NAME))


@posix_only
def test_posix_quarantine_never_clobbers(chain):
    directory, path = chain
    directory.replace_atomically(ANCHOR_NAME, b"one\n", max_bytes=1024)
    assert directory.link_no_replace(ANCHOR_NAME, ".seq_anchor.q0") in (Durability.FSYNC, Durability.FULLFSYNC)
    assert not os.path.lexists(os.path.join(path, ANCHOR_NAME))
    assert os.stat(os.path.join(path, ".seq_anchor.q0")).st_nlink == 1
    directory.replace_atomically(ANCHOR_NAME, b"two\n", max_bytes=1024)
    assert pair_of(directory.link_no_replace, ANCHOR_NAME, ".seq_anchor.q0") == (StorageErrorCode.FILE_EXISTS,
                                                                                  "file:quarantine")
    with open(os.path.join(path, ".seq_anchor.q0"), "rb") as handle:
        assert handle.read() == b"one\n"  # the existing quarantine copy is untouched
    with open(os.path.join(path, ANCHOR_NAME), "rb") as handle:
        assert handle.read() == b"two\n"


def _patch_dir_fd_unlink(monkeypatch, behaviour):
    """Fault-inject ``os.unlink`` as a descriptor-relative (``dir_fd``) operation, for one test only.

    Every write first runs the real capability probe ``_posix_write_capable``, which requires
    ``os.unlink in os.supports_dir_fd``. A plain Python replacement is not in that set, so the probe
    correctly refuses with ``file:write-platform`` before the fault is reached (C2-C-H3). The probe is
    left untouched: the double is added to a *copy* of the set, and monkeypatch restores both the
    function and the original set at teardown or ``monkeypatch.undo()``. Returns the recorded calls.
    """
    calls = []

    def unlink(name, *, dir_fd):  # keyword-only dir_fd: only descriptor-relative unlinks are simulated
        calls.append((name, dir_fd))
        return behaviour(name, dir_fd=dir_fd)

    monkeypatch.setattr(sp.os, "supports_dir_fd", set(sp.os.supports_dir_fd) | {unlink})
    monkeypatch.setattr(sp.os, "unlink", unlink)
    assert sp._posix_write_capable()  # the real probe accepts the double; nothing else is relaxed
    return calls


@posix_only
def test_posix_quarantine_crash_between_link_and_unlink_fails_closed(chain, monkeypatch):
    directory, path = chain
    directory.replace_atomically(ANCHOR_NAME, b"one\n", max_bytes=1024)
    original_supported = os.supports_dir_fd

    def crash(name, *, dir_fd):
        raise OSError(errno.EIO, "synthetic crash after link")

    calls = _patch_dir_fd_unlink(monkeypatch, crash)
    assert pair_of(directory.link_no_replace, ANCHOR_NAME, ".seq_anchor.q1") == (
        StorageErrorCode.STORAGE_UNAVAILABLE, "file:quarantine")
    assert [name for name, _ in calls] == [ANCHOR_NAME]  # the injected crash really ran, after the link
    assert all(isinstance(dir_fd, int) and dir_fd >= 0 for _, dir_fd in calls)
    monkeypatch.undo()
    assert os.supports_dir_fd is original_supported and os.unlink in os.supports_dir_fd  # fully restored
    assert os.stat(os.path.join(path, ANCHOR_NAME)).st_nlink == 2  # state S1, left for the operator
    for name in (ANCHOR_NAME, ".seq_anchor.q1"):
        assert pair_of(directory.open_read, name, max_size=64) == (StorageErrorCode.FILE_UNSAFE, "file:links")
    assert pair_of(directory.link_no_replace, ANCHOR_NAME, ".seq_anchor.q2") == (StorageErrorCode.FILE_UNSAFE,
                                                                                  "file:links")
    assert pair_of(directory.replace_atomically, ANCHOR_NAME, b"x\n", max_bytes=64) == (StorageErrorCode.FILE_UNSAFE,
                                                                                         "file:target")
    assert os.path.exists(os.path.join(path, ANCHOR_NAME)) and os.path.exists(os.path.join(path, ".seq_anchor.q1"))


@posix_only
def test_posix_remove_created_removes_only_its_own_file(chain):
    directory, path = chain
    with directory.create_exclusive("seg-0.jsonl", max_size=64) as segment:
        token = segment.created_token()
    assert directory.remove_created(token) is True
    assert not os.path.lexists(os.path.join(path, "seg-0.jsonl"))
    assert pair_of(directory.remove_created, token) == (StorageErrorCode.FILE_UNSAFE, "token:closed")  # single use


@posix_only
@pytest.mark.parametrize("substitute", ["file", "symlink"])
def test_posix_remove_created_never_deletes_a_substituted_file(chain, substitute):
    directory, path = chain
    member = os.path.join(path, "seg-0.jsonl")
    with directory.create_exclusive("seg-0.jsonl", max_size=64) as segment:
        token = segment.created_token()
    os.rename(member, member + ".ours")
    if substitute == "file":
        with open(member, "wb") as handle:
            handle.write(b"foreign")
    else:
        os.symlink(member + ".ours", member)
    assert pair_of(directory.remove_created, token) == (StorageErrorCode.FILE_UNSAFE, "file:substituted")
    assert os.path.lexists(member) and os.path.lexists(member + ".ours")


@posix_only
def test_posix_remove_created_refuses_links_moves_and_other_directories(chain, audit_root):
    directory, path = chain
    member = os.path.join(path, "seg-0.jsonl")
    with directory.create_exclusive("seg-0.jsonl", max_size=64) as segment:
        token = segment.created_token()
    os.link(member, member + ".x")
    assert pair_of(directory.remove_created, token) == (StorageErrorCode.FILE_UNSAFE, "file:links")
    with directory.create_exclusive("seg-1.jsonl", max_size=64) as segment:
        moved = segment.created_token()
    os.rename(os.path.join(path, "seg-1.jsonl"), os.path.join(path, "elsewhere"))
    assert pair_of(directory.remove_created, moved) == (StorageErrorCode.FILE_UNSAFE, "file:moved")
    with directory.create_exclusive("seg-2.jsonl", max_size=64) as segment:
        foreign = segment.created_token()
    with AuditDirectory.open(audit_root) as audit, audit.open_chain(OTHER_CHAIN, create=True) as other:
        assert pair_of(other.remove_created, foreign) == (StorageErrorCode.INPUT_TYPE_INVALID, "token:directory")
    assert os.path.exists(os.path.join(path, "seg-2.jsonl"))


@posix_only
def test_posix_remove_created_reports_already_gone(chain):
    directory, path = chain
    with directory.create_exclusive("seg-0.jsonl", max_size=64) as segment:
        token = segment.created_token()
    os.unlink(os.path.join(path, "seg-0.jsonl"))
    assert directory.remove_created(token) is False


@posix_only
def test_posix_cleanup_race_is_detected_not_prevented(chain, monkeypatch):
    directory, path = chain
    member = os.path.join(path, "seg-0.jsonl")
    with directory.create_exclusive("seg-0.jsonl", max_size=64) as segment:
        token = segment.created_token()
    real_unlink = os.unlink

    def swap_then_unlink(name, *, dir_fd):  # a same-credential attacker wins the stat -> unlink window
        os.rename(member, member + ".ours")
        with open(member, "wb") as handle:
            handle.write(b"foreign")
        return real_unlink(name, dir_fd=dir_fd)  # the real descriptor-relative unlink

    calls = _patch_dir_fd_unlink(monkeypatch, swap_then_unlink)
    assert pair_of(directory.remove_created, token) == (StorageErrorCode.FILE_UNSAFE, "file:cleanup-race")
    assert [name for name, _ in calls] == ["seg-0.jsonl"]  # the swap really ran inside the unlink window
    assert os.path.exists(member + ".ours")  # our object survived; the residual is reported, never hidden
    assert not os.path.lexists(member)  # the substituted (foreign) file was deleted: detected, not prevented


@posix_only
def test_posix_failed_creation_cleans_up_only_its_own_file(chain, monkeypatch):
    directory, path = chain

    def failing_fchmod(fd, mode):
        raise OSError(errno.EIO, "synthetic")

    monkeypatch.setattr(sp.os, "fchmod", failing_fchmod)
    assert code_of(directory.create_exclusive, "seg-0.jsonl", max_size=64) is StorageErrorCode.STORAGE_UNAVAILABLE
    assert not os.path.lexists(os.path.join(path, "seg-0.jsonl"))


@posix_only
def test_posix_listing_is_bounded_and_never_names_unknown_entries(chain):
    directory, path = chain
    for name in ("seg-1.jsonl", "seg-0.jsonl", ANCHOR_NAME, ".writer.lock", "secret-user-file", "chain.key"):
        with open(os.path.join(path, name), "wb"):
            pass
    os.symlink("/etc", os.path.join(path, "seg-9.jsonl"))
    result = directory.list_names()
    assert result.names == (".seq_anchor", ".writer.lock", "seg-0.jsonl", "seg-1.jsonl", "seg-9.jsonl")
    assert result.other_entries == 2
    assert pair_of(directory.list_names, max_entries=3) == (StorageErrorCode.ENTRY_LIMIT_EXCEEDED, "directory:entries")
    assert code_of(directory.open_read, "seg-9.jsonl", max_size=64) is StorageErrorCode.UNSAFE_PATH


# --- Linux native --------------------------------------------------------------------------------------------


@linux_only
def test_linux_real_mountinfo_parses_and_the_audit_root_is_accepted(audit_root):
    entries = parse_mountinfo(sp._read_mountinfo())
    assert entries and any(e.mount_point == b"/" for e in entries)
    st = os.stat(audit_root)
    fstype = filesystem_type(entries, os.major(st.st_dev), os.minor(st.st_dev), os.fsencode(audit_root))
    assert not sp._is_refused_filesystem(fstype)
    AuditDirectory.open(audit_root).close()


@linux_only
def test_linux_descriptors_are_never_leaked(chain, monkeypatch):
    directory, path = chain

    def count():
        return len(os.listdir("/proc/self/fd"))

    # C2-C-H4: real members whose open() succeeds and whose post-open validation then fails, so the
    # rejection path in _posix_open_member must close the descriptor it already holds.
    with directory.create_exclusive("seg-1.jsonl", max_size=64) as segment:
        segment.append(LINE)  # safe (0o600, one link, ours) but larger than the bound used below
    with directory.create_exclusive("seg-2.jsonl", max_size=64):
        pass
    os.chmod(os.path.join(path, "seg-2.jsonl"), 0o640)  # group bits: rejected only after fstat
    assert len(LINE) > 1

    before = count()
    for _ in range(3):
        with directory.create_exclusive("seg-0.jsonl", max_size=64) as segment:
            token = segment.created_token()
            segment.append(LINE)
        directory.remove_created(token)
        code_of(directory.open_read, "seg-0.jsonl", max_size=64)
        directory.replace_atomically(ANCHOR_NAME, LINE, max_bytes=64)
        with directory.open_read(ANCHOR_NAME, max_size=64) as reader:
            reader.read(64)
        code_of(directory.create_exclusive, "seg-01.jsonl", max_size=64)
        directory.list_names()
        assert pair_of(directory.open_read, "seg-1.jsonl", max_size=1) == (StorageErrorCode.FILE_TOO_LARGE,
                                                                           "file:limit")
        assert pair_of(directory.open_append, "seg-1.jsonl", max_size=1) == (StorageErrorCode.FILE_TOO_LARGE,
                                                                             "file:limit")
        assert pair_of(directory.open_read, "seg-2.jsonl", max_size=64) == (StorageErrorCode.FILE_UNSAFE,
                                                                            "file:permissions")
        assert count() == before  # stable after every round of rejected opens, not only at the end
    assert count() == before


# --- Windows native ---------------------------------------------------------------------------------------------


@windows_only
def test_windows_fat32_audit_root_is_refused_before_writing(tmp_path):
    from pathlib import Path

    path = os.path.realpath(str(tmp_path))
    if os.path.realpath(path) != path:
        pytest.skip("temp path is not canonical on this host")
    root = Path(path).anchor
    try:
        os.stat(root + "::$INDEX_ALLOCATION")
        pytest.skip("temp directory is on a stream-capable filesystem; this test needs FAT32/exFAT")
    except OSError:
        pass
    assert pair_of(AuditDirectory.open, path, windows_attestation=ATTESTED) == (
        StorageErrorCode.UNSUPPORTED_FILESYSTEM, "directory:filesystem")
    assert code_of(AuditDirectory.open, path) is StorageErrorCode.ATTESTATION_REQUIRED
    assert os.listdir(path) == []


@pytest.fixture
def ntfs_base():
    """A fresh, uniquely named directory inside the authorized NTFS directory (safe to repeat, e.g. per mutant).

    Left in place: the CI cleanup step removes the whole authorized directory without following junctions."""
    import tempfile

    return tempfile.mkdtemp(prefix="c2c-", dir=NTFS_DIR)


@ntfs_only
def test_ntfs_audit_storage_is_read_only_and_writes_touch_nothing(ntfs_base):
    root = os.path.join(ntfs_base, "audit")
    os.mkdir(root)
    os.mkdir(os.path.join(root, CHAIN))
    with open(os.path.join(root, CHAIN, "seg-0.jsonl"), "wb") as handle:
        handle.write(LINE)
    with AuditDirectory.open(root, windows_attestation=ATTESTED) as audit:
        assert audit.list_names() == ListResult((CHAIN,), 0)
        assert pair_of(audit.open_chain, OTHER_CHAIN, create=True) == (StorageErrorCode.UNSUPPORTED_PLATFORM,
                                                                        "file:write-windows")
        with audit.open_chain(CHAIN) as chain:
            before = sorted(os.listdir(os.path.join(root, CHAIN)))
            for call in _write_calls(chain):
                assert code_of(call) is StorageErrorCode.UNSUPPORTED_PLATFORM
            assert sorted(os.listdir(os.path.join(root, CHAIN))) == before
            with chain.open_read("seg-0.jsonl", max_size=64) as reader:
                assert reader.read(64) == LINE
                reader.verify_unchanged()
            assert chain.list_names().names == ("seg-0.jsonl",)
    assert not os.path.exists(os.path.join(root, OTHER_CHAIN))


@ntfs_only
def test_ntfs_junction_chain_directory_and_hard_linked_member_are_refused(ntfs_base):
    import _winapi

    root = os.path.join(ntfs_base, "audit")
    target = os.path.join(ntfs_base, "junction-target")
    os.mkdir(root)
    os.mkdir(target)
    _winapi.CreateJunction(target, os.path.join(root, CHAIN))
    os.mkdir(os.path.join(root, OTHER_CHAIN))
    member = os.path.join(root, OTHER_CHAIN, "seg-0.jsonl")
    with open(member, "wb") as handle:
        handle.write(LINE)
    os.link(member, os.path.join(root, OTHER_CHAIN, "copy"))
    try:
        with AuditDirectory.open(root, windows_attestation=ATTESTED) as audit:
            assert code_of(audit.open_chain, CHAIN) is StorageErrorCode.UNSAFE_PATH
            with audit.open_chain(OTHER_CHAIN) as chain:
                assert pair_of(chain.open_read, "seg-0.jsonl", max_size=64) == (StorageErrorCode.FILE_UNSAFE,
                                                                                 "file:links")
    finally:
        os.rmdir(os.path.join(root, CHAIN))  # removes the junction only


@ntfs_only
def test_ntfs_open_member_cannot_be_replaced_and_growth_is_detected(ntfs_base):
    root = os.path.join(ntfs_base, "audit")
    os.mkdir(root)
    os.mkdir(os.path.join(root, CHAIN))
    member = os.path.join(root, CHAIN, "seg-0.jsonl")
    with open(member, "wb") as handle:
        handle.write(LINE)
    with AuditDirectory.open(root, windows_attestation=ATTESTED) as audit, audit.open_chain(CHAIN) as chain:
        with chain.open_read("seg-0.jsonl", max_size=64) as reader:
            with pytest.raises(OSError):
                os.rename(member, member + ".old")  # the open read handle prevents replacement (C2-B measured)
            with open(member, "ab") as handle:
                handle.write(b"more")
            assert pair_of(reader.verify_unchanged) == (StorageErrorCode.FILE_UNSAFE, "file:changed")


# --- Python versions ----------------------------------------------------------------------------------------------


def test_supported_python_versions():
    assert sys.version_info >= (3, 11)
    if IS_POSIX_WRITE:
        assert os.rename in os.supports_dir_fd and os.link in os.supports_follow_symlinks
