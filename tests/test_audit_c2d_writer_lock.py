"""Genesis B2-M2-C2-D: the chain writer lock (safepath.WriterLock).

Test tiers (mocked tests are never evidence of native platform behaviour):
* Portable: error codes, states, errno mapping tables, object hygiene, static structure.
* Mocked (``test_mocked_*``): the real acquisition, cleanup and lifecycle code driven with a stub
  ``fcntl`` and stub ``stat`` results for designated descriptors, on any host. Real descriptors are used,
  so "closed" is observed, not assumed.
* POSIX native (Linux/macOS CI): real flock on a private directory under the home directory, including
  helper subprocesses (contention, crash, fork). Every subprocess wait is bounded.
* Linux native: descriptor counting through /proc/self/fd; flock and fcntl locks do not interact.
* macOS native: flock and fcntl locks interact (BSD semantics; fail closed).
* NTFS native: Windows refuses before any filesystem I/O (audit storage is read-only).
The lock is advisory: these tests never claim protection against processes that ignore it.
All data is synthetic.
"""

import ast
import contextlib
import copy
import errno
import inspect
import os
import pickle
import stat
import subprocess
import sys
import time

import pytest

from rig_sentinel.audit import safepath as sp
from rig_sentinel.audit.safepath import (
    AuditDirectory,
    ChainDirectory,
    LockState,
    WindowsAttestation,
    WriterLock,
    check_chain_member_name,
)
from rig_sentinel.audit.storage_errors import StorageError, StorageErrorCode

IS_WINDOWS = os.name == "nt"
IS_POSIX_LOCK = sp._platform() == "posix" and sp._posix_write_capable() and sp._lock_capable()
IS_LINUX = sys.platform == "linux"
IS_MACOS = sys.platform == "darwin"
IS_ROOT = IS_POSIX_LOCK and os.geteuid() == 0
NTFS_DIR = os.environ.get("RIG_SENTINEL_NTFS_TEST_DIR")
ATTESTED = WindowsAttestation(local_fixed_ntfs=True, acl_recipe_applied=True, dedicated_account=True)
CHAIN = "chain-" + "0123456789abcdef" * 2
LOCK_NAME = ".writer.lock"
REAL_OPEN_LOCK_FILE = sp._posix_open_lock_file  # captured before any harness replaces it
WAIT = 30  # seconds: every subprocess interaction is bounded

posix_only = pytest.mark.skipif(not IS_POSIX_LOCK, reason="POSIX-only (flock, dir_fd)")
linux_only = pytest.mark.skipif(not (IS_POSIX_LOCK and IS_LINUX), reason="Linux-only")
macos_only = pytest.mark.skipif(not (IS_POSIX_LOCK and IS_MACOS), reason="macOS-only")
non_root = pytest.mark.skipif(IS_ROOT, reason="permission denials cannot be produced as root")
ntfs_only = pytest.mark.skipif(not (IS_WINDOWS and NTFS_DIR),
                               reason="needs an authorized native NTFS directory (RIG_SENTINEL_NTFS_TEST_DIR)")


def error_of(fn, *args, **kwargs):
    with pytest.raises(StorageError) as info:
        fn(*args, **kwargs)
    assert info.value.__context__ is None and info.value.__cause__ is None
    return info.value


def pair_of(fn, *args, **kwargs):
    error = error_of(fn, *args, **kwargs)
    return (error.code, error.path)


def is_closed(number):
    try:
        os.fstat(number)
    except OSError:
        return True
    return False


# --- Portable: codes, states, tables, hygiene, structure ----------------------------------------------------


def test_new_error_codes_are_additive():
    assert StorageErrorCode.LOCKED.value == "locked"
    assert StorageErrorCode.LOCK_INVALID.value == "lock_invalid"
    assert StorageErrorCode.PERMISSION_DENIED.value == "permission_denied"
    for name in ("FILE_UNSAFE", "UNSAFE_PATH", "STORAGE_UNAVAILABLE", "UNSUPPORTED_PLATFORM",
                 "UNSUPPORTED_FILESYSTEM", "FILE_EXISTS"):
        assert StorageErrorCode[name].value == name.lower()


def test_lock_states_and_terminal_labels():
    assert [state.value for state in LockState] == ["new", "held", "invalid", "released", "inherited"]
    assert sp._TERMINAL_LOCK_LABELS == {LockState.NEW: "lock:invalid", LockState.INVALID: "lock:invalid",
                                        LockState.RELEASED: "lock:released", LockState.INHERITED: "lock:forked"}


@pytest.mark.parametrize("number, expected", [
    (errno.EWOULDBLOCK, (StorageErrorCode.LOCKED, "lock:held")),
    (errno.EAGAIN, (StorageErrorCode.LOCKED, "lock:held")),
    (errno.EACCES, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:flock-denied")),
    (errno.EPERM, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:flock-denied")),
    (errno.EOPNOTSUPP, (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "lock:unsupported")),
    (errno.ENOTSUP, (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "lock:unsupported")),
    (errno.ENOLCK, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:resources")),
    (errno.EINTR, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:interrupted")),
    (errno.EBADF, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:flock")),
    (errno.EINVAL, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:flock")),
])
def test_flock_errno_mapping(number, expected):
    assert sp._lock_flock_problem(OSError(number, "synthetic")) == expected


def test_permission_denial_is_never_contention():
    for number in (errno.EACCES, errno.EPERM):
        assert sp._lock_flock_problem(OSError(number, "x"))[0] is not StorageErrorCode.LOCKED
        assert sp._lock_open_problem(OSError(number, "x"))[0] is StorageErrorCode.PERMISSION_DENIED


@pytest.mark.parametrize("number, expected", [
    (errno.EACCES, (StorageErrorCode.PERMISSION_DENIED, "lock:open-denied")),
    (errno.EPERM, (StorageErrorCode.PERMISSION_DENIED, "lock:open-denied")),
    (errno.ELOOP, (StorageErrorCode.UNSAFE_PATH, "lock:open")),
    (errno.ENXIO, (StorageErrorCode.FILE_UNSAFE, "lock:type")),
    (errno.EISDIR, (StorageErrorCode.FILE_UNSAFE, "lock:type")),
    (errno.EIO, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:open")),
])
def test_open_errno_mapping(number, expected):
    assert sp._lock_open_problem(OSError(number, "synthetic")) == expected


def _stat(*, ino=7, nlink=1, size=0, mode=stat.S_IFREG | 0o600, uid=4242, dev=99):
    return os.stat_result((mode, ino, dev, nlink, uid, 0, size, 0, 0, 0))


@pytest.mark.parametrize("kwargs, label", [
    ({}, None),
    ({"mode": stat.S_IFREG | 0o400}, None),
    ({"mode": stat.S_IFDIR | 0o700}, "lock:type"),
    ({"mode": stat.S_IFIFO | 0o600}, "lock:type"),
    ({"nlink": 2}, "lock:links"),
    ({"nlink": 0}, "lock:links"),
    ({"uid": 1}, "lock:permissions"),
    ({"mode": stat.S_IFREG | 0o640}, "lock:permissions"),
    ({"mode": stat.S_IFREG | 0o604}, "lock:permissions"),
    ({"mode": stat.S_IFREG | 0o610}, "lock:permissions"),
    ({"size": 1}, "lock:size"),
])
def test_lock_file_validation(kwargs, label):
    assert sp._lock_file_label(_stat(**kwargs), 4242) == label


def test_lock_name_is_reserved_and_never_a_member():
    assert sp._WRITER_LOCK_NAME == LOCK_NAME and sp._is_listed_member(LOCK_NAME)
    for kind in ("segment", "readable", "quarantine", "quarantine-source"):
        assert pair_of(check_chain_member_name, LOCK_NAME, kind=kind) == (StorageErrorCode.UNSAFE_PATH,
                                                                           "path:member-name")


def test_writer_lock_hygiene():
    lock = WriterLock(_dfd=None)
    for action in (pickle.dumps, copy.copy, copy.deepcopy):
        with pytest.raises(TypeError):
            action(lock)
    assert repr(lock) == "WriterLock(state='new')" == str(lock)
    assert lock.state is LockState.NEW and not lock.held


def _held_lock(owner=None):
    lock = WriterLock(_dfd=None)
    lock._state = LockState.HELD
    lock._owner = os.getpid() if owner is None else owner
    return lock


def test_terminal_states_are_absorbing():
    new = WriterLock(_dfd=None)
    assert pair_of(new.verify_held) == (StorageErrorCode.LOCK_INVALID, "lock:invalid")
    new._end(LockState.INVALID)
    released = _held_lock()
    released.release()
    inherited = _held_lock(owner=os.getpid() + 1)
    assert not inherited.held
    assert pair_of(inherited.verify_held) == (StorageErrorCode.LOCK_INVALID, "lock:forked")
    for lock, state, label in ((new, LockState.INVALID, "lock:invalid"), (released, LockState.RELEASED, "lock:released"),
                               (inherited, LockState.INHERITED, "lock:forked")):
        assert lock.state is state and not lock.held
        for _ in range(2):
            lock.release()  # idempotent no-op
            assert pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, label)
            lock._end(LockState.HELD)  # cannot leave a terminal state
            lock._end(LockState.RELEASED)
            lock._inherit()
            assert lock.state is state


def test_release_in_another_process_never_releases_as_owner():
    lock = _held_lock(owner=os.getpid() + 1)
    lock.release()
    assert lock.state is LockState.INHERITED


def _c2d_scopes(tree):
    names = {"WriterLock", "_lock_file_label", "_posix_open_lock_fd", "_lock_open_problem", "_posix_create_lock_file",
             "_posix_open_lock_file", "_lock_flock_problem", "_held_lock_problem", "_invalidate_inherited_locks",
             "_after_fork_in_child", "_lock_capable", "_lock_create_problem"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            yield node
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "ChainDirectory":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "acquire_writer_lock":
                    yield item


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _dotted(node.value)
        return f"{inner}.{node.attr}" if inner else None
    return None


def test_lock_code_never_removes_renames_chmods_or_unlocks():
    tree = ast.parse(inspect.getsource(sp))
    forbidden_calls = {"os.unlink", "os.remove", "os.rename", "os.replace", "os.chmod", "os.fchmod", "os.truncate",
                       "os.ftruncate", "os.write", "os.link", "os.mkdir", "os.rmdir", "fcntl.lockf", "fcntl.fcntl"}
    forbidden_attributes = {"LOCK_UN", "LOCK_SH", "O_CREAT", "O_RDWR", "O_WRONLY", "O_TRUNC", "O_APPEND"}
    # DV-H1-1 Option A: the single exception, scoped to the exclusive creator (checked in detail below).
    creator_only = {"_posix_create_lock_file": ({"os.fchmod"}, {"O_CREAT"})}
    seen = 0
    for scope in _c2d_scopes(tree):
        seen += 1
        calls_ok, attributes_ok = creator_only.get(scope.name, (set(), set()))
        for node in ast.walk(scope):
            if isinstance(node, ast.Call):
                called = _dotted(node.func)
                assert called not in forbidden_calls - calls_ok, (scope.name, called)
            if isinstance(node, ast.Attribute):
                assert node.attr not in forbidden_attributes - attributes_ok, (scope.name, node.attr)
    assert seen == 13


def _function(tree, name):
    matches = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name]
    assert len(matches) == 1, name
    return matches[0]


def test_only_the_dedicated_helper_creates_the_lock_file():
    """DV-H1-1 Option A: exactly one exclusive, descriptor-relative, read-only, no-follow creator."""
    tree = ast.parse(inspect.getsource(sp))
    helper = _function(tree, "_posix_create_lock_file")
    opens = [n for n in ast.walk(helper) if isinstance(n, ast.Call) and _dotted(n.func) == "os.open"]
    assert len(opens) == 1
    call = opens[0]
    assert _dotted(call.args[0]) == "_WRITER_LOCK_NAME" and ast.literal_eval(call.args[2]) == 0o600
    assert [ast.unparse(k) for k in call.keywords] == ["dir_fd=dfd"]
    flags = {n.attr for n in ast.walk(helper) if isinstance(n, ast.Attribute) and n.attr.startswith("O_")}
    assert flags == {"O_RDONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_CLOEXEC"}  # (+ O_NOCTTY via getattr)
    chmods = [(_dotted(n.args[0]), ast.literal_eval(n.args[1])) for n in ast.walk(helper)
              if isinstance(n, ast.Call) and _dotted(n.func) == "os.fchmod"]
    assert chmods == [("lock_fd", 0o600)]  # only the descriptor it has just created, exact mode
    called = {_dotted(n.func) for n in ast.walk(helper) if isinstance(n, ast.Call)}
    assert not called & {"os.unlink", "os.remove", "os.chmod", "os.write", "os.rename", "os.replace"}
    assert "_posix_unlink_if_ours" in called  # cleanup removes only its own file
    # Nothing else names the lock file in a create: the C2-C member creator is never pointed at it, and the
    # helper is reached only from the open-or-create-once sequence.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _dotted(node.func) in ("_posix_create_member", "_posix_create",
                                                                 "_posix_replace"):
            assert "_WRITER_LOCK_NAME" not in ast.unparse(node), ast.unparse(node)
    callers = {scope.name for scope in ast.walk(tree) if isinstance(scope, ast.FunctionDef)
               and any(isinstance(n, ast.Call) and _dotted(n.func) == "_posix_create_lock_file" for n in ast.walk(scope))}
    assert callers == {"_posix_open_lock_file"}
    creators = {scope.name for scope in ast.walk(tree) if isinstance(scope, ast.FunctionDef)
                and any(isinstance(n, ast.Attribute) and n.attr == "O_CREAT" for n in ast.walk(scope))}
    assert creators == {"_posix_create", "_posix_create_member", "_posix_replace", "_posix_create_lock_file"}
    source = inspect.getsource(sp)
    assert source.index("def _posix_create_lock_file") < source.index("def _windows_component_identities")
    # No alias: the lock file's name exists as a literal exactly once, in the reserved-name constant, so no
    # other code can reach it under another spelling.
    literals = [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and n.value == LOCK_NAME]
    assignments = [n for n in ast.walk(tree) if isinstance(n, ast.Assign) and n.value in literals
                   and [_dotted(target) for target in n.targets] == ["_WRITER_LOCK_NAME"]]
    assert len(literals) == 1 and len(assignments) == 1


def test_acquire_refuses_first_and_c2c_primitives_stay_lock_agnostic():
    body = ast.parse(inspect.getsource(ChainDirectory.acquire_writer_lock).strip()).body[0].body
    if isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    assert ast.unparse(body[0]) == "self._require_posix_write()"
    for method in ("create_exclusive", "open_append", "open_read", "replace_atomically", "link_no_replace",
                   "remove_created", "list_names", "sync"):
        source = inspect.getsource(getattr(ChainDirectory, method))
        assert "WriterLock" not in source and "verify_held" not in source, method


def test_fork_hook_is_registered_through_a_trampoline():
    source = inspect.getsource(sp)
    assert source.count("os.register_at_fork(after_in_child=_after_fork_in_child)") == 1
    calls = []
    original = sp._invalidate_inherited_locks
    try:
        sp._invalidate_inherited_locks = lambda: calls.append(1)
        sp._after_fork_in_child()
    finally:
        sp._invalidate_inherited_locks = original
    assert calls == [1]


def test_lock_capability_is_attribute_presence_only(monkeypatch):
    monkeypatch.setattr(sp, "_posix_write_capable", lambda: True)
    monkeypatch.setattr(sp.os, "register_at_fork", lambda **kwargs: None, raising=False)

    class WithFlock:
        @staticmethod
        def flock(fd, operation):
            return None

    monkeypatch.setattr(sp, "fcntl", WithFlock)
    assert sp._lock_capable()
    monkeypatch.setattr(WithFlock, "flock", lambda fd, operation: None)  # a test wrapper: still capable
    assert sp._lock_capable()
    monkeypatch.setattr(sp, "fcntl", object())
    assert not sp._lock_capable()
    monkeypatch.setattr(sp, "fcntl", WithFlock)
    monkeypatch.delattr(sp.os, "register_at_fork")
    assert not sp._lock_capable()
    monkeypatch.setattr(sp, "fcntl", None)
    assert not sp._lock_capable()


# --- Mocked: refusal before any OS call -------------------------------------------------------------------


GUARDED = ("open", "close", "dup", "fstat", "stat", "lstat", "mkdir", "unlink", "rename", "replace", "link", "chmod",
           "fchmod", "write", "read", "fsync", "scandir")


@contextlib.contextmanager
def no_os_calls():
    """Every listed os function (and fcntl.flock, if present) records and fails, only inside the block."""
    calls = []
    saved = {}
    for name in GUARDED:
        if hasattr(sp.os, name):
            saved[name] = getattr(sp.os, name)
            setattr(sp.os, name, (lambda name: lambda *a, **k: calls.append(name) or (_ for _ in ()).throw(
                AssertionError("os." + name)))(name))
    try:
        yield calls
    finally:
        for name, real in saved.items():
            setattr(sp.os, name, real)


def test_windows_refuses_before_any_os_call():
    chain = ChainDirectory(_kind="nt", _fd=None, _path="C:\\audit\\" + CHAIN, _identities=((1, 2),))
    with no_os_calls() as calls:
        problem = pair_of(chain.acquire_writer_lock)
    assert problem == (StorageErrorCode.UNSUPPORTED_PLATFORM, "file:write-windows") and calls == []
    assert "msvcrt" not in vars(sp)


def test_incapable_posix_refuses_before_any_os_call(monkeypatch):
    chain = ChainDirectory(_kind="posix", _fd=-1, _path="/a/" + CHAIN, _identities=())
    monkeypatch.setattr(sp, "_posix_write_capable", lambda: False)
    with no_os_calls() as calls:
        first = pair_of(chain.acquire_writer_lock)
    monkeypatch.setattr(sp, "_posix_write_capable", lambda: True)
    monkeypatch.setattr(sp, "_lock_capable", lambda: False)
    with no_os_calls() as more:
        second = pair_of(chain.acquire_writer_lock)
    assert first == (StorageErrorCode.UNSUPPORTED_PLATFORM, "file:write-platform")
    assert second == (StorageErrorCode.UNSUPPORTED_PLATFORM, "lock:platform")
    assert calls == [] and more == []
    chain._fd = None


def test_closed_chain_directory_refuses(monkeypatch):
    chain = ChainDirectory(_kind="posix", _fd=None, _path="/a/" + CHAIN, _identities=())
    chain._closed = True
    with no_os_calls() as calls:
        assert pair_of(chain.acquire_writer_lock) == (StorageErrorCode.STORAGE_UNAVAILABLE, "directory:closed")
    assert calls == []


# --- Mocked: the real acquisition and lifecycle code with a stub fcntl ------------------------------------


class StubFcntl:
    LOCK_SH, LOCK_EX, LOCK_NB, LOCK_UN = 1, 2, 4, 8

    def __init__(self):
        self.calls = []
        self.effect = None  # exception instance to raise, or a callable run before returning

    def flock(self, fd, operation):
        self.calls.append(operation)
        if isinstance(self.effect, BaseException):
            raise self.effect
        if callable(self.effect):
            self.effect()


class Mocked:
    """A posix-kind ChainDirectory over real descriptors (so closing is observable), stub fcntl and stat."""

    def __init__(self, monkeypatch, tmp_path):
        self.monkeypatch = monkeypatch
        self.files = []
        self.fds = []
        self.opened_locks = []
        self.dups = []
        self.fcntl = StubFcntl()
        self.fstat_result = _stat()
        self.named_result = _stat()
        self.open_problem = None
        base = tmp_path / "fds"
        base.mkdir()
        self.base = base
        source = self._real_fd("chain")
        self.chain = ChainDirectory(_kind="posix", _fd=source, _path="/a/" + CHAIN, _identities=())
        monkeypatch.setattr(sp, "_posix_write_capable", lambda: True)
        monkeypatch.setattr(sp, "_lock_capable", lambda: True)
        monkeypatch.setattr(sp.os, "geteuid", lambda: 4242, raising=False)
        monkeypatch.setattr(sp, "fcntl", self.fcntl)
        monkeypatch.setattr(sp, "_posix_open_lock_file", self._open_lock_file)
        real_dup, real_fstat, real_stat = os.dup, os.fstat, os.stat

        def dup(fd):
            new = real_dup(fd)
            self.dups.append(new)
            return new

        def fstat(fd):
            real = real_fstat(fd)  # a closed descriptor still fails, so closing stays observable
            if fd not in self.opened_locks:
                return real
            if isinstance(self.fstat_result, BaseException):
                raise self.fstat_result
            return self.fstat_result

        def stat_(path, *args, **kwargs):
            if path == LOCK_NAME and "dir_fd" in kwargs:
                if isinstance(self.named_result, BaseException):
                    raise self.named_result
                return self.named_result
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(sp.os, "dup", dup)
        monkeypatch.setattr(sp.os, "fstat", fstat)
        monkeypatch.setattr(sp.os, "stat", stat_)

    def _real_fd(self, name):
        path = self.base / (name + str(len(self.files)))
        path.write_bytes(b"")
        self.files.append(path)
        fd = os.open(str(path), os.O_RDONLY)
        self.fds.append(fd)
        return fd

    def _open_lock_file(self, dfd):
        if self.open_problem is not None:
            return None, self.open_problem
        fd = self._real_fd("lock")
        self.opened_locks.append(fd)
        return fd, None

    def owned(self):
        return self.opened_locks + self.dups

    def all_closed(self):
        return all(is_closed(fd) for fd in self.owned())

    def cleanup(self):
        self.monkeypatch.undo()
        for fd in self.fds:
            if not is_closed(fd):
                os.close(fd)


@pytest.fixture
def mocked(monkeypatch, tmp_path):
    harness = Mocked(monkeypatch, tmp_path)
    yield harness
    sp._HELD_LOCKS.clear()
    harness.cleanup()


def test_mocked_acquire_verify_and_release(mocked):
    lock = mocked.chain.acquire_writer_lock()
    assert lock.state is LockState.HELD and lock.held
    assert mocked.fcntl.calls == [StubFcntl.LOCK_EX | StubFcntl.LOCK_NB]  # exclusive, non-blocking, once
    assert sp._HELD_LOCKS == {id(lock): lock}
    lock.verify_held()
    assert not mocked.all_closed()
    lock.release()
    assert lock.state is LockState.RELEASED and mocked.all_closed() and sp._HELD_LOCKS == {}
    assert pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, "lock:released")
    lock.release()
    assert lock.state is LockState.RELEASED


def test_mocked_context_manager_releases(mocked):
    with mocked.chain.acquire_writer_lock() as lock:
        assert lock.held
    assert lock.state is LockState.RELEASED and mocked.all_closed()


@pytest.mark.parametrize("number, expected", [
    (errno.EWOULDBLOCK, (StorageErrorCode.LOCKED, "lock:held")),
    (errno.EAGAIN, (StorageErrorCode.LOCKED, "lock:held")),
    (errno.EACCES, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:flock-denied")),
    (errno.EPERM, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:flock-denied")),
    (errno.EINTR, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:interrupted")),
    (errno.ENOLCK, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:resources")),
    (errno.EOPNOTSUPP, (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "lock:unsupported")),
    (errno.ENOTSUP, (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "lock:unsupported")),
    (errno.EBADF, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:flock")),
])
def test_mocked_flock_failures_close_everything_without_retry(mocked, number, expected):
    mocked.fcntl.effect = OSError(number, "synthetic")
    assert pair_of(mocked.chain.acquire_writer_lock) == expected
    assert len(mocked.fcntl.calls) == 1  # no retry loop, including EINTR
    assert mocked.all_closed() and sp._HELD_LOCKS == {}


@pytest.mark.parametrize("exception", [KeyboardInterrupt(), SystemExit(3), RuntimeError("handler")])
def test_mocked_signal_handler_exception_closes_everything(mocked, exception):
    mocked.fcntl.effect = exception
    with pytest.raises(type(exception)) as info:
        mocked.chain.acquire_writer_lock()
    assert info.value is exception  # the original exception, unchanged
    assert len(mocked.fcntl.calls) == 1 and mocked.all_closed() and sp._HELD_LOCKS == {}


@pytest.mark.parametrize("result, label", [
    (_stat(mode=stat.S_IFREG | 0o640), "lock:permissions"),
    (_stat(uid=1), "lock:permissions"),
    (_stat(nlink=2), "lock:links"),
    (_stat(size=3), "lock:size"),
    (_stat(mode=stat.S_IFDIR | 0o700), "lock:type"),
])
def test_mocked_unsafe_lock_file_is_refused_before_flock(mocked, result, label):
    mocked.fstat_result = result
    assert pair_of(mocked.chain.acquire_writer_lock) == (StorageErrorCode.FILE_UNSAFE, label)
    assert mocked.fcntl.calls == [] and mocked.all_closed()


def test_mocked_fstat_failure_after_open_closes_everything(mocked):
    mocked.fstat_result = OSError(errno.EIO, "synthetic")
    assert pair_of(mocked.chain.acquire_writer_lock) == (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:open")
    assert mocked.all_closed()


def test_mocked_open_problem_closes_the_directory_copy(mocked):
    mocked.open_problem = (StorageErrorCode.PERMISSION_DENIED, "lock:open-denied")
    assert pair_of(mocked.chain.acquire_writer_lock) == (StorageErrorCode.PERMISSION_DENIED, "lock:open-denied")
    assert mocked.fcntl.calls == [] and mocked.dups and mocked.all_closed()


@pytest.mark.parametrize("named, label", [
    (_stat(ino=8), "lock:substituted"),
    (FileNotFoundError(errno.ENOENT, "gone"), "lock:substituted"),
    (_stat(mode=stat.S_IFLNK | 0o777), "lock:substituted"),
    (_stat(nlink=2), "lock:links"),
    (OSError(errno.EIO, "synthetic"), "lock:verify"),
])
def test_mocked_pathname_identity_is_checked_after_flock(mocked, named, label):
    mocked.named_result = named
    assert pair_of(mocked.chain.acquire_writer_lock) == (StorageErrorCode.LOCK_INVALID, label)
    assert len(mocked.fcntl.calls) == 1 and mocked.all_closed() and sp._HELD_LOCKS == {}


@pytest.mark.parametrize("changed, label", [
    (_stat(size=1), "lock:size"),
    (_stat(ino=9), "lock:changed"),
    (_stat(nlink=0), "lock:substituted"),
    (_stat(nlink=2), "lock:links"),
])
def test_mocked_descriptor_identity_is_checked_after_flock(mocked, changed, label):
    def during_lock():
        mocked.fstat_result = changed

    mocked.fcntl.effect = during_lock
    assert pair_of(mocked.chain.acquire_writer_lock) == (StorageErrorCode.LOCK_INVALID, label)
    assert mocked.all_closed()


@pytest.mark.parametrize("attribute, value, label", [
    ("fstat_result", _stat(size=1), "lock:size"),
    ("fstat_result", _stat(ino=9), "lock:changed"),
    ("fstat_result", _stat(nlink=2), "lock:links"),
    ("fstat_result", _stat(nlink=0), "lock:substituted"),
    ("named_result", _stat(ino=8), "lock:substituted"),
    ("named_result", FileNotFoundError(errno.ENOENT, "gone"), "lock:substituted"),
    ("named_result", _stat(nlink=2), "lock:links"),
    ("named_result", OSError(errno.EIO, "synthetic"), "lock:verify"),
])
def test_mocked_failed_verification_invalidates_and_closes(mocked, attribute, value, label):
    lock = mocked.chain.acquire_writer_lock()
    setattr(mocked, attribute, value)
    assert pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, label)
    assert lock.state is LockState.INVALID and not lock.held and mocked.all_closed() and sp._HELD_LOCKS == {}
    setattr(mocked, attribute, _stat())  # even if the file looks fine again, the lock never comes back
    assert pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, "lock:invalid")
    lock.release()
    assert lock.state is LockState.INVALID


def test_mocked_owner_pid_mismatch_becomes_inherited(mocked, monkeypatch):
    lock = mocked.chain.acquire_writer_lock()
    real = os.getpid()
    monkeypatch.setattr(sp.os, "getpid", lambda: real + 1)
    assert not lock.held
    assert pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, "lock:forked")
    assert lock.state is LockState.INHERITED and mocked.all_closed() and sp._HELD_LOCKS == {}


def test_mocked_fork_hook_closes_lock_fd_and_directory_fd(mocked):
    lock = mocked.chain.acquire_writer_lock()
    lock_fd, dir_fd = lock._fd, lock._dfd
    assert not is_closed(lock_fd) and not is_closed(dir_fd)
    sp._invalidate_inherited_locks()
    assert is_closed(lock_fd) and is_closed(dir_fd)  # both (H-1)
    assert lock.state is LockState.INHERITED and not lock.held and sp._HELD_LOCKS == {}
    assert pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, "lock:forked")
    lock.release()
    assert lock.state is LockState.INHERITED


def test_mocked_close_is_double_close_safe(mocked):
    lock = mocked.chain.acquire_writer_lock()
    lock_fd = lock._fd
    lock.release()
    replacement = os.open(str(mocked.files[0]), os.O_RDONLY)  # may reuse the same number
    try:
        lock._close_fds()
        lock.release()
        sp._invalidate_inherited_locks()
        assert not is_closed(replacement)
    finally:
        os.close(replacement)
    assert lock._fd is None and lock._dfd is None and lock_fd is not None


# --- Mocked (H2): error paths, descriptor ownership, children without the fork hook, terminal states --------


def test_mocked_directory_dup_failure_opens_nothing(mocked, monkeypatch):
    def failing_dup(fd):
        raise OSError(errno.EMFILE, "synthetic")

    monkeypatch.setattr(sp.os, "dup", failing_dup)
    assert pair_of(mocked.chain.acquire_writer_lock) == (StorageErrorCode.STORAGE_UNAVAILABLE, "directory:dup")
    assert mocked.opened_locks == [] and mocked.fcntl.calls == [] and sp._HELD_LOCKS == {}
    assert not is_closed(mocked.chain._fd)  # the chain directory's own descriptor is never touched


def test_mocked_lock_owns_a_private_directory_copy(mocked):
    chain_fd = mocked.chain._fd
    lock = mocked.chain.acquire_writer_lock()
    assert lock._dfd in mocked.dups and lock._dfd != chain_fd
    lock.release()
    assert mocked.all_closed() and not is_closed(chain_fd)  # releasing never closes the chain's descriptor
    with mocked.chain.acquire_writer_lock() as again:  # the chain directory stays usable
        assert again.held


@pytest.mark.parametrize("number, expected", [
    (errno.EACCES, (StorageErrorCode.PERMISSION_DENIED, "lock:open-denied")),
    (errno.EPERM, (StorageErrorCode.PERMISSION_DENIED, "lock:open-denied")),
    (errno.ELOOP, (StorageErrorCode.UNSAFE_PATH, "lock:open")),
    (errno.ENXIO, (StorageErrorCode.FILE_UNSAFE, "lock:type")),
    (errno.EISDIR, (StorageErrorCode.FILE_UNSAFE, "lock:type")),
    (errno.EIO, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:open")),
    (errno.EMFILE, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:open")),
])
def test_mocked_lock_file_open_errors_close_the_directory_copy(mocked, monkeypatch, number, expected):
    calls = []

    def open_fd(dfd):
        calls.append(dfd)
        raise OSError(number, "synthetic")

    monkeypatch.setattr(sp, "_posix_open_lock_file", REAL_OPEN_LOCK_FILE)
    monkeypatch.setattr(sp, "_posix_open_lock_fd", open_fd)
    monkeypatch.setattr(sp, "_posix_create_lock_file", lambda dfd: pytest.fail("create after a non-ENOENT error"))
    assert pair_of(mocked.chain.acquire_writer_lock) == expected
    assert len(calls) == 1 and calls[0] in mocked.dups  # opened relative to the private directory copy, once
    assert mocked.fcntl.calls == [] and mocked.all_closed() and sp._HELD_LOCKS == {}


@pytest.mark.parametrize("second, expected", [
    (PermissionError(errno.EACCES, "x"), (StorageErrorCode.PERMISSION_DENIED, "lock:open-denied")),
    (OSError(errno.ELOOP, "x"), (StorageErrorCode.UNSAFE_PATH, "lock:open")),
    (FileNotFoundError(errno.ENOENT, "x"), (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:open")),
])
def test_mocked_open_failure_after_create_closes_everything(mocked, monkeypatch, second, expected):
    results = [FileNotFoundError(errno.ENOENT, "x"), second]
    created = []

    def open_fd(dfd):
        raise results.pop(0)

    monkeypatch.setattr(sp, "_posix_open_lock_file", REAL_OPEN_LOCK_FILE)
    monkeypatch.setattr(sp, "_posix_open_lock_fd", open_fd)
    monkeypatch.setattr(sp, "_posix_create_lock_file", lambda dfd: created.append(dfd))
    assert pair_of(mocked.chain.acquire_writer_lock) == expected
    assert results == [] and len(created) == 1  # open, create once, open once: no loop
    assert mocked.fcntl.calls == [] and mocked.all_closed() and sp._HELD_LOCKS == {}


def test_mocked_create_problem_closes_the_directory_copy(mocked, monkeypatch):
    def open_fd(dfd):
        raise FileNotFoundError(errno.ENOENT, "x")

    monkeypatch.setattr(sp, "_posix_open_lock_file", REAL_OPEN_LOCK_FILE)
    monkeypatch.setattr(sp, "_posix_open_lock_fd", open_fd)
    monkeypatch.setattr(sp, "_posix_create_lock_file",
                        lambda dfd: (StorageErrorCode.PERMISSION_DENIED, "lock:create-denied"))
    assert pair_of(mocked.chain.acquire_writer_lock) == (StorageErrorCode.PERMISSION_DENIED, "lock:create-denied")
    assert mocked.fcntl.calls == [] and mocked.all_closed() and sp._HELD_LOCKS == {}


def test_mocked_child_without_the_fork_hook_is_never_held(mocked, monkeypatch):
    """A child created by a fork that bypassed os.register_at_fork (for example a C-level fork)."""
    lock = mocked.chain.acquire_writer_lock()
    flock_calls = list(mocked.fcntl.calls)
    real = os.getpid()
    monkeypatch.setattr(sp.os, "getpid", lambda: real + 1)
    assert not lock.held
    assert lock.state is LockState.HELD and not mocked.all_closed()  # reading `held` has no side effect
    lock.release()  # in the child: never releases as owner, never LOCK_UN, closes its own copies only
    assert lock.state is LockState.INHERITED and mocked.all_closed() and sp._HELD_LOCKS == {}
    assert mocked.fcntl.calls == flock_calls
    assert pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, "lock:forked")
    monkeypatch.setattr(sp.os, "getpid", lambda: real)  # even back in the "owner", the lock never returns
    assert not lock.held and pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, "lock:forked")


def _to_invalid(mocked, lock):
    mocked.fstat_result = _stat(size=1)
    error_of(lock.verify_held)
    mocked.fstat_result = _stat()


def _to_released(mocked, lock):
    lock.release()


def _to_inherited_by_hook(mocked, lock):
    sp._invalidate_inherited_locks()


@pytest.mark.parametrize("reach, state, label", [
    (_to_invalid, LockState.INVALID, "lock:invalid"),
    (_to_released, LockState.RELEASED, "lock:released"),
    (_to_inherited_by_hook, LockState.INHERITED, "lock:forked"),
])
def test_mocked_terminal_states_reached_by_real_paths_are_absorbing(mocked, reach, state, label):
    lock = mocked.chain.acquire_writer_lock()
    reach(mocked, lock)
    assert lock.state is state and not lock.held and mocked.all_closed() and sp._HELD_LOCKS == {}
    assert lock._fd is None and lock._dfd is None
    flock_calls = list(mocked.fcntl.calls)
    for _ in range(2):
        assert pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, label)
        lock.release()
        lock.close()
        lock._end(LockState.HELD)
        sp._invalidate_inherited_locks()
        assert lock.state is state and not lock.held
    assert mocked.fcntl.calls == flock_calls  # nothing in a terminal state touches the lock again
    with mocked.chain.acquire_writer_lock() as fresh:  # a new acquisition is a new, independent object
        assert fresh is not lock and fresh.held and lock.state is state


# --- Mocked: lock-file open and create sequencing ----------------------------------------------------------


def test_mocked_open_then_create_once(monkeypatch):
    events = []

    def opener(results):
        def open_fd(dfd):
            events.append("open")
            result = results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        return open_fd

    monkeypatch.setattr(sp, "_posix_create_lock_file", lambda dfd: events.append("create") or None)
    monkeypatch.setattr(sp, "_posix_open_lock_fd", opener([55]))
    assert sp._posix_open_lock_file(3) == (55, None) and events == ["open"]
    events.clear()
    monkeypatch.setattr(sp, "_posix_open_lock_fd", opener([FileNotFoundError(errno.ENOENT, "x"), 56]))
    assert sp._posix_open_lock_file(3) == (56, None) and events == ["open", "create", "open"]
    events.clear()
    monkeypatch.setattr(sp, "_posix_open_lock_fd", opener([FileNotFoundError(errno.ENOENT, "x"),
                                                           FileNotFoundError(errno.ENOENT, "x")]))
    assert sp._posix_open_lock_file(3) == (None, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:open"))
    assert events == ["open", "create", "open"]  # no retry loop
    events.clear()
    monkeypatch.setattr(sp, "_posix_open_lock_fd", opener([PermissionError(errno.EACCES, "x")]))
    assert sp._posix_open_lock_file(3) == (None, (StorageErrorCode.PERMISSION_DENIED, "lock:open-denied"))
    assert events == ["open"]
    events.clear()
    monkeypatch.setattr(sp, "_posix_create_lock_file",
                        lambda dfd: events.append("create") or (StorageErrorCode.UNSAFE_PATH, "lock:create"))
    monkeypatch.setattr(sp, "_posix_open_lock_fd", opener([FileNotFoundError(errno.ENOENT, "x")]))
    assert sp._posix_open_lock_file(3) == (None, (StorageErrorCode.UNSAFE_PATH, "lock:create"))
    assert events == ["open", "create"]


# --- Mocked (DV-H1-1 Option A): the dedicated, errno-aware lock-file creator ------------------------------------
#
# INJECTED errno simulations on any host: they prove classification, cleanup and descriptor handling of the
# real helper, never native kernel behaviour (that is the POSIX-native tier below). os.open, fstat, fchmod and
# the pathname stat are replaced for the designated descriptors only; a real descriptor stands in for the
# created file, so closing is observed. The C2-C cleanup helper is recorded here; its refusal to delete a
# foreign file is proven by C2-C tests and by the native substitution test below.

CREATE_DFD = 31337
CREATE_ERRNOS = ["EACCES", "EPERM", "ENOSPC", "EROFS", "EIO", "EDQUOT"]


def _portable_posix_flags(monkeypatch):
    for flag, value in (("O_NOFOLLOW", 0x10000000), ("O_CLOEXEC", 0x20000000), ("O_NOCTTY", 0x40000000)):
        monkeypatch.setattr(sp.os, flag, getattr(os, flag, value), raising=False)
    monkeypatch.setattr(sp.os, "geteuid", lambda: 4242, raising=False)


class CreateHarness:
    def __init__(self, monkeypatch, tmp_path):
        self.monkeypatch = monkeypatch
        _portable_posix_flags(monkeypatch)
        path = tmp_path / "created-lock"
        path.write_bytes(b"")
        self.fd = os.open(str(path), os.O_RDONLY)
        self.opens = []
        self.chmods = []
        self.cleanups = []
        self.fstat_fds = []
        self.open_effect = None  # exception raised by the create itself
        self.fchmod_effect = None  # exception raised by fchmod
        self.created = _stat(ino=11, mode=stat.S_IFREG | 0o400)  # right after the create (umask applied)
        self.after = _stat(ino=11)  # after fchmod(0o600)
        self.named = _stat(ino=11)  # the pathname, as seen by stat(dir_fd=..., follow_symlinks=False)
        real_fstat, real_stat = os.fstat, os.stat
        seen = {"count": 0}

        def fake_open(name, flags, *args, **kwargs):
            self.opens.append((name, flags, args, kwargs))
            if self.open_effect is not None:
                raise self.open_effect
            return self.fd

        def fake_fstat(fd):
            self.fstat_fds.append(fd)
            real = real_fstat(fd)  # a closed or foreign descriptor still fails, so closing stays observable
            if fd != self.fd:
                return real
            seen["count"] += 1
            return self.created if seen["count"] == 1 else self.after

        def fake_fchmod(fd, mode):
            self.chmods.append((fd, mode))
            if self.fchmod_effect is not None:
                raise self.fchmod_effect

        def fake_stat(name, *args, **kwargs):
            if name == LOCK_NAME and kwargs.get("dir_fd") == CREATE_DFD:
                assert kwargs.get("follow_symlinks") is False
                if isinstance(self.named, BaseException):
                    raise self.named
                return self.named
            return real_stat(name, *args, **kwargs)

        monkeypatch.setattr(sp.os, "open", fake_open)
        monkeypatch.setattr(sp.os, "fstat", fake_fstat)
        monkeypatch.setattr(sp.os, "fchmod", fake_fchmod, raising=False)
        monkeypatch.setattr(sp.os, "stat", fake_stat)
        monkeypatch.setattr(sp, "_posix_unlink_if_ours",
                            lambda dfd, name, fd, identity: self.cleanups.append((dfd, name, fd, identity)))

    def create(self):
        return sp._posix_create_lock_file(CREATE_DFD)

    def ours(self):
        return [(CREATE_DFD, LOCK_NAME, self.fd, sp._identity(self.created))]

    def closed(self):
        return is_closed(self.fd)

    def close(self):
        self.monkeypatch.undo()
        if not is_closed(self.fd):
            os.close(self.fd)


@pytest.fixture
def creating(monkeypatch, tmp_path):
    harness = CreateHarness(monkeypatch, tmp_path)
    yield harness
    harness.close()


def test_create_lock_file_is_exclusive_read_only_private_and_closed(creating):
    assert creating.create() is None
    [(name, flags, args, kwargs)] = creating.opens
    expected = (os.O_RDONLY | os.O_CREAT | os.O_EXCL | sp.os.O_NOFOLLOW | sp.os.O_CLOEXEC
                | getattr(sp.os, "O_NOCTTY", 0))
    assert (name, flags, args, kwargs) == (LOCK_NAME, expected, (0o600,), {"dir_fd": CREATE_DFD})
    assert flags & (os.O_WRONLY | os.O_RDWR | getattr(os, "O_TRUNC", 0) | getattr(os, "O_APPEND", 0)) == 0
    assert creating.chmods == [(creating.fd, 0o600)]  # exact mode, on the new descriptor only
    assert creating.cleanups == [] and creating.closed()
    assert CREATE_DFD not in creating.fstat_fds  # the directory's mode bits are never consulted


@pytest.mark.parametrize("number, expected", [
    (errno.EACCES, (StorageErrorCode.PERMISSION_DENIED, "lock:create-denied")),
    (errno.EPERM, (StorageErrorCode.PERMISSION_DENIED, "lock:create-denied")),
    (errno.ENOSPC, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create")),
    (errno.EDQUOT, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create")),
    (errno.EROFS, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create")),
    (errno.EIO, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create")),
    (errno.ELOOP, (StorageErrorCode.UNSAFE_PATH, "lock:create")),
    (errno.ENOTDIR, (StorageErrorCode.UNSAFE_PATH, "lock:create")),
    (errno.EINVAL, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create")),  # unknown: conservative
    (errno.ENAMETOOLONG, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create")),
    (99999, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create")),
    (errno.EEXIST, None),  # the caller opens and validates the existing name exactly once
])
def test_create_lock_file_classifies_the_actual_errno(creating, number, expected):
    creating.open_effect = OSError(number, "synthetic")
    result = creating.create()
    assert result == expected
    assert result is None or result[0] is not StorageErrorCode.LOCKED  # a denial is never contention
    assert len(creating.opens) == 1  # one create attempt, no retry
    assert creating.chmods == [] and creating.cleanups == []  # nothing was created, nothing is removed
    assert CREATE_DFD not in creating.fstat_fds  # classified from the errno, never from the directory mode


@pytest.mark.parametrize("mode", [0o700, 0o500, 0o300, 0o000])
def test_create_classification_is_independent_of_the_directory_mode(creating, monkeypatch, mode):
    original = sp.os.fstat
    monkeypatch.setattr(sp.os, "fstat", lambda fd: _stat(mode=stat.S_IFDIR | mode) if fd == CREATE_DFD else original(fd))
    for number, code in ((errno.EACCES, StorageErrorCode.PERMISSION_DENIED),
                         (errno.EROFS, StorageErrorCode.STORAGE_UNAVAILABLE)):
        creating.open_effect = OSError(number, "synthetic")
        assert creating.create()[0] is code


@pytest.mark.parametrize("number", [errno.EPERM, errno.EACCES, errno.EIO, errno.EROFS])
def test_post_create_fchmod_failure_removes_only_our_file_and_closes(creating, number):
    creating.fchmod_effect = OSError(number, "synthetic")
    assert creating.create() == (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create-verify")
    assert creating.cleanups == creating.ours() and creating.closed()


@pytest.mark.parametrize("after, label", [
    (_stat(ino=11, mode=stat.S_IFREG | 0o644), "lock:permissions"),
    (_stat(ino=11, uid=1), "lock:permissions"),
    (_stat(ino=11, nlink=2), "lock:links"),
    (_stat(ino=11, size=1), "lock:size"),
    (_stat(ino=11, mode=stat.S_IFDIR | 0o700), "lock:type"),
])
def test_post_create_validation_failure_removes_only_our_file(creating, after, label):
    creating.after = after
    assert creating.create() == (StorageErrorCode.FILE_UNSAFE, label)
    assert creating.cleanups == creating.ours() and creating.closed()


@pytest.mark.parametrize("named", [_stat(ino=12), _stat(ino=11, dev=98), _stat(ino=13, mode=stat.S_IFLNK | 0o777),
                                   FileNotFoundError(errno.ENOENT, "gone")])
def test_post_create_identity_failure_is_detected_and_cleanup_is_identity_bound(creating, named):
    creating.named = named  # another inode (or nothing) at the name right after our create
    assert creating.create() == (StorageErrorCode.FILE_UNSAFE, "lock:changed")
    assert creating.cleanups == creating.ours()  # the identity-bound C2-C helper decides; never a bare unlink
    assert creating.closed()


def test_post_create_pathname_stat_error_fails_closed(creating):
    creating.named = OSError(errno.EIO, "synthetic")
    assert creating.create() == (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create-verify")
    assert creating.cleanups == creating.ours() and creating.closed()


@pytest.mark.parametrize("exception", [KeyboardInterrupt(), SystemExit(2), RuntimeError("handler")])
def test_base_exception_after_create_cleans_up_and_propagates_unchanged(creating, exception):
    creating.fchmod_effect = exception
    with pytest.raises(type(exception)) as info:
        creating.create()
    assert info.value is exception
    assert creating.cleanups == creating.ours() and creating.closed()


def test_base_exception_from_the_create_itself_propagates(creating):
    creating.open_effect = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        creating.create()
    assert creating.chmods == [] and creating.cleanups == []


@pytest.mark.parametrize("number, expected", [
    (errno.EACCES, (StorageErrorCode.PERMISSION_DENIED, "lock:create-denied")),
    (errno.EPERM, (StorageErrorCode.PERMISSION_DENIED, "lock:create-denied")),
    (errno.EROFS, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create")),
    (errno.ENOSPC, (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create")),
])
def test_mocked_acquire_reports_the_create_errno_and_closes_everything(mocked, monkeypatch, number, expected):
    _portable_posix_flags(monkeypatch)
    creates = []

    def missing(dfd):
        raise FileNotFoundError(errno.ENOENT, "x")

    def failing_create(name, flags, *args, **kwargs):
        creates.append((name, kwargs.get("dir_fd")))
        raise OSError(number, "synthetic")

    monkeypatch.setattr(sp, "_posix_open_lock_file", REAL_OPEN_LOCK_FILE)
    monkeypatch.setattr(sp, "_posix_open_lock_fd", missing)
    monkeypatch.setattr(sp.os, "open", failing_create)
    assert pair_of(mocked.chain.acquire_writer_lock) == expected
    assert len(creates) == 1 and creates[0][0] == LOCK_NAME and creates[0][1] in mocked.dups
    assert mocked.fcntl.calls == [] and mocked.all_closed() and sp._HELD_LOCKS == {}


# The approved C2-C member primitive is unchanged and still carries no errno: the reason Option A needed a
# dedicated creator instead of reusing it.


def _c2c_create_with_errno(monkeypatch, name):
    """Run the real C2-C create primitive with os.open failing with errno ``name``; returns what it saw."""
    _portable_posix_flags(monkeypatch)
    seen = []

    def failing_open(path, flags, *args, **kwargs):
        seen.append((path, flags & os.O_CREAT != 0, flags & os.O_EXCL != 0, flags & sp.os.O_NOFOLLOW != 0,
                     kwargs.get("dir_fd")))
        raise OSError(getattr(errno, name, errno.EIO), "synthetic")

    monkeypatch.setattr(sp.os, "open", failing_open)
    return seen


@pytest.mark.parametrize("name", CREATE_ERRNOS)
def test_c2c_member_create_primitive_is_unchanged_and_carries_no_errno(monkeypatch, name):
    seen = _c2c_create_with_errno(monkeypatch, name)
    error = error_of(sp._posix_create_member, CREATE_DFD, "seg-0.jsonl", 0)
    monkeypatch.undo()
    assert (error.code, error.path) == (StorageErrorCode.STORAGE_UNAVAILABLE, "file:create")
    assert not hasattr(error, "errno") and error.__context__ is None
    assert seen == [("seg-0.jsonl", True, True, True, CREATE_DFD)]


# --- POSIX native ---------------------------------------------------------------------------------------------


@pytest.fixture
def audit_root():
    import shutil
    import tempfile

    home = os.path.realpath(os.path.expanduser("~"))
    base = tempfile.mkdtemp(prefix="rig-c2d-", dir=home)
    os.chmod(base, 0o700)
    yield base
    for directory, _, _ in os.walk(base):
        with contextlib.suppress(OSError):
            os.chmod(directory, 0o700)
    shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def chain(audit_root):
    with AuditDirectory.open(audit_root) as audit:
        directory = audit.open_chain(CHAIN, create=True)
    yield directory, os.path.join(audit_root, CHAIN)
    directory.close()
    sp._HELD_LOCKS.clear()


HELPER = r"""
import os, sys
from rig_sentinel.audit.safepath import AuditDirectory
from rig_sentinel.audit.storage_errors import StorageError, StorageErrorCode
mode, root, name = sys.argv[1], sys.argv[2], sys.argv[3]
with AuditDirectory.open(root) as audit:
    chain = audit.open_chain(name)
try:
    lock = chain.acquire_writer_lock()
except StorageError as error:
    print("LOCKED" if error.code is StorageErrorCode.LOCKED else "ERROR " + error.code.value, flush=True)
    sys.exit(3 if error.code is StorageErrorCode.LOCKED else 4)
print("HELD", flush=True)
if mode == "hold":
    sys.stdin.read()
elif mode == "exit-holding":
    os._exit(0)
lock.release()
"""

LOCKF_HELPER = r"""
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR | os.O_NOFOLLOW)
fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
print("HELD", flush=True)
sys.stdin.read()
"""

FORK_HELPER = r"""
import os, sys
from rig_sentinel.audit import safepath as sp
from rig_sentinel.audit.safepath import AuditDirectory, LockState
from rig_sentinel.audit.storage_errors import StorageError, StorageErrorCode
mode, root, name = sys.argv[1], sys.argv[2], sys.argv[3]
with AuditDirectory.open(root) as audit:
    chain = audit.open_chain(name)
lock = chain.acquire_writer_lock()
numbers = (lock._fd, lock._dfd)


def closed(number):
    try:
        os.fstat(number)
    except OSError:
        return True
    return False


def child_ok():
    if mode == "nohook":
        if lock.state is not LockState.HELD or lock.held or any(closed(n) for n in numbers):
            return False
    elif lock.state is not LockState.INHERITED or lock.held or not all(closed(n) for n in numbers):
        return False
    try:
        lock.verify_held()
        return False
    except StorageError as error:
        if error.code is not StorageErrorCode.LOCK_INVALID or error.path != "lock:forked":
            return False
    lock.release()
    return lock.state is LockState.INHERITED and all(closed(n) for n in numbers)


def locked_out():
    try:
        chain.acquire_writer_lock().release()
    except StorageError as error:
        return error.code is StorageErrorCode.LOCKED
    return False


if mode == "nohook":
    sp._invalidate_inherited_locks = lambda: None
ready_r, ready_w = os.pipe()
go_r, go_w = os.pipe()
pid = os.fork()
if pid == 0:
    result = 8
    try:
        os.close(ready_r)
        os.close(go_w)
        result = 0 if child_ok() else 7
        os.write(ready_w, b"r")
        os.read(go_r, 1)
    finally:
        os._exit(result)
os.close(ready_w)
os.close(go_r)
problems = []
try:
    if os.read(ready_r, 1) != b"r":
        problems.append("child not ready")
    if not lock.held:
        problems.append("parent lost the lock")
    lock.verify_held()
    if mode == "release-while-child":
        lock.release()
        try:
            chain.acquire_writer_lock().release()  # the child's copy was closed by the hook
        except StorageError as error:
            problems.append("re-acquire failed: " + error.code.value)
    else:
        if not locked_out():
            problems.append("lock not held while the parent holds it")
finally:
    os.close(go_w)
    _, status = os.waitpid(pid, 0)
if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
    problems.append("child status " + str(status))
if mode != "release-while-child":
    lock.release()
    if locked_out():
        problems.append("lock still held after release")
print("OK" if not problems else "FAIL " + "; ".join(problems), flush=True)
sys.exit(0 if not problems else 9)
"""


def _command(code, *args):
    return [sys.executable, "-W", "error", "-c", code, *args]


def _run(code, *args):
    return subprocess.run(_command(code, *args), capture_output=True, text=True, timeout=WAIT,
                          stdin=subprocess.DEVNULL)


def _read_line(proc):
    import select

    fd = proc.stdout.fileno()
    data = b""
    deadline = time.monotonic() + WAIT
    while not data.endswith(b"\n"):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            break
        chunk = os.read(fd, 1)
        if not chunk:
            break
        data += chunk
    return data.decode("ascii", "replace").strip()


@contextlib.contextmanager
def _holder(code, *args):
    proc = subprocess.Popen(_command(code, *args), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        yield proc, _read_line(proc)
    finally:
        with contextlib.suppress(OSError):
            proc.stdin.close()
        try:
            proc.wait(timeout=WAIT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=WAIT)
        proc.stdout.close()
        proc.stderr.close()


def _wrap_flock(monkeypatch, before):
    real = sp.fcntl.flock
    calls = []

    def flock(fd, operation):
        calls.append(operation)
        before()
        return real(fd, operation)

    monkeypatch.setattr(sp.fcntl, "flock", flock)
    assert sp._lock_capable()  # fault injection never trips the capability probe (C2-C H3 lesson)
    return calls


@posix_only
def test_posix_same_process_independent_opens_contend(chain):
    directory, path = chain
    first = directory.acquire_writer_lock()
    assert first.held and first.state is LockState.HELD
    assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.LOCKED, "lock:held")
    first.verify_held()
    first.release()
    second = directory.acquire_writer_lock()
    assert second.held
    second.release()


@posix_only
def test_posix_lifecycle_and_context_manager(chain):
    directory, path = chain
    with directory.acquire_writer_lock() as lock:
        lock.verify_held()
    assert lock.state is LockState.RELEASED and not lock.held
    assert pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, "lock:released")
    lock.release()
    assert lock.state is LockState.RELEASED
    directory.acquire_writer_lock().release()


@posix_only
def test_posix_cross_process_contention(chain, audit_root):
    directory, path = chain
    with _holder(HELPER, "hold", audit_root, CHAIN) as (proc, line):
        assert line == "HELD"
        assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.LOCKED, "lock:held")
    assert proc.returncode == 0
    with directory.acquire_writer_lock() as lock:
        result = _run(HELPER, "try", audit_root, CHAIN)
        assert (result.returncode, result.stdout.strip()) == (3, "LOCKED")
        lock.verify_held()
    result = _run(HELPER, "try", audit_root, CHAIN)
    assert (result.returncode, result.stdout.strip()) == (0, "HELD")


@posix_only
def test_posix_lock_is_released_when_the_holder_is_killed(chain, audit_root):
    import signal

    directory, path = chain
    with _holder(HELPER, "hold", audit_root, CHAIN) as (proc, line):
        assert line == "HELD"
        assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.LOCKED, "lock:held")
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=WAIT)
        with directory.acquire_writer_lock() as lock:
            assert lock.held
    assert proc.returncode == -signal.SIGKILL


@posix_only
def test_posix_lock_is_released_when_the_holder_exits_without_release(chain, audit_root):
    directory, path = chain
    result = _run(HELPER, "exit-holding", audit_root, CHAIN)
    assert (result.returncode, result.stdout.strip()) == (0, "HELD")
    with directory.acquire_writer_lock() as lock:
        assert lock.held


@posix_only
def test_posix_symlink_at_the_lock_name_is_refused(chain):
    directory, path = chain
    target = os.path.join(path, "seg-0.jsonl")
    with open(target, "wb"):
        pass
    os.chmod(target, 0o600)
    os.symlink("seg-0.jsonl", os.path.join(path, LOCK_NAME))
    assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.UNSAFE_PATH, "lock:open")
    assert os.path.islink(os.path.join(path, LOCK_NAME)) and os.path.getsize(target) == 0


@posix_only
def test_posix_lock_descriptors_are_read_only_and_close_on_exec(chain):
    import fcntl

    directory, path = chain
    with directory.acquire_writer_lock() as lock:
        for number in (lock._fd, lock._dfd):
            assert fcntl.fcntl(number, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        assert fcntl.fcntl(lock._fd, fcntl.F_GETFL) & getattr(os, "O_ACCMODE", 3) == os.O_RDONLY
        probe = "import os, sys\ntry:\n    os.fstat(int(sys.argv[1]))\nexcept OSError:\n    sys.exit(0)\nsys.exit(5)"
        for number in (lock._fd, lock._dfd):
            result = subprocess.run([sys.executable, "-c", probe, str(number)], close_fds=False, timeout=WAIT,
                                    stdin=subprocess.DEVNULL, capture_output=True)
            assert result.returncode == 0  # not inherited across exec


@posix_only
def test_posix_hard_linked_lock_file_is_refused(chain):
    directory, path = chain
    directory.acquire_writer_lock().release()
    lock_path = os.path.join(path, LOCK_NAME)
    os.link(lock_path, os.path.join(path, "seg-9.jsonl"))
    assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.FILE_UNSAFE, "lock:links")
    assert os.stat(lock_path).st_nlink == 2


@posix_only
@pytest.mark.parametrize("kind", ["fifo", "directory"])
def test_posix_wrong_file_types_are_refused_without_blocking(chain, kind):
    import signal

    directory, path = chain
    lock_path = os.path.join(path, LOCK_NAME)
    if kind == "fifo":
        os.mkfifo(lock_path, 0o600)
    else:
        os.mkdir(lock_path, 0o700)

    def timed_out(signum, frame):
        raise TimeoutError("lock acquisition blocked")

    previous = signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(10)
    try:
        assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.FILE_UNSAFE, "lock:type")
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


@posix_only
@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o606])
def test_posix_unsafe_modes_are_refused_and_never_repaired(chain, mode):
    directory, path = chain
    directory.acquire_writer_lock().release()
    lock_path = os.path.join(path, LOCK_NAME)
    os.chmod(lock_path, mode)
    assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.FILE_UNSAFE, "lock:permissions")
    assert stat.S_IMODE(os.stat(lock_path).st_mode) == mode


@posix_only
@pytest.mark.parametrize("umask", [0o000, 0o022, 0o077, 0o277])  # 0o277: only fchmod restores 0o600
def test_posix_created_lock_file_is_empty_and_private(chain, umask):
    directory, path = chain
    previous = os.umask(umask)
    try:
        directory.acquire_writer_lock().release()
    finally:
        os.umask(previous)
    info = os.stat(os.path.join(path, LOCK_NAME))
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0 and info.st_nlink == 1


@posix_only
def test_posix_non_empty_lock_file_is_refused_and_never_truncated(chain):
    directory, path = chain
    directory.acquire_writer_lock().release()
    lock_path = os.path.join(path, LOCK_NAME)
    with open(lock_path, "ab") as handle:
        handle.write(b"pid=1\n")
    assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.FILE_UNSAFE, "lock:size")
    with open(lock_path, "rb") as handle:
        assert handle.read() == b"pid=1\n"


@posix_only
def test_posix_growth_after_acquisition_invalidates(chain):
    directory, path = chain
    lock = directory.acquire_writer_lock()
    with open(os.path.join(path, LOCK_NAME), "ab") as handle:
        handle.write(b"x")
    assert pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, "lock:size")
    assert lock.state is LockState.INVALID and lock._fd is None and lock._dfd is None


@posix_only
def test_posix_substitution_before_flock_is_detected(chain, monkeypatch):
    directory, path = chain
    directory.acquire_writer_lock().release()
    lock_path = os.path.join(path, LOCK_NAME)

    def substitute():
        os.rename(lock_path, os.path.join(path, "seg-7.jsonl"))
        with open(lock_path, "wb"):
            pass
        os.chmod(lock_path, 0o600)

    calls = _wrap_flock(monkeypatch, substitute)
    assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.LOCK_INVALID, "lock:substituted")
    assert len(calls) == 1 and sp._HELD_LOCKS == {}
    monkeypatch.undo()
    assert os.path.getsize(lock_path) == 0  # the planted file is untouched
    with directory.acquire_writer_lock() as lock:  # nothing left locked by the failed attempt
        assert lock.held


@posix_only
def test_posix_descriptor_change_before_flock_is_detected(chain, monkeypatch):
    directory, path = chain
    directory.acquire_writer_lock().release()
    lock_path = os.path.join(path, LOCK_NAME)

    def grow():
        with open(lock_path, "ab") as handle:
            handle.write(b"x")

    _wrap_flock(monkeypatch, grow)
    assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.LOCK_INVALID, "lock:size")


@posix_only
def test_posix_substitution_after_acquisition_is_detected_not_prevented(chain):
    directory, path = chain
    lock = directory.acquire_writer_lock()
    lock_path = os.path.join(path, LOCK_NAME)
    os.rename(lock_path, os.path.join(path, "seg-8.jsonl"))
    with open(lock_path, "wb"):
        pass
    os.chmod(lock_path, 0o600)
    with directory.acquire_writer_lock() as second:  # advisory: a second writer can lock the new inode
        assert second.held
        assert pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, "lock:substituted")  # detected later
    assert lock.state is LockState.INVALID and lock._fd is None


@posix_only
def test_posix_hard_link_after_acquisition_is_detected(chain):
    directory, path = chain
    lock = directory.acquire_writer_lock()
    os.link(os.path.join(path, LOCK_NAME), os.path.join(path, "seg-6.jsonl"))
    assert pair_of(lock.verify_held) == (StorageErrorCode.LOCK_INVALID, "lock:links")
    assert lock.state is LockState.INVALID


@posix_only
@pytest.mark.parametrize("mode", ["hook", "release-while-child", "nohook"])
def test_posix_fork_child_never_owns_the_lock(chain, audit_root, mode):
    result = _run(FORK_HELPER, mode, audit_root, CHAIN)
    assert (result.returncode, result.stdout.strip()) == (0, "OK"), result.stdout + result.stderr


@posix_only
@non_root
def test_posix_create_denied_is_permission_denied(chain):
    directory, path = chain
    os.chmod(path, 0o500)
    try:
        assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.PERMISSION_DENIED, "lock:create-denied")
    finally:
        os.chmod(path, 0o700)
    assert not os.path.lexists(os.path.join(path, LOCK_NAME))


@posix_only
@non_root
def test_posix_open_denied_is_permission_denied_not_contention(chain):
    directory, path = chain
    directory.acquire_writer_lock().release()
    lock_path = os.path.join(path, LOCK_NAME)
    os.chmod(lock_path, 0o000)
    try:
        assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.PERMISSION_DENIED, "lock:open-denied")
    finally:
        os.chmod(lock_path, 0o600)


def _plant_after_first_missing_open(monkeypatch, plant):
    """Native EEXIST race: ``plant`` runs right after the first open found no lock file, before the create."""
    real = sp._posix_open_lock_fd
    planted = []

    def open_then_plant(dfd):
        try:
            return real(dfd)
        except FileNotFoundError:
            if not planted:
                plant()
                planted.append(1)
            raise

    monkeypatch.setattr(sp, "_posix_open_lock_fd", open_then_plant)
    return planted


@posix_only
def test_posix_symlink_planted_before_create_is_never_followed(chain, monkeypatch):
    directory, path = chain
    lock_path = os.path.join(path, LOCK_NAME)
    target = os.path.join(path, "seg-1.jsonl")
    with open(target, "wb"):
        pass
    os.chmod(target, 0o600)
    planted = _plant_after_first_missing_open(monkeypatch, lambda: os.symlink("seg-1.jsonl", lock_path))
    # The exclusive create meets the symlink (EEXIST, never followed); the single re-open refuses it.
    assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.UNSAFE_PATH, "lock:open")
    assert planted == [1] and os.path.islink(lock_path) and sp._HELD_LOCKS == {}
    info = os.stat(target)
    assert info.st_size == 0 and stat.S_IMODE(info.st_mode) == 0o600  # the target was never touched


@posix_only
def test_posix_unsafe_file_planted_before_create_is_refused_and_kept(chain, monkeypatch):
    directory, path = chain
    lock_path = os.path.join(path, LOCK_NAME)

    def plant():
        with open(lock_path, "wb") as handle:
            handle.write(b"planted")
        os.chmod(lock_path, 0o644)

    _plant_after_first_missing_open(monkeypatch, plant)
    assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.FILE_UNSAFE, "lock:permissions")
    info = os.stat(lock_path)
    assert stat.S_IMODE(info.st_mode) == 0o644 and info.st_size == 7  # never repaired, never deleted


class OneShotFchmod:
    """Deterministic fchmod fault injection for native tests.

    ``sp.os`` is the real ``os`` module, so the patch is process-wide; it is therefore installed only with
    ``monkeypatch.context()`` around a single acquisition, and it acts exactly once: on its first call, which
    must be ``fchmod(<the newly created lock file>, 0o600)``. Any later call goes to the real function. Every
    call is recorded so the test can assert the injection happened once, where intended.
    """

    def __init__(self, real, lock_path, action):
        self.real = real
        self.lock_path = lock_path
        self.action = action
        self.calls = []

    def __call__(self, fd, mode):
        first = not self.calls
        self.calls.append((os.fstat(fd).st_ino, mode))
        if first:
            assert os.path.samestat(os.fstat(fd), os.stat(self.lock_path, follow_symlinks=False))
            return self.action(fd, mode, self.real)
        return self.real(fd, mode)


def test_native_fchmod_fault_injection_is_one_shot_and_targeted(tmp_path):
    """Portable check of the native tests' injection helper (the native tests themselves run on POSIX CI)."""
    target = tmp_path / "lock"
    target.write_bytes(b"")
    other = tmp_path / "other"
    other.write_bytes(b"")
    fd = os.open(str(target), os.O_RDONLY)
    foreign = os.open(str(other), os.O_RDONLY)
    seen = []
    try:
        injected = OneShotFchmod(lambda f, m: seen.append(("real", m)), str(target),
                                 lambda f, m, real: seen.append(("action", m)))
        injected(fd, 0o600)
        injected(fd, 0o644)
        assert seen == [("action", 0o600), ("real", 0o644)] and len(injected.calls) == 2
        stray = OneShotFchmod(lambda f, m: None, str(target), lambda f, m, real: None)
        with pytest.raises(AssertionError):
            stray(foreign, 0o600)  # the first call must be on the lock file itself
    finally:
        os.close(fd)
        os.close(foreign)


def _acquire_with_fchmod_fault(monkeypatch, directory, lock_path, action):
    real = os.fchmod
    injected = OneShotFchmod(real, lock_path, action)
    with monkeypatch.context() as scoped:
        scoped.setattr(sp.os, "fchmod", injected)
        result = pair_of(directory.acquire_writer_lock)
    assert os.fchmod is real and sp.os.fchmod is real  # restored before anything else runs
    assert len(injected.calls) == 1 and injected.calls[0][1] == 0o600  # injected once, at the creator's fchmod
    return result, injected.calls[0][0]


@posix_only
def test_posix_substitution_right_after_create_is_detected_and_the_foreign_file_kept(chain, monkeypatch):
    directory, path = chain
    lock_path = os.path.join(path, LOCK_NAME)
    moved = os.path.join(path, "seg-2.jsonl")

    def swap_then_chmod(fd, mode, real):
        os.rename(lock_path, moved)  # our new file leaves the name ...
        with open(lock_path, "wb") as handle:  # ... and a foreign file takes it
            handle.write(b"foreign")
        return real(fd, mode)

    result, created_inode = _acquire_with_fchmod_fault(monkeypatch, directory, lock_path, swap_then_chmod)
    assert result == (StorageErrorCode.FILE_UNSAFE, "lock:changed")
    with open(lock_path, "rb") as handle:
        assert handle.read() == b"foreign"  # cleanup is identity-bound: the foreign file is never deleted
    assert os.stat(moved).st_ino == created_inode and sp._HELD_LOCKS == {}  # ours: moved away, never touched


@posix_only
def test_posix_fchmod_failure_after_create_removes_only_our_file(chain, monkeypatch):
    """Native create, INJECTED fchmod failure (EIO cannot be produced on demand)."""
    directory, path = chain
    lock_path = os.path.join(path, LOCK_NAME)

    def failing_fchmod(fd, mode, real):
        raise OSError(errno.EIO, "injected")

    result, _ = _acquire_with_fchmod_fault(monkeypatch, directory, lock_path, failing_fchmod)
    assert result == (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create-verify")
    assert not os.path.lexists(lock_path)  # our own new file was removed
    with directory.acquire_writer_lock() as lock:  # and the next attempt (real fchmod) creates it normally
        assert lock.held


@posix_only
def test_posix_lock_file_is_never_removed_or_written(chain, audit_root):
    import signal

    directory, path = chain
    directory.acquire_writer_lock().release()
    lock_path = os.path.join(path, LOCK_NAME)
    inode = os.stat(lock_path).st_ino
    for _ in range(3):
        with directory.acquire_writer_lock() as lock:
            lock.verify_held()
    lock = directory.acquire_writer_lock()
    os.link(lock_path, os.path.join(path, "seg-5.jsonl"))
    error_of(lock.verify_held)
    os.unlink(os.path.join(path, "seg-5.jsonl"))
    with _holder(HELPER, "hold", audit_root, CHAIN) as (proc, line):
        assert line == "HELD"
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=WAIT)
    info = os.stat(lock_path)
    assert (info.st_ino, info.st_size, info.st_nlink, stat.S_IMODE(info.st_mode)) == (inode, 0, 1, 0o600)


# --- Linux native ---------------------------------------------------------------------------------------------


@linux_only
@non_root
def test_linux_no_descriptor_leaks_on_any_path(chain, monkeypatch):
    directory, path = chain
    lock_path = os.path.join(path, LOCK_NAME)

    def count():
        return len(os.listdir("/proc/self/fd"))

    directory.acquire_writer_lock().release()
    before = count()
    for _ in range(3):
        with directory.acquire_writer_lock() as lock:  # acquire, verify, release
            lock.verify_held()
            assert pair_of(directory.acquire_writer_lock)[0] is StorageErrorCode.LOCKED  # contention
        for mode in (0o640, 0o000):  # post-open rejection, and open denial
            os.chmod(lock_path, mode)
            error_of(directory.acquire_writer_lock)
        os.chmod(lock_path, 0o600)
        os.link(lock_path, os.path.join(path, "seg-4.jsonl"))  # post-open rejection: links
        error_of(directory.acquire_writer_lock)
        os.unlink(os.path.join(path, "seg-4.jsonl"))
        with open(lock_path, "ab") as handle:  # post-open rejection: size
            handle.write(b"x")
        error_of(directory.acquire_writer_lock)
        os.truncate(lock_path, 0)
        lock = directory.acquire_writer_lock()  # failed verification closes everything
        os.link(lock_path, os.path.join(path, "seg-4.jsonl"))
        error_of(lock.verify_held)
        os.unlink(os.path.join(path, "seg-4.jsonl"))
        lock.release()
        assert count() == before
    os.unlink(lock_path)  # test-only: exercise the denied-create path
    os.chmod(path, 0o500)
    try:
        assert pair_of(directory.acquire_writer_lock)[0] is StorageErrorCode.PERMISSION_DENIED
    finally:
        os.chmod(path, 0o700)
    assert count() == before
    directory.acquire_writer_lock().release()  # recreated by the lock itself

    def substitute():
        os.rename(lock_path, os.path.join(path, "seg-3.jsonl"))
        with open(lock_path, "wb"):
            pass
        os.chmod(lock_path, 0o600)

    _wrap_flock(monkeypatch, substitute)  # post-flock rejection
    error_of(directory.acquire_writer_lock)
    monkeypatch.undo()
    assert count() == before


@linux_only
def test_linux_create_failures_leak_no_descriptors(chain, monkeypatch):
    directory, path = chain
    lock_path = os.path.join(path, LOCK_NAME)
    moved = os.path.join(path, "seg-2.jsonl")

    def count():
        return len(os.listdir("/proc/self/fd"))

    def failing_fchmod(fd, mode, real):
        raise OSError(errno.EIO, "injected")

    def swap_then_chmod(fd, mode, real):
        os.rename(lock_path, moved)
        with open(lock_path, "wb"):
            pass
        os.chmod(lock_path, 0o600)
        return real(fd, mode)

    before = count()
    for _ in range(3):
        result, _ = _acquire_with_fchmod_fault(monkeypatch, directory, lock_path, failing_fchmod)
        assert result[0] is StorageErrorCode.STORAGE_UNAVAILABLE and not os.path.lexists(lock_path)
        result, _ = _acquire_with_fchmod_fault(monkeypatch, directory, lock_path, swap_then_chmod)
        assert result == (StorageErrorCode.FILE_UNSAFE, "lock:changed")
        os.unlink(lock_path)  # test-only reset of both planted names
        os.unlink(moved)
        assert count() == before
    with directory.acquire_writer_lock() as lock:
        assert lock.held
    assert count() == before


@linux_only
def test_linux_flock_and_fcntl_locks_do_not_interact(chain):
    directory, path = chain
    directory.acquire_writer_lock().release()
    with _holder(LOCKF_HELPER, os.path.join(path, LOCK_NAME)) as (proc, line):
        assert line == "HELD"
        with directory.acquire_writer_lock() as lock:  # Linux: flock and fcntl locks are independent
            assert lock.held


# --- macOS native ---------------------------------------------------------------------------------------------


@macos_only
def test_macos_flock_and_fcntl_locks_interact_and_fail_closed(chain):
    directory, path = chain
    directory.acquire_writer_lock().release()
    with _holder(LOCKF_HELPER, os.path.join(path, LOCK_NAME)) as (proc, line):
        assert line == "HELD"
        assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.LOCKED, "lock:held")
    with directory.acquire_writer_lock() as lock:
        assert lock.held


@macos_only
@non_root
def test_macos_acl_denied_create_is_permission_denied(chain):
    """A real ACL denial (macOS deny entries apply to the owner) while the mode bits allow creation.

    DV-H1-1 Option A: the create's actual EACCES is classified, so the answer is PERMISSION_DENIED even
    though the directory mode bits alone would allow the create. Nothing is created, nothing is locked.
    """
    import pwd

    directory, path = chain
    user = pwd.getpwuid(os.geteuid()).pw_name
    added = subprocess.run(["/bin/chmod", "+a", "user:" + user + " deny add_file", path], capture_output=True,
                           timeout=WAIT, stdin=subprocess.DEVNULL)
    assert added.returncode == 0, added.stderr
    try:
        assert stat.S_IMODE(os.stat(path).st_mode) & 0o300 == 0o300  # the mode bits alone would allow it
        assert pair_of(directory.acquire_writer_lock) == (StorageErrorCode.PERMISSION_DENIED, "lock:create-denied")
    finally:
        subprocess.run(["/bin/chmod", "-N", path], capture_output=True, timeout=WAIT, stdin=subprocess.DEVNULL)
    assert not os.path.lexists(os.path.join(path, LOCK_NAME)) and sp._HELD_LOCKS == {}
    with directory.acquire_writer_lock() as lock:  # once the ACL is gone the lock works
        assert lock.held


# --- NTFS native: Windows refuses before any filesystem I/O -----------------------------------------------------


@pytest.fixture
def ntfs_base():
    import tempfile

    return tempfile.mkdtemp(prefix="c2d-", dir=NTFS_DIR)


@ntfs_only
def test_ntfs_writer_lock_is_refused_before_any_io(ntfs_base):
    root = os.path.join(ntfs_base, "audit")
    os.mkdir(root)
    os.mkdir(os.path.join(root, CHAIN))
    before = os.stat(os.path.join(root, CHAIN)).st_mtime_ns
    with AuditDirectory.open(root, windows_attestation=ATTESTED) as audit, audit.open_chain(CHAIN) as chain:
        with no_os_calls() as calls:  # refused before any os call, so before any filesystem write
            problem = pair_of(chain.acquire_writer_lock)
        assert problem == (StorageErrorCode.UNSUPPORTED_PLATFORM, "file:write-windows") and calls == []
    assert os.listdir(os.path.join(root, CHAIN)) == []
    assert os.stat(os.path.join(root, CHAIN)).st_mtime_ns == before
    assert "msvcrt" not in vars(sp)
