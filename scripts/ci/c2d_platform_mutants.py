"""Run the C2-D (writer lock) mutants: portable, POSIX-native, Linux-native or NTFS-native profile.

Usage: python scripts/ci/c2d_platform_mutants.py --profile {portable,posix,linux,ntfs}

Each mutant weakens one control in a temporary copy of src/ and runs tests/test_audit_c2d_writer_lock.py
against it; every mutant must make the tests fail. The repository is never modified. Every mutant must
apply exactly once. A missing platform exits 2 ("unsupported, not a success"); a timeout counts as a failure
of the run. Independent of c2b_platform_mutants.py and c2c_platform_mutants.py (their profiles, tests and
control runs are unchanged). Standard library only; synthetic data only.

Mutants 1-34 follow the approved C2-D v2 plan (section 5); where an approved case does not apply to the
implementation, the substitute is named in its description. Mutants 35-44 are additional (H1); mutants
45-57 target the error-handling and descriptor-ownership paths reviewed in H2; 40-42, 57 and 40n were
retargeted and 58-69 added for the dedicated lock-file creator (DV-H1-1 Option A); 70, 72-74 and 74n cover
the distinct post-create error paths (Gemini A/B reconciliation; 71 intentionally unused). Child runs never inherit
PYTEST_ADDOPTS, PYTEST_PLUGINS, PYTHONSTARTUP or PYTHONINSPECT, and copies of src/ never carry bytecode.
"""

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
NL = "\n"
TEST = "tests/test_audit_c2d_writer_lock.py"
TIMEOUT = 900

FLOCK_CALL = "            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[union-attr]"
OPEN_FLAGS = ("    lock_flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, \"O_NOCTTY\", 0)" + NL
              + "                  | getattr(os, \"O_NONBLOCK\", 0))")
OPEN_CALL = "    return os.open(_WRITER_LOCK_NAME, lock_flags, dir_fd=dfd)"
INHERIT = "        if self._state is LockState.HELD:" + NL + "            self._state = LockState.INHERITED" + NL \
    + "        self._close_fds()"
VERIFY_PID = ("        if os.getpid() != self._owner:" + NL
              + "            self._end(LockState.INHERITED)  # closes this process's inherited copies only")
RELEASE_END = "            return" + NL + "        self._end(LockState.RELEASED)"
LABEL_RETURN = "        if label is not None:" + NL + "            return (StorageErrorCode.FILE_UNSAFE, label)"
DUP_CALL = "        lock = WriterLock(_dfd=self._dup_dir())"
DUP_FAIL = ("            return os.dup(self._fd)  # type: ignore[arg-type]" + NL + "        except OSError:" + NL
            + "            pass" + NL + "        raise _fail(StorageErrorCode.STORAGE_UNAVAILABLE, \"directory:dup\")")
FLOCK_DENIED = ("    if number in (errno.EACCES, errno.EPERM):" + NL
                + "        return (StorageErrorCode.STORAGE_UNAVAILABLE, \"lock:flock-denied\")")
CLOSE_BOTH = "        _close_quietly(lock_fd)" + NL + "        _close_quietly(dir_fd)"
REOPEN = ("        return _posix_open_lock_fd(dfd), None" + NL + "    except OSError as error:" + NL
          + "        return None, _lock_open_problem(error)")
RELEASE_CHILD = "            self._end(LockState.INHERITED)" + NL + "            return"
# DV-H1-1 Option A: the dedicated, errno-aware creator
CREATE_DENIED = ("    if number in (errno.EACCES, errno.EPERM):" + NL
                 + "        return (StorageErrorCode.PERMISSION_DENIED, \"lock:create-denied\")")
CREATE_FLAGS = "    create_flags = (os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC"
CREATE_LINK = "    if number in (errno.ELOOP, getattr(errno, \"EMLINK\", -1), errno.ENOTDIR):  # a link or non-directory"
CREATE_EXISTS = "        if error.errno == errno.EEXIST:" + NL + "            return None"
CREATE_CHMOD = "        os.fchmod(lock_fd, 0o600)" + NL
CREATE_LABEL = "        label = _lock_file_label(os.fstat(lock_fd), owner)"
CREATE_IDENTITY = "        elif _identity(_named_identity(dfd, _WRITER_LOCK_NAME)) != created:"
CREATE_CLEANUP = ("    if problem is not None and created is not None:" + NL
                  + "        _posix_unlink_if_ours(dfd, _WRITER_LOCK_NAME, lock_fd, created)")
CREATE_CLOSE = "    _close_quietly(lock_fd)" + NL + "    return problem"
CREATE_RAISE = "        _close_quietly(lock_fd)" + NL + "        raise"
POST_CREATE_OSERROR = ("    except OSError:" + NL
                       + "        problem = (StorageErrorCode.STORAGE_UNAVAILABLE, \"lock:create-verify\")")
POST_CREATE_VANISHED = ("    except FileNotFoundError:" + NL
                        + "        problem = (StorageErrorCode.FILE_UNSAFE, \"lock:changed\")  # our new name vanished")
CREATE_ORDER = ("        created = _identity(os.fstat(lock_fd))  # first, so every later failure removes only this file" + NL
                + "        os.fchmod(lock_fd, 0o600)")
CREATE_FALLBACK = "    return (StorageErrorCode.STORAGE_UNAVAILABLE, \"lock:create\")  # ENOSPC, EDQUOT, EROFS, EIO and anything unknown"

# Mutants caught by portable and mocked tests (any host). Listed in approved order where applicable.
PORTABLE = [
    ("01 LOCK_NB removed (blocking acquisition)", FLOCK_CALL,
     "            fcntl.flock(fd, fcntl.LOCK_EX)  # type: ignore[union-attr]"),
    ("02 LOCK_EX replaced by LOCK_SH", FLOCK_CALL,
     "            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)  # type: ignore[union-attr]"),
    ("03 flock replaced by a record lock (lockf)", FLOCK_CALL,
     "            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[union-attr]"),
    ("07 S_ISREG check removed", "    if not stat.S_ISREG(st.st_mode):" + NL + "        return \"lock:type\"",
     "    if False:" + NL + "        return \"lock:type\""),
    ("08 link-count check removed (open)", "    if st.st_nlink != 1:" + NL + "        return \"lock:links\"",
     "    if False:" + NL + "        return \"lock:links\""),
    ("09 owner/mode check removed", "    if st.st_uid != uid or (st.st_mode & 0o077) != 0:", "    if False:"),
    ("10 size == 0 check removed", "    if st.st_size != 0:" + NL + "        return \"lock:size\"",
     "    if False:" + NL + "        return \"lock:size\""),
    ("11 (substitute for fchmod removed: creation uses the C2-C primitive) lock descriptor opened read-write",
     OPEN_FLAGS, OPEN_FLAGS.replace("os.O_RDONLY | os.O_NOFOLLOW", "os.O_RDWR | os.O_NOFOLLOW")),
    ("12 post-lock pathname identity not compared",
     "    if _identity(named) != locked or not stat.S_ISREG(named.st_mode):" + NL + "        return \"lock:substituted\"",
     "    if False:" + NL + "        return \"lock:substituted\""),
    ("13 post-lock descriptor re-validation removed",
     "    if descriptor_label is not None:" + NL + "        return descriptor_label",
     "    if False:" + NL + "        return descriptor_label"),
    ("14 verify_held identity re-check skipped",
     "        label = _held_lock_problem(self._fd, self._dfd, self._locked, os.geteuid())",
     "        label = None and _held_lock_problem(self._fd, self._dfd, self._locked, os.geteuid())"),
    ("15 verify_held pathname link count not checked",
     "    if named.st_nlink != 1:" + NL + "        return \"lock:links\"",
     "    if False:" + NL + "        return \"lock:links\""),
    ("16 post-lock check skipped at acquisition",
     "        after = _held_lock_problem(fd, dfd, self._locked, uid)  # type: ignore[arg-type]",
     "        after = None  # type: ignore[arg-type]"),
    ("17 owner-pid check removed from verify_held", VERIFY_PID,
     "        if False:" + NL + "            self._end(LockState.INHERITED)  # closes this process's inherited copies only"),
    ("18 at-fork hook not registered", "    os.register_at_fork(after_in_child=_after_fork_in_child)", "    pass"),
    ("19 fork hook closes the lock fd but not the directory fd (H-1)", INHERIT,
     "        if self._state is LockState.HELD:" + NL + "            self._state = LockState.INHERITED" + NL
     + "        _close_quietly(self._fd)" + NL + "        self._fd = None"),
    ("20 fork hook closes the directory fd but not the lock fd (H-1)", INHERIT,
     "        if self._state is LockState.HELD:" + NL + "            self._state = LockState.INHERITED" + NL
     + "        _close_quietly(self._dfd)" + NL + "        self._dfd = None"),
    ("21 release unlinks the lock file", RELEASE_END,
     "            return" + NL + "        os.unlink(_WRITER_LOCK_NAME, dir_fd=self._dfd)  # type: ignore[arg-type]" + NL
     + "        self._end(LockState.RELEASED)"),
    ("22 release uses LOCK_UN and keeps the descriptors", RELEASE_END,
     "            return" + NL + "        fcntl.flock(self._fd, fcntl.LOCK_UN)  # type: ignore[union-attr]" + NL
     + "        self._state = LockState.RELEASED"),
    ("23 descriptors not closed when acquisition fails (contention and other problems)",
     "        if problem is not None:" + NL + "            lock._end(LockState.INVALID)" + NL + "            raise _fail(*problem)",
     "        if problem is not None:" + NL + "            raise _fail(*problem)"),
    ("24 lock descriptor not tracked, so a post-open rejection leaks it",
     "        self._fd = fd" + NL + "        try:" + NL + "            opened = os.fstat(fd)",
     "        try:" + NL + "            opened = os.fstat(fd)"),
    ("25 failed verify_held does not invalidate or close",
     "            self._end(LockState.INVALID)" + NL + "            raise _fail(StorageErrorCode.LOCK_INVALID, label)",
     "            raise _fail(StorageErrorCode.LOCK_INVALID, label)"),
    ("26 flock EACCES reported as contention (H-2)",
     "    if number in (errno.EWOULDBLOCK, errno.EAGAIN):",
     "    if number in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):"),
    ("27 open EACCES reported as a storage failure instead of PERMISSION_DENIED",
     "        return (StorageErrorCode.PERMISSION_DENIED, \"lock:open-denied\")",
     "        return (StorageErrorCode.STORAGE_UNAVAILABLE, \"lock:open-denied\")"),
    ("28 cleanup catches OSError only, not BaseException (M-2)",
     "        except BaseException:" + NL + "            lock._end(LockState.INVALID)",
     "        except OSError:" + NL + "            lock._end(LockState.INVALID)"),
    ("29 EINTR retried", FLOCK_CALL + NL + "        except OSError as error:",
     FLOCK_CALL + NL + "        except InterruptedError:" + NL + FLOCK_CALL + NL + "        except OSError as error:"),
    ("30 a terminal state can return to HELD (M-3)",
     "        if self._state in (LockState.NEW, LockState.HELD):" + NL + "            self._state = state",
     "        if True:" + NL + "            self._state = state"),
    ("31 Windows refusal skipped (capability check reached instead)",
     "        self._require_posix_write()" + NL + "        if not _lock_capable():",
     "        if not _lock_capable():"),
    ("32 missing-capability refusal removed",
     "        if not _lock_capable():" + NL + "            raise _fail(StorageErrorCode.UNSUPPORTED_PLATFORM, \"lock:platform\")",
     "        if False:" + NL + "            raise _fail(StorageErrorCode.UNSUPPORTED_PLATFORM, \"lock:platform\")"),
    ("33 _Guarded base removed from WriterLock", "class WriterLock(_Guarded):", "class WriterLock:"),
    ("34 existing unsafe lock file repaired with chmod", LABEL_RETURN,
     "        if label is not None:" + NL + "            os.fchmod(fd, 0o600)  # type: ignore[arg-type]" + NL
     + "            return (StorageErrorCode.FILE_UNSAFE, label)"),
    # Additional mutants (35+)
    ("35 capability probe ignores the presence of flock", "fcntl is not None and hasattr(fcntl, \"flock\")",
     "fcntl is not None and True"),
    ("36 descriptor identity not compared", "    if _identity(held) != locked:" + NL + "        return \"lock:changed\"",
     "    if False:" + NL + "        return \"lock:changed\""),
    ("37 unlinked lock (nlink 0) not reported as substituted",
     "    if held.st_nlink == 0:" + NL + "        return \"lock:substituted\"  # our inode lost its name",
     "    if False:" + NL + "        return \"lock:substituted\"  # our inode lost its name"),
    ("38 fork hook does not mark the child's view INHERITED", INHERIT,
     "        if self._state is LockState.HELD:" + NL + "            pass" + NL + "        self._close_fds()"),
    ("39 descriptor slots not cleared before closing (double close)",
     "        self._fd = None" + NL + "        self._dfd = None" + NL + "        _close_quietly(lock_fd)",
     "        _close_quietly(lock_fd)"),
    ("40 (Option A substitute) create EACCES / EPERM not reported as PERMISSION_DENIED", CREATE_DENIED,
     CREATE_DENIED.replace("    if number in (errno.EACCES, errno.EPERM):", "    if False:")),
    ("41 (Option A substitute) EEXIST from the exclusive create not tolerated", CREATE_EXISTS,
     "        if False:" + NL + "            return None"),
    ("42 (Option A substitute) create descriptor leaked after a successful create", CREATE_CLOSE, "    return problem"),
    ("43 held ignores the owner pid", "        return self._state is LockState.HELD and os.getpid() == self._owner",
     "        return self._state is LockState.HELD"),
    ("44 release in a non-owner process releases as owner",
     "        if os.getpid() != self._owner:" + NL + "            self._end(LockState.INHERITED)" + NL + "            return",
     "        if False:" + NL + "            self._end(LockState.INHERITED)" + NL + "            return"),
    # H2 (Gemini ACCEPT WITH FIXES): targeted error-handling and descriptor-ownership mutants (45+)
    ("45 lock uses the chain directory's own descriptor instead of a private copy", DUP_CALL,
     "        lock = WriterLock(_dfd=self._fd)  # type: ignore[arg-type]"),
    ("46 directory dup failure ignored (acquisition continues)", DUP_FAIL,
     DUP_FAIL.replace("        raise _fail(StorageErrorCode.STORAGE_UNAVAILABLE, \"directory:dup\")", "        return -1")),
    ("47 flock ENOLCK not classified", "    if number == errno.ENOLCK:", "    if False:"),
    ("48 flock EINTR not classified", "    if number == errno.EINTR:", "    if False:"),
    ("49 flock EPERM not treated as a denial", FLOCK_DENIED, FLOCK_DENIED.replace(", errno.EPERM)", ",)")),
    ("50 flock EOPNOTSUPP / ENOTSUP not classified as an unsupported filesystem",
     "    if number in (getattr(errno, \"EOPNOTSUPP\", -1), getattr(errno, \"ENOTSUP\", -1)):", "    if False:"),
    ("51 lock open ENXIO / EISDIR not classified as a wrong file type",
     "    if number in (errno.ENXIO, errno.EISDIR):" + NL + "        return (StorageErrorCode.FILE_UNSAFE, \"lock:type\")",
     "    if False:" + NL + "        return (StorageErrorCode.FILE_UNSAFE, \"lock:type\")"),
    ("52 lock open ELOOP not classified as an unsafe path",
     "    if number in (errno.ELOOP, getattr(errno, \"EMLINK\", -1)):" + NL
     + "        return (StorageErrorCode.UNSAFE_PATH, \"lock:open\")",
     "    if False:" + NL + "        return (StorageErrorCode.UNSAFE_PATH, \"lock:open\")"),
    ("53 closing the lock leaves the private directory copy open", CLOSE_BOTH,
     "        _close_quietly(lock_fd)"),
    ("54 open failure after creating the lock file reported as contention", REOPEN,
     REOPEN.replace("_lock_open_problem(error)", "(StorageErrorCode.LOCKED, \"lock:held\")")),
    ("55 release in a non-owner process keeps the inherited descriptors", RELEASE_CHILD,
     "            self._state = LockState.INHERITED" + NL + "            return"),
    ("56 (DV-H1-1) every create failure classified as a permission denial",
     "    return (StorageErrorCode.STORAGE_UNAVAILABLE, \"lock:create\")",
     "    return (StorageErrorCode.PERMISSION_DENIED, \"lock:create-denied\")"),
    ("57 (Option A substitute) a link or non-directory at create not reported as unsafe", CREATE_LINK, "    if False:"),
    # DV-H1-1 Option A (58+): the dedicated creator's flags, mode, checks, cleanup and errno fallback
    ("58 O_EXCL removed from the lock-file create", CREATE_FLAGS, CREATE_FLAGS.replace(" | os.O_EXCL", "")),
    ("59 O_NOFOLLOW removed from the lock-file create", CREATE_FLAGS, CREATE_FLAGS.replace(" | os.O_NOFOLLOW", "")),
    ("60 O_CLOEXEC removed from the lock-file create", CREATE_FLAGS, CREATE_FLAGS.replace(" | os.O_CLOEXEC", "")),
    ("61 lock-file create opened writable", CREATE_FLAGS, CREATE_FLAGS.replace("os.O_RDONLY |", "os.O_WRONLY |")),
    ("62 fchmod(0o600) skipped after the create", CREATE_CHMOD, ""),
    ("63 post-create file validation skipped", CREATE_LABEL, "        label = None and os.fstat(lock_fd)"),
    ("64 post-create pathname identity skipped", CREATE_IDENTITY, "        elif False:"),
    ("65 own file not removed after a post-create failure", CREATE_CLEANUP,
     "    if False:" + NL + "        _posix_unlink_if_ours(dfd, _WRITER_LOCK_NAME, lock_fd, created)"),
    ("66 cleanup deletes by name without the identity check (foreign-file deletion)", CREATE_CLEANUP,
     "    if problem is not None and created is not None:" + NL + "        os.unlink(_WRITER_LOCK_NAME, dir_fd=dfd)"),
    ("67 BaseException after the create leaks the descriptor", CREATE_RAISE, "        raise"),
    ("68 unknown create errno treated as success", CREATE_FALLBACK, "    return None"),
    ("69 storage errors at create reported as contention", CREATE_FALLBACK,
     "    return (StorageErrorCode.LOCKED, \"lock:held\")"),
    # Gemini A/B reconciliation (70+): distinct post-create error paths
    ("70 post-create OSError (fstat / fchmod / pathname stat) treated as success", POST_CREATE_OSERROR,
     "    except OSError:" + NL + "        problem = None"),
    ("72 post-create vanished name treated as success", POST_CREATE_VANISHED,
     "    except FileNotFoundError:" + NL + "        problem = None"),
    ("73 post-create OSError classified with the create-errno table", POST_CREATE_OSERROR,
     "    except OSError as error:" + NL + "        problem = _lock_create_problem(error)"),
    ("74 identity recorded after fchmod (an fchmod failure then removes nothing)", CREATE_ORDER,
     "        os.fchmod(lock_fd, 0o600)" + NL + "        created = _identity(os.fstat(lock_fd))"),
]

# Mutants whose catching tests are POSIX-native (Linux and macOS).
POSIX = [
    ("04 O_NOFOLLOW removed from the lock open", OPEN_FLAGS, OPEN_FLAGS.replace(" | os.O_NOFOLLOW", "")),
    ("05 (substitute for O_CLOEXEC removed, an equivalent mutant under PEP 446) lock descriptor made inheritable",
     OPEN_CALL, "    fd = os.open(_WRITER_LOCK_NAME, lock_flags, dir_fd=dfd)" + NL + "    os.set_inheritable(fd, True)" + NL
     + "    return fd"),
    ("06 O_NONBLOCK removed from the lock open", OPEN_FLAGS,
     OPEN_FLAGS.replace(NL + "                  | getattr(os, \"O_NONBLOCK\", 0))", ")")),
    ("02n LOCK_EX replaced by LOCK_SH (native same-process contention)", FLOCK_CALL,
     "            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)  # type: ignore[union-attr]"),
    ("03n flock replaced by lockf (native same-process contention)", FLOCK_CALL,
     "            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[union-attr]"),
    ("07n S_ISREG check removed (native FIFO and directory)",
     "    if not stat.S_ISREG(st.st_mode):" + NL + "        return \"lock:type\"",
     "    if False:" + NL + "        return \"lock:type\""),
    ("08n link-count check removed (native hard link)", "    if st.st_nlink != 1:" + NL + "        return \"lock:links\"",
     "    if False:" + NL + "        return \"lock:links\""),
    ("09n owner/mode check removed (native modes)", "    if st.st_uid != uid or (st.st_mode & 0o077) != 0:", "    if False:"),
    ("10n size check removed (native non-empty file)", "    if st.st_size != 0:" + NL + "        return \"lock:size\"",
     "    if False:" + NL + "        return \"lock:size\""),
    ("11n lock descriptor opened read-write (native access mode)", OPEN_FLAGS,
     OPEN_FLAGS.replace("os.O_RDONLY | os.O_NOFOLLOW", "os.O_RDWR | os.O_NOFOLLOW")),
    ("12n pathname identity not compared (native substitution)",
     "    if _identity(named) != locked or not stat.S_ISREG(named.st_mode):" + NL + "        return \"lock:substituted\"",
     "    if False:" + NL + "        return \"lock:substituted\""),
    ("14n verify_held identity re-check skipped (native substitution after acquisition)",
     "        label = _held_lock_problem(self._fd, self._dfd, self._locked, os.geteuid())",
     "        label = None and _held_lock_problem(self._fd, self._dfd, self._locked, os.geteuid())"),
    ("17n owner-pid check removed (native fork without hook)", VERIFY_PID,
     "        if False:" + NL + "            self._end(LockState.INHERITED)  # closes this process's inherited copies only"),
    ("18n at-fork hook not registered (native fork)", "    os.register_at_fork(after_in_child=_after_fork_in_child)",
     "    pass"),
    ("19n fork hook leaves the directory fd open (native fork)", INHERIT,
     "        if self._state is LockState.HELD:" + NL + "            self._state = LockState.INHERITED" + NL
     + "        _close_quietly(self._fd)" + NL + "        self._fd = None"),
    ("20n fork hook leaves the lock fd open (native fork, release while the child lives)", INHERIT,
     "        if self._state is LockState.HELD:" + NL + "            self._state = LockState.INHERITED" + NL
     + "        _close_quietly(self._dfd)" + NL + "        self._dfd = None"),
    ("21n release unlinks the lock file (native inode check)", RELEASE_END,
     "            return" + NL + "        os.unlink(_WRITER_LOCK_NAME, dir_fd=self._dfd)  # type: ignore[arg-type]" + NL
     + "        self._end(LockState.RELEASED)"),
    ("27n open EACCES not PERMISSION_DENIED (native mode 0o000)",
     "        return (StorageErrorCode.PERMISSION_DENIED, \"lock:open-denied\")",
     "        return (StorageErrorCode.STORAGE_UNAVAILABLE, \"lock:open-denied\")"),
    ("34n existing unsafe lock file repaired with chmod (native mode unchanged)", LABEL_RETURN,
     "        if label is not None:" + NL + "            os.fchmod(fd, 0o600)  # type: ignore[arg-type]" + NL
     + "            return (StorageErrorCode.FILE_UNSAFE, label)"),
    ("40n (Option A substitute) create EACCES not PERMISSION_DENIED (native read-only chain directory)",
     CREATE_DENIED, CREATE_DENIED.replace("    if number in (errno.EACCES, errno.EPERM):", "    if False:")),
    ("58n O_EXCL removed from the create (native symlink planted before the create)", CREATE_FLAGS,
     CREATE_FLAGS.replace(" | os.O_EXCL", "")),
    ("62n fchmod(0o600) skipped (native umask 0o277)", CREATE_CHMOD, ""),
    ("64n post-create identity skipped (native substitution right after the create)", CREATE_IDENTITY,
     "        elif False:"),
    ("65n own file not removed after a post-create failure (native)", CREATE_CLEANUP,
     "    if False:" + NL + "        _posix_unlink_if_ours(dfd, _WRITER_LOCK_NAME, lock_fd, created)"),
    ("74n identity recorded after fchmod (native fchmod failure leaves the new file)", CREATE_ORDER,
     "        os.fchmod(lock_fd, 0o600)" + NL + "        created = _identity(os.fstat(lock_fd))"),
    ("66n cleanup deletes a substituted foreign file (native)", CREATE_CLEANUP,
     "    if problem is not None and created is not None:" + NL + "        os.unlink(_WRITER_LOCK_NAME, dir_fd=dfd)"),
    ("45n lock uses the chain directory's own descriptor (native: release closes the chain directory)", DUP_CALL,
     "        lock = WriterLock(_dfd=self._fd)  # type: ignore[arg-type]"),
]

# Mutants whose catching tests count real descriptors or use Linux lock semantics.
LINUX = [
    ("22l release uses LOCK_UN and keeps the descriptors (/proc/self/fd)", RELEASE_END,
     "            return" + NL + "        fcntl.flock(self._fd, fcntl.LOCK_UN)  # type: ignore[union-attr]" + NL
     + "        self._state = LockState.RELEASED"),
    ("23l descriptors not closed when acquisition fails (/proc/self/fd)",
     "        if problem is not None:" + NL + "            lock._end(LockState.INVALID)" + NL + "            raise _fail(*problem)",
     "        if problem is not None:" + NL + "            raise _fail(*problem)"),
    ("24l post-open rejection leaks the lock descriptor (/proc/self/fd)",
     "        self._fd = fd" + NL + "        try:" + NL + "            opened = os.fstat(fd)",
     "        try:" + NL + "            opened = os.fstat(fd)"),
    ("25l failed verify_held keeps the descriptors (/proc/self/fd)",
     "            self._end(LockState.INVALID)" + NL + "            raise _fail(StorageErrorCode.LOCK_INVALID, label)",
     "            raise _fail(StorageErrorCode.LOCK_INVALID, label)"),
    ("53l closing the lock leaves the private directory copy open (/proc/self/fd)", CLOSE_BOTH,
     "        _close_quietly(lock_fd)"),
]

# Mutants whose catching test is the native NTFS refusal test.
NTFS = [
    ("31w Windows refusal skipped (native NTFS: capability check reached instead)",
     "        self._require_posix_write()" + NL + "        if not _lock_capable():",
     "        if not _lock_capable():"),
]

PROFILES = {"portable": PORTABLE, "posix": POSIX, "linux": LINUX, "ntfs": NTFS}


def environment_problem(profile):
    if profile == "portable":
        return None
    if profile in ("posix", "linux"):
        try:
            import fcntl
        except ImportError:
            fcntl = None
        capable = (os.name == "posix" and os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")
                   and os.link in os.supports_follow_symlinks and os.scandir in os.supports_fd
                   and fcntl is not None and hasattr(fcntl, "flock") and hasattr(os, "register_at_fork"))
        if not capable:
            return "POSIX profile needs Linux or macOS with dir_fd, O_NOFOLLOW, flock and register_at_fork"
        if profile == "linux" and sys.platform != "linux":
            return "Linux profile needs Linux"
        return None
    directory = os.environ.get("RIG_SENTINEL_NTFS_TEST_DIR")
    if os.name != "nt" or not directory or not os.path.isdir(directory):
        return "NTFS profile needs Windows and RIG_SENTINEL_NTFS_TEST_DIR naming an existing native NTFS directory"
    return None


#: Variables that could inject code or pytest options into the child runs; they are never inherited.
DROPPED_ENV = ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONSTARTUP", "PYTHONINSPECT")


def child_env(src):
    env = {key: value for key, value in os.environ.items() if key not in DROPPED_ENV}
    env.update(PYTHONPATH=str(src), PYTHONDONTWRITEBYTECODE="1")
    return env


def copy_src(destination):
    shutil.copytree(REPO / "src", destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def run_tests(src):
    env = child_env(src)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "--tb=no", "-W", "error::Warning",
             str(REPO / TEST)],
            cwd=str(REPO), env=env, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return None
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES))
    args = parser.parse_args()
    problem = environment_problem(args.profile)
    if problem:
        print("UNSUPPORTED ENVIRONMENT (not a success): " + problem)
        return 2
    mutants = PROFILES[args.profile]
    work = pathlib.Path(tempfile.mkdtemp(prefix="rig-c2d-mutants-"))
    try:
        control_src = work / "control" / "src"
        copy_src(control_src)
        try:
            probe = subprocess.run([sys.executable, "-c", "import rig_sentinel.audit.safepath as s; print(s.__file__)"],
                                   env=child_env(control_src), capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            print("CONTROL FAILED: import probe timed out")
            return 1
        if str(control_src) not in probe.stdout:
            print("CONTROL FAILED: the mutated copy would not be imported (" + probe.stdout.strip() + ")")
            return 1
        control = run_tests(control_src)
        if control is None or control.returncode != 0:
            print("CONTROL FAILED: unmutated tests do not pass" + NL + ("timeout" if control is None else control.stdout[-2000:]))
            return 1
        caught = 0
        failures = 0
        for index, (name, old, new) in enumerate(mutants, 1):
            src = work / f"m{index}" / "src"
            copy_src(src)
            target = src / "rig_sentinel" / "audit" / "safepath.py"
            text = target.read_text(encoding="utf-8")
            if text.count(old) != 1 or old == new:
                failures += 1
                print(f"{index}. NOT APPLIED ({text.count(old)} matches): {name}")
                continue
            target.write_text(text.replace(old, new), encoding="utf-8")
            result = run_tests(src)
            if result is None:
                failures += 1
                print(f"{index}. [TIMEOUT] {name}")
                continue
            status = "CAUGHT" if result.returncode != 0 else "NOT CAUGHT"
            caught += status == "CAUGHT"
            print(f"{index}. [{status}] {name}")
        print(f"profile {args.profile}: caught {caught}/{len(mutants)}")
        return 0 if caught == len(mutants) and failures == 0 else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
