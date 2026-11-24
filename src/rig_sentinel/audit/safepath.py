"""Safe filesystem primitives for key files (Genesis B2-M2-C2-B, minimum C2-C subset).

The only audit module allowed to touch the filesystem (founder decision F11, D-C2-3/D-C2-4).
It provides exactly what C2-B key files need: path rules, opening a key directory safely,
and reading or exclusively creating one small private file in it. Key directories have no writer
lock, segment, anchor or recovery code (see the C2-C and C2-D sections below for audit storage).

POSIX (Linux, macOS):
* The configured directory must be an absolute, canonical path (``realpath(path) == path``).
* It is opened one component at a time from ``/``, each relative to the already-opened parent
  with ``O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC``, so a symlink anywhere fails.
* Ancestors must be owned by root or the effective user and not group- or other-writable
  (strict, no sticky-bit exception, D-C2-2). The final directory must be owned by the effective
  user with no group or other permissions.
* The resulting :class:`SafeDirectory` holds the final directory descriptor. Every file
  operation is relative to it (``dir_fd``) and never follows symlinks.

Windows (NTFS only, attestation required, D-C2-6):
* The standard library has no ``dir_fd``, ``O_NOFOLLOW``, ACL access or filesystem-type query.
* Paths must pass strict syntax rules (drive-letter absolute; no UNC or device prefixes,
  streams, reserved names, trailing dots or spaces) and equal ``os.path.realpath`` (this
  refuses 8.3 short names, junctioned ancestors, mapped network drives).
* Every component must be a directory without a reparse point.
* The directory must support named streams (``dir::$INDEX_ALLOCATION``), which refuses FAT32
  and exFAT before anything is written. This does not prove NTFS; the attestation covers it.
* Identities (volume serial and file index) are checked before and after each operation.
  A swap of an intermediate directory between the two checks is a residual race. ACLs are not
  verified (operator attestation only).
* **Key-file creation is disabled on Windows** (H2, finding R3): an ancestor swapped around an
  exclusive create can redirect the new file, and the standard library has no handle-relative
  create to prevent it. Creation is refused before any key material exists or any filesystem call
  is made. Loading remains available under the checks above and the mandatory trusted pin; the
  read-path races (R1, R2) are not claimed to be impossible.

Errors are :class:`StorageError` codes with fixed labels. They never include paths, file
contents or ``OSError`` text, and are raised without exception context.

Audit storage (Genesis B2-M2-C2-C), separate classes so key-file and audit operations never mix:
* :class:`AuditDirectory` (an audit root, opened like a key directory) and :class:`ChainDirectory`
  (``chain-<32 hex>`` inside it). Member names come from fixed tables; ``*.key`` is never accepted.
* POSIX only for every write: exclusive segment creation, single-write append with seal on a
  short write, atomic anchor replacement (``O_EXCL`` temp, sync, identity checks, ``renameat``,
  directory sync), no-clobber quarantine (``linkat`` + identity-checked ``unlinkat``) and cleanup
  bound to a retained descriptor (:class:`CreatedToken`). Each write method refuses on Windows before
  any filesystem call. Windows audit operations are read-only.
* A failed directory sync after a namespace change raises ``DURABILITY_UNCERTAIN``; it is never
  reported as durable. Callers (C3/C4) must reconcile persisted state; there is no recovery here.
* Linux: ``/proc/self/mountinfo`` is parsed with bounds and network, FUSE, FAT-type and memory-backed
  (tmpfs, ramfs) filesystems are refused (best effort, fail closed). It cannot authenticate physical
  storage.
* No protection is claimed against processes with the same credentials, or root.

Writer lock (Genesis B2-M2-C2-D), :class:`WriterLock` from :meth:`ChainDirectory.acquire_writer_lock`:
* POSIX only: ``flock(LOCK_EX | LOCK_NB)`` on ``chain-<id>/.writer.lock``, a permanent, empty, private
  file opened read-only relative to the held chain descriptor. An existing lock file is never
  unlinked, renamed, truncated or chmod-ed by this module; only its exclusive creator sets mode 0o600
  on the file it has just created, and removes only that file if its own checks fail. Windows refuses
  before any I/O (audit storage is read-only).
* Advisory: it excludes only cooperating RIG Sentinel writers (in this process or another). It does
  not stop processes that ignore it, same-account processes, or root. Identity checks after locking
  and in :meth:`WriterLock.verify_held` detect substitution of the lock file; they cannot prevent it.
* Non-blocking only (no waits, no retry loops): contention raises ``LOCKED``. Release closes the
  descriptors (no ``LOCK_UN``); the kernel releases the lock when the last reference closes or the
  process dies. After a fork the child's copies are closed and the child is never an owner.
* Callers (C3) must hold the lock for the writer's whole lifetime and call ``verify_held`` before every
  protected operation; the C2-C primitives themselves stay lock-agnostic.
"""

from __future__ import annotations

import errno
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum

try:  # POSIX only; used solely for F_FULLFSYNC on macOS (D-C2-4)
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

from rig_sentinel.audit.storage_errors import StorageError, StorageErrorCode

__all__ = [
    "ANCHOR_NAME",
    "ANCHOR_TEMP_NAME",
    "MAX_COMPONENTS",
    "MAX_POSIX_PATH_BYTES",
    "MAX_WINDOWS_PATH",
    "AuditDirectory",
    "ChainDirectory",
    "CreatedToken",
    "Durability",
    "ListResult",
    "LockState",
    "MountEntry",
    "SafeAppendFile",
    "SafeDirectory",
    "SafeReadFile",
    "WindowsAttestation",
    "WriterLock",
    "check_chain_directory_name",
    "check_chain_member_name",
    "check_file_name",
    "check_posix_path",
    "check_windows_path",
    "filesystem_type",
    "parse_mountinfo",
]

MAX_POSIX_PATH_BYTES = 4_096
MAX_WINDOWS_PATH = 259
MAX_COMPONENTS = 64
_ROLES = frozenset({"keys"})
_FILE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\.key")
_DRIVE_RE = re.compile(r"[A-Za-z]:\\")
_WINDOWS_FORBIDDEN = frozenset('<>"|?*/:')
_SUPERSCRIPTS = (chr(0xB9), chr(0xB2), chr(0xB3))
_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"}
    | {f"{prefix}{digit}" for prefix in ("COM", "LPT") for digit in "0123456789"}
    | {f"{prefix}{digit}" for prefix in ("COM", "LPT") for digit in _SUPERSCRIPTS}
)


def _fail(code: StorageErrorCode, label: str) -> StorageError:
    return StorageError(code, label)


# --- Pure path rules (testable on every platform) ------------------------------------------------


def _has_control(text: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in text)


def _is_reserved(component: str) -> bool:
    """Windows device names, with or without an extension, compared case-insensitively."""
    base = component.split(".", 1)[0].rstrip(" ")
    return base.upper() in _RESERVED_NAMES


def check_posix_path(path: object) -> tuple[str, ...]:
    """Validate a configured POSIX directory path; return its components (pure)."""
    if type(path) is not str or not path.startswith("/") or path == "/":
        raise _fail(StorageErrorCode.UNSAFE_PATH, "path:syntax")
    if len(path.encode("utf-8", "surrogateescape")) > MAX_POSIX_PATH_BYTES or "\x00" in path or _has_control(path):
        raise _fail(StorageErrorCode.UNSAFE_PATH, "path:syntax")
    components = tuple(path[1:].split("/"))
    if len(components) > MAX_COMPONENTS or any(c in ("", ".", "..") for c in components):
        raise _fail(StorageErrorCode.UNSAFE_PATH, "path:component")
    return components


def check_windows_path(path: object) -> tuple[str, ...]:
    """Validate a configured Windows directory path ``X:\\a\\b``; return its components (pure)."""
    if type(path) is not str or len(path) > MAX_WINDOWS_PATH or _has_control(path):
        raise _fail(StorageErrorCode.UNSAFE_PATH, "path:syntax")
    if _DRIVE_RE.match(path) is None or path.startswith(("\\\\", "//")):
        raise _fail(StorageErrorCode.UNSAFE_PATH, "path:syntax")
    rest = path[3:]
    if not rest or any(char in _WINDOWS_FORBIDDEN for char in rest):
        raise _fail(StorageErrorCode.UNSAFE_PATH, "path:syntax")  # no streams, UNC, slashes, wildcards
    components = tuple(rest.split("\\"))
    if len(components) > MAX_COMPONENTS:
        raise _fail(StorageErrorCode.UNSAFE_PATH, "path:component")
    for component in components:
        if component in ("", ".", "..") or component.endswith((".", " ")) or _is_reserved(component):
            raise _fail(StorageErrorCode.UNSAFE_PATH, "path:component")
    return components


def check_file_name(name: object) -> str:
    """Key file names: ``[a-z0-9][a-z0-9_-]{0,62}.key``, never a reserved device name (pure)."""
    if type(name) is not str or _FILE_NAME_RE.fullmatch(name) is None or _is_reserved(name):
        raise _fail(StorageErrorCode.UNSAFE_PATH, "path:file-name")
    return name


# --- Windows attestation ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WindowsAttestation:
    """Operator statements C2 cannot verify with the standard library (D-C2-6).

    All three must be exactly ``True``: the directory is on a local, fixed NTFS volume; its
    ACLs were set with the documented ``icacls`` recipe; the writer runs under a dedicated
    account. A false attestation is not detected.
    """

    local_fixed_ntfs: bool
    acl_recipe_applied: bool
    dedicated_account: bool

    def confirmed(self) -> bool:
        return all(value is True for value in (self.local_fixed_ntfs, self.acl_recipe_applied, self.dedicated_account))


# --- errno mapping -------------------------------------------------------------------------------


def _map_os_error(error: OSError, *, missing: StorageErrorCode) -> StorageErrorCode:
    number = error.errno
    if number == errno.ENOENT:
        return missing
    if number in (errno.ELOOP, errno.ENOTDIR, getattr(errno, "EMLINK", -1)):
        return StorageErrorCode.UNSAFE_PATH  # O_NOFOLLOW / O_DIRECTORY refused a link or non-directory
    if number == errno.EEXIST:
        return StorageErrorCode.KEY_FILE_EXISTS
    return StorageErrorCode.STORAGE_UNAVAILABLE


def _close_quietly(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _platform() -> str | None:
    if os.name == "nt":
        return "nt"
    if (
        os.name == "posix"
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_CLOEXEC")
    ):
        return "posix"
    return None


_Identity = tuple[int, int]


def _identity(st: os.stat_result) -> _Identity:
    return (st.st_dev, st.st_ino)


# --- SafeDirectory -----------------------------------------------------------------------------------


class SafeDirectory:
    """A verified key directory. POSIX: holds its descriptor. Windows: holds verified identities.

    Use as a context manager. ``repr`` shows only the role label, never the path. Not picklable.
    """

    __slots__ = ("_closed", "_fd", "_identities", "_kind", "_path", "_role")

    def __init__(self, *, _kind: str, _role: str, _fd: int | None, _path: str | None,
                 _identities: tuple[_Identity, ...]) -> None:
        self._kind = _kind
        self._role = _role
        self._fd = _fd
        self._path = _path
        self._identities = _identities
        self._closed = False

    @classmethod
    def open(cls, path: object, *, role: object, windows_attestation: object = None) -> SafeDirectory:
        if type(role) is not str or role not in _ROLES:
            raise _fail(StorageErrorCode.INPUT_TYPE_INVALID, "directory:role")
        kind = _platform()
        if kind == "posix":
            return cls(_kind="posix", _role=role, _fd=_posix_open_directory(path), _path=None, _identities=())
        if kind == "nt":
            if type(windows_attestation) is not WindowsAttestation or not windows_attestation.confirmed():
                raise _fail(StorageErrorCode.ATTESTATION_REQUIRED, "directory:windows")
            checked, identities = _windows_open_directory(path)
            return cls(_kind="nt", _role=role, _fd=None, _path=checked, _identities=identities)
        raise _fail(StorageErrorCode.UNSUPPORTED_PLATFORM, "directory:platform")

    def __enter__(self) -> SafeDirectory:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            fd, self._fd = self._fd, None
            _close_quietly(fd)

    def _require_open(self) -> None:
        if self._closed:
            raise _fail(StorageErrorCode.STORAGE_UNAVAILABLE, "directory:closed")

    def __repr__(self) -> str:
        return f"SafeDirectory(role={self._role!r}, closed={self._closed})"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: object) -> object:
        raise TypeError("SafeDirectory cannot be pickled")

    def __copy__(self) -> SafeDirectory:
        raise TypeError("SafeDirectory cannot be copied")

    def __deepcopy__(self, memo: object) -> SafeDirectory:
        raise TypeError("SafeDirectory cannot be copied")

    # -- file operations (key files only in C2-B) --------------------------------------------------

    def read_private_file(self, name: object, *, max_bytes: int) -> bytes:
        """Read a small private regular file completely; refuse anything unusual."""
        self._require_open()
        checked = check_file_name(name)
        if self._kind == "posix":
            return _posix_read(self._fd, checked, max_bytes)  # type: ignore[arg-type]
        return _windows_read(self._path, self._identities, checked, max_bytes)  # type: ignore[arg-type]

    def require_private_create(self) -> None:
        """Refuse private-file creation where it is not supported. Call before preparing any secret.

        POSIX: supported (exclusive create relative to the held directory descriptor).
        Windows: refused with ``UNSUPPORTED_PLATFORM`` (H2, finding R3). Nothing is touched.
        """
        self._require_open()
        if self._kind != "posix":
            raise _fail(StorageErrorCode.UNSUPPORTED_PLATFORM, "file:create-windows")

    def create_private_file(self, name: object, data: bytes) -> None:
        """Create ``name`` exclusively (never overwrite), write ``data`` completely, and sync it.

        POSIX only; refused on Windows before any filesystem call (see :meth:`require_private_create`).
        """
        self.require_private_create()
        checked = check_file_name(name)
        if type(data) is not bytes:
            raise _fail(StorageErrorCode.INPUT_TYPE_INVALID, "file:data")
        _posix_create(self._fd, checked, data)  # type: ignore[arg-type]


# --- POSIX ---------------------------------------------------------------------------------------------


def _posix_directory_problem(st: os.stat_result, euid: int, *, final: bool) -> StorageErrorCode | None:
    if not stat.S_ISDIR(st.st_mode):
        return StorageErrorCode.UNSAFE_PATH
    mode = stat.S_IMODE(st.st_mode)
    if final:
        if st.st_uid != euid or mode & 0o077:
            return StorageErrorCode.UNSAFE_PERMISSIONS
    elif st.st_uid not in (0, euid) or mode & 0o022:
        return StorageErrorCode.UNSAFE_PERMISSIONS
    return None


def _posix_open_directory(path: object) -> int:
    components = check_posix_path(path)
    if os.path.realpath(path) != path:  # type: ignore[arg-type]
        raise _fail(StorageErrorCode.UNSAFE_PATH, "path:not-canonical")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    euid = os.geteuid()  # type: ignore[attr-defined]
    fd: int | None = None
    problem: tuple[StorageErrorCode, str] | None = None
    try:
        fd = os.open("/", flags)
        code = _posix_directory_problem(os.fstat(fd), euid, final=False)
        if code is not None:
            problem = (code, "directory:ancestor")
        for index, component in enumerate(components):
            if problem is not None:
                break
            next_fd = os.open(component, flags | os.O_NOFOLLOW, dir_fd=fd)
            _close_quietly(fd)
            fd = next_fd
            final = index == len(components) - 1
            code = _posix_directory_problem(os.fstat(fd), euid, final=final)
            if code is not None:
                problem = (code, "directory:final" if final else "directory:ancestor")
    except OSError as error:
        problem = (_map_os_error(error, missing=StorageErrorCode.STORAGE_UNAVAILABLE), "directory:open")
    if problem is not None:
        _close_quietly(fd)
        raise _fail(*problem)
    return fd  # type: ignore[return-value]


def _posix_file_problem(st: os.stat_result, euid: int, max_bytes: int) -> tuple[StorageErrorCode, str] | None:
    if not stat.S_ISREG(st.st_mode):
        return (StorageErrorCode.KEY_FILE_UNSAFE, "file:type")
    if st.st_nlink != 1:
        return (StorageErrorCode.KEY_FILE_UNSAFE, "file:links")
    if st.st_uid != euid or stat.S_IMODE(st.st_mode) & 0o077:
        return (StorageErrorCode.KEY_FILE_UNSAFE, "file:permissions")
    if st.st_size > max_bytes:
        return (StorageErrorCode.KEY_FILE_FORMAT, "file:size")
    return None


def _stable(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        _identity(before) == _identity(after)
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
    )


def _read_all(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= limit:
        chunk = os.read(fd, limit + 1 - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _posix_read(dfd: int, name: str, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_NONBLOCK", 0)
    euid = os.geteuid()  # type: ignore[attr-defined]
    fd: int | None = None
    problem: tuple[StorageErrorCode, str] | None = None
    data = b""
    try:
        fd = os.open(name, flags, dir_fd=dfd)
        before = os.fstat(fd)
        problem = _posix_file_problem(before, euid, max_bytes)
        if problem is None:
            data = _read_all(fd, max_bytes)
            after = os.fstat(fd)
            if not _stable(before, after) or len(data) != before.st_size:
                problem = (StorageErrorCode.KEY_FILE_UNSAFE, "file:changed")
    except OSError as error:
        problem = (_map_os_error(error, missing=StorageErrorCode.KEY_FILE_MISSING), "file:open")
    _close_quietly(fd)
    if problem is not None:
        raise _fail(*problem)
    return data


def _full_sync(fd: int) -> None:
    os.fsync(fd)
    if fcntl is not None and hasattr(fcntl, "F_FULLFSYNC"):
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)  # macOS: request a drive-cache flush (F5)
        except OSError:
            pass  # filesystem without F_FULLFSYNC support: fsync above already returned


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        view = view[written:]


def _posix_create(dfd: int, name: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NOCTTY", 0)
    euid = os.geteuid()  # type: ignore[attr-defined]
    fd: int | None = None
    created: _Identity | None = None
    problem: tuple[StorageErrorCode, str] | None = None
    try:
        fd = os.open(name, flags, 0o600, dir_fd=dfd)
        st = os.fstat(fd)
        created = _identity(st)
        os.fchmod(fd, 0o600)  # umask can only remove bits; set the exact mode
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != euid:
            problem = (StorageErrorCode.KEY_FILE_UNSAFE, "file:created")
        else:
            _write_all(fd, data)
            _full_sync(fd)
    except OSError as error:
        problem = (_map_os_error(error, missing=StorageErrorCode.STORAGE_UNAVAILABLE), "file:create")
    _close_quietly(fd)
    if problem is None:
        try:
            _full_sync(dfd)  # persist the new directory entry
        except OSError:
            problem = (StorageErrorCode.STORAGE_UNAVAILABLE, "directory:sync")
    if problem is not None:
        if created is not None:
            _posix_remove_if_same(dfd, name, created)
        raise _fail(*problem)


def _posix_remove_if_same(dfd: int, name: str, created: _Identity) -> None:
    """Remove a file we created, but only if the name still refers to it (never a replacement)."""
    try:
        current = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if _identity(current) == created and stat.S_ISREG(current.st_mode):
            os.unlink(name, dir_fd=dfd)
    except OSError:
        pass


# --- C2-C: audit storage names, limits and shared helpers -----------------------------------------------

ANCHOR_NAME = ".seq_anchor"
ANCHOR_TEMP_NAME = ".seq_anchor.tmp"
_WRITER_LOCK_NAME = ".writer.lock"  # reserved for C2-D: listed, never opened by C2-C
_CHAIN_DIR_RE = re.compile(r"chain-[0-9a-f]{32}")
_SEGMENT_RE = re.compile(r"seg-(?:0|[1-9][0-9]{0,15})\.jsonl")
_QUARANTINE_RE = re.compile(r"\.seq_anchor\.q[0-7]")
MAX_FILE_BYTES = 1 << 40  # upper bound accepted for any caller-supplied max_size
MAX_REPLACE_BYTES = 1 << 20
MAX_LIST_ENTRIES = 1_000_000


class Durability(StrEnum):
    """What a successful sync achieved (F5). Never returned when durability is uncertain."""

    FSYNC = "fsync"  # os.fsync returned success
    FULLFSYNC = "fullfsync"  # macOS: fsync and F_FULLFSYNC both returned success


@dataclass(frozen=True)
class ListResult:
    """Allowed member names (sorted) and a count of other entries, which are never named."""

    names: tuple[str, ...]
    other_entries: int


def _is_segment(name: str) -> bool:
    return _SEGMENT_RE.fullmatch(name) is not None


def _is_quarantine(name: str) -> bool:
    return _QUARANTINE_RE.fullmatch(name) is not None


def _is_readable_member(name: str) -> bool:
    return _is_segment(name) or _is_quarantine(name) or name in (ANCHOR_NAME, ANCHOR_TEMP_NAME)


def _is_listed_member(name: str) -> bool:
    return _is_readable_member(name) or name == _WRITER_LOCK_NAME


def check_chain_directory_name(name: object) -> str:
    """``chain-<32 lowercase hex>`` (pure)."""
    if type(name) is not str or _CHAIN_DIR_RE.fullmatch(name) is None:
        raise _fail(StorageErrorCode.UNSAFE_PATH, "path:chain-name")
    return name


def check_chain_member_name(name: object, *, kind: str) -> str:
    """Validate a member name of a chain directory for one operation kind (pure).

    ``segment``: ``seg-<n>.jsonl``; ``readable``: segments, the anchor, its temp and quarantine names;
    ``quarantine``: ``.seq_anchor.q0`` ... ``.q7``; ``quarantine-source``: the anchor or its temp.
    """
    if type(name) is str:
        if kind == "segment" and _is_segment(name):
            return name
        if kind == "readable" and _is_readable_member(name):
            return name
        if kind == "quarantine" and _is_quarantine(name):
            return name
        if kind == "quarantine-source" and name in (ANCHOR_NAME, ANCHOR_TEMP_NAME):
            return name
    raise _fail(StorageErrorCode.UNSAFE_PATH, "path:member-name")


def _check_limit(value: object, upper: int, label: str) -> int:
    if type(value) is not int or not 1 <= value <= upper:
        raise _fail(StorageErrorCode.INPUT_TYPE_INVALID, label)
    return value


def _fs_code(error: OSError, *, missing: StorageErrorCode) -> StorageErrorCode:
    """errno mapping for audit-storage files (the key-file mapping above is unchanged)."""
    number = error.errno
    if number == errno.ENOENT:
        return missing
    if number in (errno.ENOTDIR, errno.ELOOP, getattr(errno, "EMLINK", -1)):
        return StorageErrorCode.UNSAFE_PATH  # O_NOFOLLOW / O_DIRECTORY refused a link or non-directory
    if errno.EEXIST == number:
        return StorageErrorCode.FILE_EXISTS
    if number in (errno.EISDIR, getattr(errno, "ENXIO", -1)):
        return StorageErrorCode.FILE_UNSAFE  # a directory, or a FIFO without a reader (O_NONBLOCK)
    return StorageErrorCode.STORAGE_UNAVAILABLE


def _sync_level(fd: int) -> Durability:
    """fsync, plus F_FULLFSYNC where the platform offers it; report what was achieved."""
    os.fsync(fd)
    if fcntl is not None and hasattr(fcntl, "F_FULLFSYNC"):
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
        except OSError:
            return Durability.FSYNC
        return Durability.FULLFSYNC
    return Durability.FSYNC


def _weakest(*levels: Durability) -> Durability:
    return Durability.FULLFSYNC if all(level is Durability.FULLFSYNC for level in levels) else Durability.FSYNC


def _posix_write_capable() -> bool:
    """Descriptor-relative primitives every C2-C POSIX write needs."""
    if os.name != "posix" or not hasattr(os, "fchmod"):
        return False
    needed = (os.open, os.stat, os.mkdir, os.unlink, os.rename, os.link)
    return (
        all(function in os.supports_dir_fd for function in needed)
        and os.link in os.supports_follow_symlinks
        and os.scandir in os.supports_fd
    )


def _private_file_label(st: os.stat_result, euid: int) -> str | None:
    """Audit files: regular, one link, owned by the effective user, no group or other bits."""
    if not stat.S_ISREG(st.st_mode):
        return "file:type"
    if st.st_nlink != 1:
        return "file:links"
    if st.st_uid != euid or stat.S_IMODE(st.st_mode) & 0o077 != 0:
        return "file:permissions"
    return None


def _named_identity(dfd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=dfd, follow_symlinks=False)


# --- C2-C: POSIX descriptor-bound primitives (every caller has already refused non-POSIX) ---------------


def _posix_unlink_if_ours(dfd: int, name: str, fd: int, identity: _Identity) -> str | None:
    """Unlink ``name`` only if it is the object behind our open ``fd`` (correction A).

    Returns ``None`` if removed (or already gone), else a fixed label explaining why nothing was
    deleted, or ``file:cleanup-race`` if the post-check shows another object was removed.
    """
    try:
        held = os.fstat(fd)
        if _identity(held) != identity:
            return "token:identity"
        if held.st_nlink == 0:
            return None  # our object no longer has a name; nothing to remove
        try:
            named = _named_identity(dfd, name)
        except FileNotFoundError:
            return "file:moved"  # our object is linked elsewhere: ambiguous, never touched
        if _identity(named) != identity or not stat.S_ISREG(named.st_mode):
            return "file:substituted"
        if named.st_nlink != 1:
            return "file:links"
        os.unlink(name, dir_fd=dfd)
        if os.fstat(fd).st_nlink != 0:
            return "file:cleanup-race"  # the name removed was not our last link: detected, not prevented
    except OSError:
        return "file:cleanup"
    return None


def _posix_open_child(dfd: int, name: str, create: bool) -> int:
    euid = os.geteuid()  # type: ignore[attr-defined]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd: int | None = None
    problem: tuple[StorageErrorCode, str] | None = None
    try:
        created = False
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=dfd)
                created = True
            except FileExistsError:
                pass  # an existing child is opened and checked like any other; never chmod-ed (D-C2C-8)
        fd = os.open(name, flags, dir_fd=dfd)
        if created:
            os.fchmod(fd, 0o700)  # umask can only remove bits; set the exact mode on what we created
        st = os.fstat(fd)
        code = _posix_directory_problem(st, euid, final=True)
        if code is not None:
            problem = (code, "directory:child")
        elif _identity(_named_identity(dfd, name)) != _identity(st):
            problem = (StorageErrorCode.UNSAFE_PATH, "directory:changed")
    except OSError as error:
        problem = (_fs_code(error, missing=StorageErrorCode.STORAGE_UNAVAILABLE), "directory:child")
    if problem is not None:
        _close_quietly(fd)
        raise _fail(*problem)
    return fd  # type: ignore[return-value]


def _posix_open_member(dfd: int, name: str, flags: int, max_size: int, *, create: bool) -> tuple[int, os.stat_result]:
    """Open a chain member relative to the held directory and verify it; returns (fd, fstat)."""
    euid = os.geteuid()  # type: ignore[attr-defined]
    fd: int | None = None
    problem: tuple[StorageErrorCode, str] | None = None
    identity: _Identity | None = None
    st: os.stat_result | None = None
    try:
        if create:
            fd = os.open(name, flags, 0o600, dir_fd=dfd)
            identity = _identity(os.fstat(fd))  # recorded first, so any later failure can clean up
            os.fchmod(fd, 0o600)
        else:
            fd = os.open(name, flags, dir_fd=dfd)
        st = os.fstat(fd)
        label = _private_file_label(st, euid)
        if label is not None:
            problem = (StorageErrorCode.FILE_UNSAFE, label)
        elif st.st_size > max_size:
            problem = (StorageErrorCode.FILE_TOO_LARGE, "file:limit")
        elif _identity(_named_identity(dfd, name)) != _identity(st):
            problem = (StorageErrorCode.FILE_UNSAFE, "file:changed")
    except OSError as error:
        problem = (_fs_code(error, missing=StorageErrorCode.FILE_MISSING), "file:create" if create else "file:open")
    if problem is not None:
        if create and fd is not None and identity is not None:
            _posix_unlink_if_ours(dfd, name, fd, identity)
        _close_quietly(fd)
        raise _fail(*problem)
    return fd, st  # type: ignore[return-value]


def _posix_create_member(dfd: int, name: str, max_size: int) -> tuple[int, os.stat_result]:
    flags = (os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
             | getattr(os, "O_NOCTTY", 0))
    return _posix_open_member(dfd, name, flags, max_size, create=True)


def _lock_create_problem(error: OSError) -> tuple[StorageErrorCode, str]:
    """C2-D (DV-H1-1, Option A): classify the actual errno of a failed lock-file create; never LOCKED."""
    number = error.errno
    if number in (errno.EACCES, errno.EPERM):
        return (StorageErrorCode.PERMISSION_DENIED, "lock:create-denied")
    if number in (errno.ELOOP, getattr(errno, "EMLINK", -1), errno.ENOTDIR):  # a link or non-directory
        return (StorageErrorCode.UNSAFE_PATH, "lock:create")
    return (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create")  # ENOSPC, EDQUOT, EROFS, EIO and anything unknown


def _posix_create_lock_file(dfd: int) -> tuple[StorageErrorCode, str] | None:
    """C2-D: create the empty writer lock file (DV-H1-1, Option A). The only code that creates that name.

    One exclusive, descriptor-relative create with ``O_RDONLY | O_EXCL | O_NOFOLLOW | O_CLOEXEC`` (no
    writable descriptor ever exists) whose errno is classified as it is, never inferred. Mode 0o600 is
    then set exactly, and the regular-file, owner, mode, size and single-link checks plus a pathname
    identity check must pass. ``None`` means created and valid, or ``EEXIST`` (a concurrent creator, or a
    planted object, won): the caller then opens and validates the existing name exactly once. After any
    later failure only our own file is removed (never a substituted one), and the descriptor is always
    closed, also when a ``BaseException`` propagates. It lives with the C2-C POSIX primitives: every caller
    has already refused non-POSIX platforms.
    """
    create_flags = (os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
                    | getattr(os, "O_NOCTTY", 0))
    owner = os.geteuid()  # type: ignore[attr-defined]
    try:
        lock_fd = os.open(_WRITER_LOCK_NAME, create_flags, 0o600, dir_fd=dfd)
    except OSError as error:
        if error.errno == errno.EEXIST:
            return None
        return _lock_create_problem(error)
    created: _Identity | None = None
    problem: tuple[StorageErrorCode, str] | None = None
    try:
        created = _identity(os.fstat(lock_fd))  # first, so every later failure removes only this file
        os.fchmod(lock_fd, 0o600)
        label = _lock_file_label(os.fstat(lock_fd), owner)
        if label is not None:
            problem = (StorageErrorCode.FILE_UNSAFE, label)
        elif _identity(_named_identity(dfd, _WRITER_LOCK_NAME)) != created:
            problem = (StorageErrorCode.FILE_UNSAFE, "lock:changed")
    except FileNotFoundError:
        problem = (StorageErrorCode.FILE_UNSAFE, "lock:changed")  # our new name vanished
    except OSError:
        problem = (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:create-verify")
    except BaseException:
        if created is not None:
            _posix_unlink_if_ours(dfd, _WRITER_LOCK_NAME, lock_fd, created)
        _close_quietly(lock_fd)
        raise
    if problem is not None and created is not None:
        _posix_unlink_if_ours(dfd, _WRITER_LOCK_NAME, lock_fd, created)
    _close_quietly(lock_fd)
    return problem


def _posix_open_append_member(dfd: int, name: str, max_size: int) -> tuple[int, os.stat_result]:
    flags = (os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NOCTTY", 0)
             | getattr(os, "O_NONBLOCK", 0))
    return _posix_open_member(dfd, name, flags, max_size, create=False)


def _posix_open_read_member(dfd: int, name: str, max_size: int) -> tuple[int, os.stat_result]:
    flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NOCTTY", 0)
             | getattr(os, "O_NONBLOCK", 0))
    return _posix_open_member(dfd, name, flags, max_size, create=False)


def _posix_write_fully(fd: int, data: bytes) -> bool:
    """Write all of ``data`` (temp files only; segments use a single write). False on a zero write."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            return False
        view = view[written:]
    return True


def _posix_replace(dfd: int, name: str, data: bytes) -> Durability:
    """Atomically replace ``name`` with ``data`` via the fixed temp name (architecture 5.4, correction C)."""
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NOCTTY", 0))
    euid = os.geteuid()  # type: ignore[attr-defined]
    temp = ANCHOR_TEMP_NAME
    fd: int | None = None
    identity: _Identity | None = None
    problem: tuple[StorageErrorCode, str] | None = None
    replaced = False
    levels: list[Durability] = []
    try:
        fd = os.open(temp, flags, 0o600, dir_fd=dfd)
        identity = _identity(os.fstat(fd))  # recorded first, so any later failure can clean up
        os.fchmod(fd, 0o600)
        st = os.fstat(fd)
        label = _private_file_label(st, euid)
        if label is not None:
            problem = (StorageErrorCode.FILE_UNSAFE, label)
        elif not _posix_write_fully(fd, data):
            problem = (StorageErrorCode.PARTIAL_WRITE, "file:partial")
        else:
            try:
                levels.append(_sync_level(fd))
            except OSError:
                problem = (StorageErrorCode.DURABILITY_FAILED, "file:sync")
        if problem is None:
            if _identity(_named_identity(dfd, temp)) != identity:
                problem = (StorageErrorCode.FILE_UNSAFE, "file:changed")
            else:
                try:
                    target = _named_identity(dfd, name)
                except FileNotFoundError:
                    target = None
                if target is not None and (not stat.S_ISREG(target.st_mode) or target.st_nlink != 1):
                    problem = (StorageErrorCode.FILE_UNSAFE, "file:target")
        if problem is None:
            os.replace(temp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            replaced = True
            if _identity(_named_identity(dfd, name)) != identity:
                problem = (StorageErrorCode.FILE_UNSAFE, "file:replaced")  # detection only
    except OSError as error:
        if fd is None:
            problem = (_fs_code(error, missing=StorageErrorCode.STORAGE_UNAVAILABLE), "file:temp-create")
            if problem[0] is StorageErrorCode.FILE_EXISTS:
                problem = (StorageErrorCode.FILE_EXISTS, "file:temp-exists")  # an orphan is never reused
        elif replaced:
            problem = (StorageErrorCode.FILE_UNSAFE, "file:replaced")
        else:
            problem = (_fs_code(error, missing=StorageErrorCode.STORAGE_UNAVAILABLE), "file:replace")
    if problem is None:
        try:
            levels.append(_sync_level(dfd))
        except OSError:
            problem = (StorageErrorCode.DURABILITY_UNCERTAIN, "directory:sync-after-replace")
    if problem is not None and fd is not None and identity is not None and not replaced:
        _posix_unlink_if_ours(dfd, temp, fd, identity)  # our temp only; anything else is left alone
    _close_quietly(fd)
    if problem is not None:
        raise _fail(*problem)
    return _weakest(*levels)


def _posix_link_no_replace(dfd: int, source: str, target: str) -> Durability:
    """Quarantine without overwriting: states S0 -> S1 (two links) -> S2 (correction B)."""
    euid = os.geteuid()  # type: ignore[attr-defined]
    flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_NONBLOCK", 0))
    fd: int | None = None
    problem: tuple[StorageErrorCode, str] | None = None
    level: Durability | None = None
    try:
        fd = os.open(source, flags, dir_fd=dfd)
        st = os.fstat(fd)
        identity = _identity(st)
        label = _private_file_label(st, euid)  # S0 requires exactly one link
        if label is not None:
            problem = (StorageErrorCode.FILE_UNSAFE, label)
        elif _identity(_named_identity(dfd, source)) != identity:
            problem = (StorageErrorCode.FILE_UNSAFE, "file:changed")
        if problem is None:
            os.link(source, target, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)  # never clobbers
            if _identity(_named_identity(dfd, target)) != identity or os.fstat(fd).st_nlink != 2:
                problem = (StorageErrorCode.FILE_UNSAFE, "file:linked")
        if problem is None:
            if _identity(_named_identity(dfd, source)) != identity:
                problem = (StorageErrorCode.FILE_UNSAFE, "file:changed")  # stop in S1; no repair
            else:
                os.unlink(source, dir_fd=dfd)
                if os.fstat(fd).st_nlink != 1:
                    problem = (StorageErrorCode.FILE_UNSAFE, "file:unlinked")
    except OSError as error:
        problem = (_fs_code(error, missing=StorageErrorCode.FILE_MISSING), "file:quarantine")
    if problem is None:
        try:
            level = _sync_level(dfd)
        except OSError:
            problem = (StorageErrorCode.DURABILITY_UNCERTAIN, "directory:sync")
    _close_quietly(fd)
    if problem is not None:
        raise _fail(*problem)
    return level  # type: ignore[return-value]


def _posix_list(dfd: int, allowed: object, max_entries: int) -> ListResult:
    names: list[str] = []
    others = 0
    count = 0
    problem: tuple[StorageErrorCode, str] | None = None
    try:
        with os.scandir(dfd) as entries:
            for entry in entries:
                count += 1
                if count > max_entries:
                    problem = (StorageErrorCode.ENTRY_LIMIT_EXCEEDED, "directory:entries")
                    break
                if allowed(entry.name):  # type: ignore[operator]
                    names.append(entry.name)
                else:
                    others += 1
    except OSError as error:
        problem = (_fs_code(error, missing=StorageErrorCode.STORAGE_UNAVAILABLE), "directory:list")
    if problem is not None:
        raise _fail(*problem)
    return ListResult(tuple(sorted(names)), others)


# --- C2-C: Linux mountinfo (best effort, fail closed; D-C2-7, D-C2C-4a) ---------------------------------

MAX_MOUNTINFO_BYTES = 1 << 20
MAX_MOUNTINFO_LINES = 10_000
MAX_MOUNTINFO_LINE_BYTES = 8_192
_REFUSED_FILESYSTEMS = frozenset({
    b"nfs", b"nfs4", b"cifs", b"smb3", b"smbfs", b"fuse", b"fuseblk", b"vfat", b"exfat", b"msdos",
    b"9p", b"ceph", b"glusterfs", b"afs",
    b"tmpfs", b"ramfs",  # C2-C-H2: memory-backed, lost at reboot; never acceptable for durable audit data
})
_MAJOR_MINOR_RE = re.compile(rb"([0-9]{1,10}):([0-9]{1,10})")
_FSTYPE_RE = re.compile(rb"[a-z0-9][a-z0-9._+-]{0,63}")
_DIGITS_RE = re.compile(rb"[0-9]{1,10}")


@dataclass(frozen=True)
class MountEntry:
    major: int
    minor: int
    mount_point: bytes
    fstype: bytes


def _mount_fail(label: str) -> StorageError:
    return _fail(StorageErrorCode.UNSUPPORTED_FILESYSTEM, label)


def _unescape_mount_field(field: bytes) -> bytes | None:
    """Undo mountinfo's ``\\ooo`` octal escapes. Any other backslash use is malformed (None)."""
    out = bytearray()
    index = 0
    while index < len(field):
        byte = field[index]
        if byte != 0x5C:
            out.append(byte)
            index += 1
            continue
        digits = field[index + 1:index + 4]
        if len(digits) != 3 or any(d not in b"01234567" for d in digits):
            return None
        value = int(digits, 8)
        if value == 0 or value > 0xFF:
            return None
        out.append(value)
        index += 4
    return bytes(out)


def parse_mountinfo(data: object) -> tuple[MountEntry, ...]:
    """Parse ``/proc/self/mountinfo`` bytes strictly and with bounds (pure). Fails closed."""
    if type(data) is not bytes or not data or len(data) > MAX_MOUNTINFO_BYTES or not data.endswith(b"\n"):
        raise _mount_fail("mountinfo:size")
    lines = data[:-1].split(b"\n")
    if len(lines) > MAX_MOUNTINFO_LINES:
        raise _mount_fail("mountinfo:size")
    entries: list[MountEntry] = []
    for line in lines:
        if not line or len(line) > MAX_MOUNTINFO_LINE_BYTES or any(b < 0x20 or b > 0x7E for b in line):
            raise _mount_fail("mountinfo:line")
        fields = line.split(b" ")
        if b"" in fields or len(fields) < 10 or b"-" not in fields[6:]:
            raise _mount_fail("mountinfo:line")
        separator = fields.index(b"-", 6)
        if len(fields) != separator + 4:
            raise _mount_fail("mountinfo:line")
        if _DIGITS_RE.fullmatch(fields[0]) is None or _DIGITS_RE.fullmatch(fields[1]) is None:
            raise _mount_fail("mountinfo:line")
        device = _MAJOR_MINOR_RE.fullmatch(fields[2])
        mount_point = _unescape_mount_field(fields[4])
        fstype = fields[separator + 1]
        if device is None or mount_point is None or not mount_point.startswith(b"/") or _FSTYPE_RE.fullmatch(fstype) is None:
            raise _mount_fail("mountinfo:line")
        entries.append(MountEntry(int(device.group(1)), int(device.group(2)), mount_point, fstype))
    return tuple(entries)


def _mount_covers(mount_point: bytes, path: bytes) -> bool:
    return mount_point == b"/" or path == mount_point or path.startswith(mount_point + b"/")


def filesystem_type(entries: tuple[MountEntry, ...], major: int, minor: int, path: bytes) -> bytes:
    """The filesystem type of the mount holding ``path`` on device ``major:minor`` (pure, fail closed).

    Among entries for the device (bind mounts share one), the longest mount point that is a prefix of
    the canonical path wins; a tie between different types is ambiguous and refused.
    """
    candidates = [e for e in entries if (e.major, e.minor) == (major, minor) and _mount_covers(e.mount_point, path)]
    if not candidates:
        raise _mount_fail("mountinfo:device")
    longest = max(len(e.mount_point) for e in candidates)
    types = {e.fstype for e in candidates if len(e.mount_point) == longest}
    if len(types) != 1:
        raise _mount_fail("mountinfo:ambiguous")
    return types.pop()


def _is_refused_filesystem(fstype: bytes) -> bool:
    return fstype in _REFUSED_FILESYSTEMS or fstype.startswith(b"fuse.")


def _read_mountinfo() -> bytes:
    fd = os.open("/proc/self/mountinfo", os.O_RDONLY | os.O_CLOEXEC)
    try:
        return _read_all(fd, MAX_MOUNTINFO_BYTES)
    finally:
        _close_quietly(fd)


def _linux_filesystem_problem(fd: int, path: str) -> tuple[StorageErrorCode, str] | None:
    """Linux only; other POSIX systems have no standard-library source (operator requirement)."""
    if os.uname().sysname != "Linux":  # type: ignore[attr-defined]
        return None
    try:
        st = os.fstat(fd)
        data = _read_mountinfo()
    except OSError:
        return (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "mountinfo:unreadable")
    try:
        fstype = filesystem_type(parse_mountinfo(data), os.major(st.st_dev), os.minor(st.st_dev),  # type: ignore[attr-defined]
                                 os.fsencode(path))
    except StorageError as error:
        return (error.code, error.path)
    if _is_refused_filesystem(fstype):
        return (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "directory:filesystem")
    return None


# --- Windows -------------------------------------------------------------------------------------------


def _is_reparse(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _windows_component_identities(path: str, components: tuple[str, ...]) -> tuple[_Identity, ...]:
    """``lstat`` every prefix: each must be a directory without a reparse point."""
    identities = []
    current = path[:2]
    for component in components:
        current = current + "\\" + component
        st = os.lstat(current)
        if _is_reparse(st) or not stat.S_ISDIR(st.st_mode):
            raise _fail(StorageErrorCode.UNSAFE_PATH, "directory:reparse")
        identities.append(_identity(st))
    return tuple(identities)


def _windows_stream_probe(directory: str, identity: _Identity) -> StorageErrorCode | None:
    """Named-stream probe (R1 classification). NTFS-like filesystems accept ``dir::$INDEX_ALLOCATION``.

    ``None``: supported, and the probe resolves to the verified directory.
    ``UNSAFE_PATH``: the probe succeeds but resolves to a different directory (identity mismatch shown).
    ``UNSUPPORTED_FILESYSTEM``: the probe fails (capability absent, e.g. FAT32/exFAT, or not verifiable).
    """
    try:
        st = os.stat(directory + "::$INDEX_ALLOCATION")
    except OSError:
        return StorageErrorCode.UNSUPPORTED_FILESYSTEM
    if _identity(st) != identity:
        return StorageErrorCode.UNSAFE_PATH
    return None


def _windows_probe_problem(path: str, identities: tuple[_Identity, ...]) -> tuple[StorageErrorCode, str] | None:
    """Classify a probe result. A failed probe counts as tampering only with evidence of an identity change."""
    code = _windows_stream_probe(path, identities[-1])
    if code is None:
        return None
    if code is StorageErrorCode.UNSAFE_PATH:
        return (StorageErrorCode.UNSAFE_PATH, "directory:changed")
    try:
        changed = _windows_component_identities(path, check_windows_path(path)) != identities
    except (StorageError, OSError):
        changed = True  # a component vanished or became a reparse point: identity evidence
    if changed:
        return (StorageErrorCode.UNSAFE_PATH, "directory:changed")
    return (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "directory:filesystem")  # reason undetermined: fail closed


def _windows_open_directory(path: object) -> tuple[str, tuple[_Identity, ...]]:
    components = check_windows_path(path)
    checked: str = path  # type: ignore[assignment]
    problem: tuple[StorageErrorCode, str] | None = None
    identities: tuple[_Identity, ...] = ()
    try:
        if os.path.realpath(checked) != checked:
            problem = (StorageErrorCode.UNSAFE_PATH, "path:not-canonical")
        else:
            identities = _windows_component_identities(checked, components)
            problem = _windows_probe_problem(checked, identities)
            if problem is None and _windows_component_identities(checked, components) != identities:
                problem = (StorageErrorCode.UNSAFE_PATH, "directory:changed")
    except StorageError as error:
        problem = (error.code, error.path)
    except OSError as error:
        problem = (_map_os_error(error, missing=StorageErrorCode.STORAGE_UNAVAILABLE), "directory:open")
    if problem is not None:
        raise _fail(*problem)
    return checked, identities


def _windows_recheck(path: str, identities: tuple[_Identity, ...]) -> None:
    components = check_windows_path(path)
    problem = False
    try:
        problem = _windows_component_identities(path, components) != identities
    except (StorageError, OSError):
        problem = True
    if problem:
        raise _fail(StorageErrorCode.UNSAFE_PATH, "directory:changed")


def _windows_file_problem(st: os.stat_result, max_bytes: int) -> tuple[StorageErrorCode, str] | None:
    if _is_reparse(st) or not stat.S_ISREG(st.st_mode):
        return (StorageErrorCode.KEY_FILE_UNSAFE, "file:type")
    if st.st_nlink != 1:
        return (StorageErrorCode.KEY_FILE_UNSAFE, "file:links")
    if st.st_size > max_bytes:
        return (StorageErrorCode.KEY_FILE_FORMAT, "file:size")
    return None


def _windows_read(path: str, identities: tuple[_Identity, ...], name: str, max_bytes: int) -> bytes:
    full = path + "\\" + name
    _windows_recheck(path, identities)
    fd: int | None = None
    problem: tuple[StorageErrorCode, str] | None = None
    data = b""
    try:
        before = os.lstat(full)
        problem = _windows_file_problem(before, max_bytes)
        if problem is None:
            fd = os.open(full, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)  # type: ignore[attr-defined]
            opened = os.fstat(fd)
            if _identity(opened) != _identity(before) or opened.st_nlink != 1:
                problem = (StorageErrorCode.UNSAFE_PATH, "file:changed")
            else:
                problem = _windows_probe_problem(path, identities)
            if problem is None:
                data = _read_all(fd, max_bytes)
                after = os.fstat(fd)
                if not _stable(opened, after) or len(data) != opened.st_size:
                    problem = (StorageErrorCode.KEY_FILE_UNSAFE, "file:changed")
                elif _identity(os.lstat(full)) != _identity(opened):
                    problem = (StorageErrorCode.UNSAFE_PATH, "file:changed")
    except OSError as error:
        problem = (_map_os_error(error, missing=StorageErrorCode.KEY_FILE_MISSING), "file:open")
    _close_quietly(fd)
    if problem is not None:
        raise _fail(*problem)
    _windows_recheck(path, identities)
    return data


# --- C2-C: Windows audit storage is read-only (no create, write, rename or delete exists here) -------


def _windows_open_read_member(path: str, identities: tuple[_Identity, ...], name: str,
                              max_size: int) -> tuple[int, os.stat_result]:
    full = path + "\\" + name
    fd: int | None = None
    opened: os.stat_result | None = None
    problem: tuple[StorageErrorCode, str] | None = None
    try:
        _windows_recheck(path, identities)
        before = os.lstat(full)
        if _is_reparse(before) or not stat.S_ISREG(before.st_mode):
            problem = (StorageErrorCode.FILE_UNSAFE, "file:type")
        elif before.st_nlink != 1:
            problem = (StorageErrorCode.FILE_UNSAFE, "file:links")
        elif before.st_size > max_size:
            problem = (StorageErrorCode.FILE_TOO_LARGE, "file:limit")
        else:
            fd = os.open(full, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)  # type: ignore[attr-defined]
            opened = os.fstat(fd)
            if opened.st_nlink != 1 or _identity(before) != _identity(opened):
                problem = (StorageErrorCode.UNSAFE_PATH, "file:changed")
            if problem is None:
                problem = _windows_probe_problem(path, identities)
            if problem is None:
                _windows_recheck(path, identities)
    except StorageError as error:
        problem = (error.code, error.path)
    except OSError as error:
        problem = (_fs_code(error, missing=StorageErrorCode.FILE_MISSING), "file:open")
    if problem is not None:
        _close_quietly(fd)
        raise _fail(*problem)
    return fd, opened  # type: ignore[return-value]


def _windows_list(path: str, identities: tuple[_Identity, ...], allowed: object, max_entries: int) -> ListResult:
    names: list[str] = []
    others = 0
    count = 0
    problem: tuple[StorageErrorCode, str] | None = None
    try:
        _windows_recheck(path, identities)
        with os.scandir(path) as entries:
            for entry in entries:
                count += 1
                if count > max_entries:
                    problem = (StorageErrorCode.ENTRY_LIMIT_EXCEEDED, "directory:entries")
                    break
                if allowed(entry.name):  # type: ignore[operator]
                    names.append(entry.name)
                else:
                    others += 1
        if problem is None:
            _windows_recheck(path, identities)
    except StorageError as error:
        problem = (error.code, error.path)
    except OSError as error:
        problem = (_fs_code(error, missing=StorageErrorCode.STORAGE_UNAVAILABLE), "directory:list")
    if problem is not None:
        raise _fail(*problem)
    return ListResult(tuple(sorted(names)), others)


# --- C2-C: objects ------------------------------------------------------------------------------------


class _Guarded:
    """Shared object hygiene: no pickling or copying; ``repr`` never shows paths or identities."""

    __slots__ = ()

    def __reduce_ex__(self, protocol: object) -> object:
        raise TypeError(f"{type(self).__name__} cannot be pickled")

    def __copy__(self) -> object:
        raise TypeError(f"{type(self).__name__} cannot be copied")

    def __deepcopy__(self, memo: object) -> object:
        raise TypeError(f"{type(self).__name__} cannot be copied")

    def __enter__(self) -> object:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()  # type: ignore[attr-defined]


class CreatedToken(_Guarded):
    """Proof that this process created one chain file, bound to a retained descriptor (correction A).

    While the token's descriptor is open the inode cannot be freed, so its ``(st_dev, st_ino)`` cannot be
    reused by another file. Single use: :meth:`ChainDirectory.remove_created` consumes it. A closed token
    can never authorize a removal; cleanup is then an operator task.
    """

    __slots__ = ("_closed", "_dfd", "_fd", "_identity", "_name")

    def __init__(self, *, _fd: int, _dfd: int, _name: str, _identity: _Identity) -> None:
        self._fd = _fd
        self._dfd = _dfd
        self._name = _name
        self._identity = _identity
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            _close_quietly(self._fd)
            _close_quietly(self._dfd)

    def __repr__(self) -> str:
        return f"CreatedToken(closed={self._closed})"

    __str__ = __repr__


class SafeAppendFile(_Guarded):
    """An open chain segment (POSIX). Single-write appends; any failure seals the handle."""

    __slots__ = ("_closed", "_created", "_dfd", "_fd", "_identity", "_max", "_name", "_sealed", "_size")

    def __init__(self, *, _fd: int, _dfd: int, _name: str, _st: os.stat_result, _max: int, _created: bool) -> None:
        self._fd = _fd
        self._dfd = _dfd
        self._name = _name
        self._identity = _identity(_st)
        self._size = _st.st_size
        self._max = _max
        self._created = _created
        self._sealed = False
        self._closed = False

    @property
    def size(self) -> int:
        return self._size

    @property
    def sealed(self) -> bool:
        return self._sealed

    def _require_usable(self) -> None:
        if self._closed:
            raise _fail(StorageErrorCode.STORAGE_UNAVAILABLE, "file:closed")
        if self._sealed:
            raise _fail(StorageErrorCode.FILE_UNSAFE, "file:sealed")

    def append(self, data: object) -> None:
        """Append ``data`` with exactly one ``os.write`` (C0-H1 4.2, D-C2C-6)."""
        self._require_usable()
        if type(data) is not bytes or not data:
            raise _fail(StorageErrorCode.INPUT_TYPE_INVALID, "file:data")
        if self._size + len(data) > self._max:
            raise _fail(StorageErrorCode.FILE_TOO_LARGE, "file:limit")
        euid = os.geteuid()  # type: ignore[attr-defined]
        problem: tuple[StorageErrorCode, str] | None = None
        try:
            st = os.fstat(self._fd)
            label = _private_file_label(st, euid)
            if label is None and (_identity(st) != self._identity or st.st_size != self._size):
                label = "file:changed"  # truncated, appended to by someone else, or replaced
            if label is not None:
                problem = (StorageErrorCode.FILE_UNSAFE, label)
            else:
                written = os.write(self._fd, data)
                if written != len(data):
                    self._size += max(written, 0)
                    problem = (StorageErrorCode.PARTIAL_WRITE, "file:partial")
                else:
                    self._size += written
        except OSError as error:
            problem = (_fs_code(error, missing=StorageErrorCode.FILE_MISSING), "file:append")
        if problem is not None:
            self._sealed = True
            raise _fail(*problem)

    def sync(self) -> Durability:
        """Make appended bytes durable as far as the platform reports; failure seals the handle."""
        self._require_usable()
        try:
            return _sync_level(self._fd)
        except OSError:
            pass
        self._sealed = True
        raise _fail(StorageErrorCode.DURABILITY_FAILED, "file:sync")

    def verify_name(self) -> None:
        """The segment name must still refer to this open file (detects rename or replacement)."""
        if self._closed:
            raise _fail(StorageErrorCode.STORAGE_UNAVAILABLE, "file:closed")
        problem = False
        try:
            named = _named_identity(self._dfd, self._name)
            problem = _identity(named) != self._identity or not stat.S_ISREG(named.st_mode)
        except OSError:
            problem = True
        if problem:
            raise _fail(StorageErrorCode.FILE_UNSAFE, "file:replaced")

    def created_token(self) -> CreatedToken:
        """A single-use cleanup token for a segment this handle created (correction A)."""
        if self._closed or not self._created:
            raise _fail(StorageErrorCode.INPUT_TYPE_INVALID, "token:not-created")
        fd: int | None = None
        dfd: int | None = None
        try:
            fd = os.dup(self._fd)
            dfd = os.dup(self._dfd)
        except OSError:
            _close_quietly(fd)
            fd = None
        if fd is None or dfd is None:
            raise _fail(StorageErrorCode.STORAGE_UNAVAILABLE, "token:create")
        return CreatedToken(_fd=fd, _dfd=dfd, _name=self._name, _identity=self._identity)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            _close_quietly(self._fd)
            _close_quietly(self._dfd)

    def __repr__(self) -> str:
        return f"SafeAppendFile(closed={self._closed}, sealed={self._sealed})"

    __str__ = __repr__


class SafeReadFile(_Guarded):
    """A bounded read handle for a chain member (POSIX, and Windows read-only)."""

    __slots__ = ("_closed", "_dfd", "_fd", "_identities", "_kind", "_max", "_name", "_opened", "_path", "_total")

    def __init__(self, *, _kind: str, _fd: int, _st: os.stat_result, _max: int, _name: str,
                 _dfd: int | None = None, _path: str | None = None,
                 _identities: tuple[_Identity, ...] = ()) -> None:
        self._kind = _kind
        self._fd = _fd
        self._opened = _st
        self._max = _max
        self._name = _name
        self._dfd = _dfd
        self._path = _path
        self._identities = _identities
        self._total = 0
        self._closed = False

    def read(self, max_bytes: object) -> bytes:
        """Return up to ``max_bytes``; ``b''`` at the end. Never past the handle's ``max_size``."""
        if self._closed:
            raise _fail(StorageErrorCode.STORAGE_UNAVAILABLE, "file:closed")
        limit = _check_limit(max_bytes, MAX_FILE_BYTES, "file:read-size")
        problem: tuple[StorageErrorCode, str] | None = None
        chunk = b""
        try:
            chunk = os.read(self._fd, min(limit, self._max - self._total + 1))
        except OSError as error:
            problem = (_fs_code(error, missing=StorageErrorCode.FILE_MISSING), "file:read")
        if problem is None and self._total + len(chunk) > self._max:
            problem = (StorageErrorCode.FILE_TOO_LARGE, "file:limit")  # the file grew past its bound
        if problem is not None:
            raise _fail(*problem)
        self._total += len(chunk)
        return chunk

    def verify_unchanged(self) -> None:
        """Identity, link count, size and mtime are as they were at open, and the name still matches."""
        if self._closed:
            raise _fail(StorageErrorCode.STORAGE_UNAVAILABLE, "file:closed")
        problem: tuple[StorageErrorCode, str] | None = None
        try:
            now = os.fstat(self._fd)
            if now.st_nlink != 1 or not _stable(self._opened, now):
                problem = (StorageErrorCode.FILE_UNSAFE, "file:changed")
            elif self._kind == "posix":
                if _identity(_named_identity(self._dfd, self._name)) != _identity(now):  # type: ignore[arg-type]
                    problem = (StorageErrorCode.FILE_UNSAFE, "file:replaced")
            else:
                if _identity(os.lstat(self._path + "\\" + self._name)) != _identity(now):  # type: ignore[operator]
                    problem = (StorageErrorCode.UNSAFE_PATH, "file:replaced")
                else:
                    _windows_recheck(self._path, self._identities)  # type: ignore[arg-type]
        except StorageError as error:
            problem = (error.code, error.path)
        except OSError:
            problem = (StorageErrorCode.FILE_UNSAFE, "file:replaced")
        if problem is not None:
            raise _fail(*problem)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            _close_quietly(self._fd)
            _close_quietly(self._dfd)

    def __repr__(self) -> str:
        return f"SafeReadFile(closed={self._closed})"

    __str__ = __repr__


# --- C2-D: writer lock (POSIX only; advisory; D-C2D-1 ... D-C2D-14) -------------------------------------


class LockState(StrEnum):
    """Writer-lock lifecycle (D-C2D-14). INVALID, RELEASED and INHERITED are terminal."""

    NEW = "new"  # internal only: being acquired; never returned to a caller
    HELD = "held"
    INVALID = "invalid"
    RELEASED = "released"
    INHERITED = "inherited"  # a forked child's view of its parent's lock; never an owner


_TERMINAL_LOCK_LABELS = {
    LockState.NEW: "lock:invalid",
    LockState.INVALID: "lock:invalid",
    LockState.RELEASED: "lock:released",
    LockState.INHERITED: "lock:forked",
}
_HELD_LOCKS: dict[int, WriterLock] = {}  # this process's HELD locks, for the at-fork hook


def _lock_capable() -> bool:
    """Attribute presence only (never function identity), so test wrappers cannot trip it."""
    return (_posix_write_capable() and fcntl is not None and hasattr(fcntl, "flock")
            and hasattr(os, "register_at_fork"))


def _lock_file_label(st: os.stat_result, uid: int) -> str | None:
    """The lock file must be a private, empty, single-link regular file owned by ``uid``."""
    if not stat.S_ISREG(st.st_mode):
        return "lock:type"
    if st.st_nlink != 1:
        return "lock:links"
    if st.st_uid != uid or (st.st_mode & 0o077) != 0:
        return "lock:permissions"
    if st.st_size != 0:
        return "lock:size"
    return None


def _posix_open_lock_fd(dfd: int) -> int:
    """Read-only, no symlinks, close-on-exec, never blocks on a planted FIFO; relative to the chain fd."""
    lock_flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NOCTTY", 0)
                  | getattr(os, "O_NONBLOCK", 0))
    return os.open(_WRITER_LOCK_NAME, lock_flags, dir_fd=dfd)


def _lock_open_problem(error: OSError) -> tuple[StorageErrorCode, str]:
    number = error.errno
    if number in (errno.EACCES, errno.EPERM):
        return (StorageErrorCode.PERMISSION_DENIED, "lock:open-denied")
    if number in (errno.ELOOP, getattr(errno, "EMLINK", -1)):
        return (StorageErrorCode.UNSAFE_PATH, "lock:open")
    if number in (errno.ENXIO, errno.EISDIR):
        return (StorageErrorCode.FILE_UNSAFE, "lock:type")
    return (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:open")


def _posix_open_lock_file(dfd: int) -> tuple[int | None, tuple[StorageErrorCode, str] | None]:
    """Open the existing lock file, or create it once and then open it (no retry loop)."""
    try:
        return _posix_open_lock_fd(dfd), None
    except FileNotFoundError:
        pass
    except OSError as error:
        return None, _lock_open_problem(error)
    problem = _posix_create_lock_file(dfd)
    if problem is not None:
        return None, problem
    try:
        return _posix_open_lock_fd(dfd), None
    except OSError as error:
        return None, _lock_open_problem(error)


def _lock_flock_problem(error: OSError) -> tuple[StorageErrorCode, str]:
    """Only documented contention is ``LOCKED``; a denial is never disguised as contention (H-2)."""
    number = error.errno
    if number in (errno.EWOULDBLOCK, errno.EAGAIN):
        return (StorageErrorCode.LOCKED, "lock:held")
    if number in (errno.EACCES, errno.EPERM):
        return (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:flock-denied")
    if number in (getattr(errno, "EOPNOTSUPP", -1), getattr(errno, "ENOTSUP", -1)):
        return (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "lock:unsupported")
    if number == errno.ENOLCK:
        return (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:resources")
    if number == errno.EINTR:
        return (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:interrupted")
    return (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:flock")


def _held_lock_problem(fd: int, dfd: int, locked: _Identity, uid: int) -> str | None:
    """Descriptor identity and pathname identity must both still be the locked, valid lock file (M-1).

    Detection only: a process with write access to the chain directory can still race these checks.
    """
    try:
        held = os.fstat(fd)
        named = os.stat(_WRITER_LOCK_NAME, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return "lock:substituted"
    except OSError:
        return "lock:verify"
    if _identity(held) != locked:
        return "lock:changed"
    if held.st_nlink == 0:
        return "lock:substituted"  # our inode lost its name
    descriptor_label = _lock_file_label(held, uid)
    if descriptor_label is not None:
        return descriptor_label
    if _identity(named) != locked or not stat.S_ISREG(named.st_mode):
        return "lock:substituted"
    if named.st_nlink != 1:
        return "lock:links"
    return None


class WriterLock(_Guarded):
    """An exclusive, non-blocking, advisory writer lock on one chain directory (POSIX only).

    Obtain it only from :meth:`ChainDirectory.acquire_writer_lock`. It excludes other cooperating RIG
    Sentinel writers; it does not stop processes that ignore it, same-account processes or root. Use it as
    a context manager. ``release`` is idempotent. ``verify_held`` must be called before every protected
    operation (C3 contract); on any failure the lock becomes INVALID, its descriptors are closed and it can
    never become HELD again. Not thread-safe; not picklable or copyable; ``repr`` shows only the state.
    """

    __slots__ = ("_dfd", "_fd", "_locked", "_owner", "_state")

    def __init__(self, *, _dfd: int) -> None:
        self._dfd: int | None = _dfd
        self._fd: int | None = None
        self._locked: _Identity | None = None
        self._owner = os.getpid()
        self._state = LockState.NEW

    @property
    def state(self) -> LockState:
        return self._state

    @property
    def held(self) -> bool:
        return self._state is LockState.HELD and os.getpid() == self._owner

    def _close_fds(self) -> None:
        """Idempotent: slots are cleared before closing, so a reused descriptor number is never closed."""
        lock_fd, dir_fd = self._fd, self._dfd
        self._fd = None
        self._dfd = None
        _close_quietly(lock_fd)
        _close_quietly(dir_fd)

    def _end(self, state: LockState) -> None:
        """Enter a terminal state (only from NEW or HELD), forget the lock and close its descriptors."""
        if self._state in (LockState.NEW, LockState.HELD):
            self._state = state
        _HELD_LOCKS.pop(id(self), None)
        self._close_fds()

    def _acquire(self) -> tuple[StorageErrorCode, str] | None:
        dfd: int = self._dfd  # type: ignore[assignment]
        uid = os.geteuid()  # type: ignore[attr-defined]
        fd, problem = _posix_open_lock_file(dfd)
        if problem is not None:
            return problem
        self._fd = fd
        try:
            opened = os.fstat(fd)  # type: ignore[arg-type]
        except OSError:
            return (StorageErrorCode.STORAGE_UNAVAILABLE, "lock:open")
        label = _lock_file_label(opened, uid)
        if label is not None:
            return (StorageErrorCode.FILE_UNSAFE, label)
        self._locked = _identity(opened)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[union-attr]
        except OSError as error:
            return _lock_flock_problem(error)
        after = _held_lock_problem(fd, dfd, self._locked, uid)  # type: ignore[arg-type]
        if after is not None:
            return (StorageErrorCode.LOCK_INVALID, after)
        self._owner = os.getpid()
        self._state = LockState.HELD
        _HELD_LOCKS[id(self)] = self
        return None

    def verify_held(self) -> None:
        """Fail closed unless this process still holds this lock on the same lock file (M-3)."""
        if self._state is not LockState.HELD:
            raise _fail(StorageErrorCode.LOCK_INVALID, _TERMINAL_LOCK_LABELS[self._state])
        if os.getpid() != self._owner:
            self._end(LockState.INHERITED)  # closes this process's inherited copies only
            raise _fail(StorageErrorCode.LOCK_INVALID, "lock:forked")
        label = _held_lock_problem(self._fd, self._dfd, self._locked, os.geteuid())  # type: ignore[arg-type,attr-defined]
        if label is not None:
            self._end(LockState.INVALID)
            raise _fail(StorageErrorCode.LOCK_INVALID, label)

    def release(self) -> None:
        """Idempotent. Closes the descriptors (never ``LOCK_UN``, never unlinks the lock file)."""
        if self._state is not LockState.HELD:
            return
        if os.getpid() != self._owner:
            self._end(LockState.INHERITED)
            return
        self._end(LockState.RELEASED)

    def close(self) -> None:
        self.release()

    def _inherit(self) -> None:
        """At-fork hook, child side: never an owner; close BOTH inherited descriptors (H-1)."""
        if self._state is LockState.HELD:
            self._state = LockState.INHERITED
        self._close_fds()

    def __repr__(self) -> str:
        return f"WriterLock(state={self._state.value!r})"

    __str__ = __repr__


def _invalidate_inherited_locks() -> None:
    """Runs in a forked child (interpreter forks only): every inherited lock becomes INHERITED, closed."""
    for lock in list(_HELD_LOCKS.values()):
        lock._inherit()
    _HELD_LOCKS.clear()


def _after_fork_in_child() -> None:
    _invalidate_inherited_locks()  # looked up at call time


class _AuditBase(_Guarded):
    __slots__ = ("_closed", "_fd", "_identities", "_kind", "_path")
    _ROLE = ""

    def __init__(self, *, _kind: str, _fd: int | None, _path: str, _identities: tuple[_Identity, ...]) -> None:
        self._kind = _kind
        self._fd = _fd
        self._path = _path
        self._identities = _identities
        self._closed = False

    def _require_open(self) -> None:
        if not self._closed:
            return
        raise _fail(StorageErrorCode.STORAGE_UNAVAILABLE, "directory:closed")

    def _require_posix_write(self) -> None:
        """First statement of every write method: Windows (and incapable POSIX) refuse before any I/O."""
        self._require_open()
        windows = self._kind != "posix"
        if windows:
            raise _fail(StorageErrorCode.UNSUPPORTED_PLATFORM, "file:write-windows")
        if not _posix_write_capable():
            raise _fail(StorageErrorCode.UNSUPPORTED_PLATFORM, "file:write-platform")

    def _allowed(self, name: str) -> bool:
        raise NotImplementedError

    def list_names(self, *, max_entries: object = MAX_LIST_ENTRIES) -> ListResult:
        """Bounded listing: allowed names (sorted) and a count of other entries, never their names."""
        self._require_open()
        limit = _check_limit(max_entries, MAX_LIST_ENTRIES, "directory:max-entries")
        if self._kind == "posix":
            if os.scandir not in os.supports_fd:
                raise _fail(StorageErrorCode.UNSUPPORTED_PLATFORM, "directory:list-platform")
            return _posix_list(self._fd, self._allowed, limit)  # type: ignore[arg-type]
        return _windows_list(self._path, self._identities, self._allowed, limit)

    def sync(self) -> Durability:
        """Sync the directory (persists entries created, replaced or removed in it). POSIX only."""
        self._require_posix_write()
        try:
            return _sync_level(self._fd)  # type: ignore[arg-type]
        except OSError:
            pass
        raise _fail(StorageErrorCode.DURABILITY_UNCERTAIN, "directory:sync")

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            fd, self._fd = self._fd, None
            _close_quietly(fd)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(role={self._ROLE!r}, closed={self._closed})"

    __str__ = __repr__


class AuditDirectory(_AuditBase):
    """The audit root (B2-M2-C2-C). It holds only ``chain-<32 hex>`` directories."""

    __slots__ = ()
    _ROLE = "audit_root"

    @classmethod
    def open(cls, path: object, *, windows_attestation: object = None) -> AuditDirectory:
        kind = _platform()
        if kind == "posix":
            fd = _posix_open_directory(path)  # C2-B walk: canonical, no symlinks, strict ancestors, private
            problem = _linux_filesystem_problem(fd, path)  # type: ignore[arg-type]
            if problem is not None:
                _close_quietly(fd)
                raise _fail(*problem)
            return cls(_kind="posix", _fd=fd, _path=path, _identities=())  # type: ignore[arg-type]
        if kind == "nt":
            attested = type(windows_attestation) is WindowsAttestation and windows_attestation.confirmed()
            if not attested:
                raise _fail(StorageErrorCode.ATTESTATION_REQUIRED, "directory:windows")
            checked, identities = _windows_open_directory(path)
            return cls(_kind="nt", _fd=None, _path=checked, _identities=identities)
        unsupported = _fail(StorageErrorCode.UNSUPPORTED_PLATFORM, "directory:platform")
        raise unsupported

    def _allowed(self, name: str) -> bool:
        return _CHAIN_DIR_RE.fullmatch(name) is not None

    def open_chain(self, name: object, *, create: bool = False) -> ChainDirectory:
        """Open (or, POSIX only, create with mode 0o700) a ``chain-<32 hex>`` directory."""
        if create is not False:
            if create is not True:
                raise _fail(StorageErrorCode.INPUT_TYPE_INVALID, "directory:create")
            self._require_posix_write()
        self._require_open()
        checked = check_chain_directory_name(name)
        if self._kind == "posix":
            fd = _posix_open_child(self._fd, checked, create)  # type: ignore[arg-type]
            child_path = self._path + "/" + checked
            problem = _linux_filesystem_problem(fd, child_path)
            if problem is not None:
                _close_quietly(fd)
                raise _fail(*problem)
            return ChainDirectory(_kind="posix", _fd=fd, _path=child_path, _identities=())
        child, identities = _windows_open_directory(self._path + "\\" + checked)
        return ChainDirectory(_kind="nt", _fd=None, _path=child, _identities=identities)

    def verify_chain_named(self, chain: object) -> None:
        """Raise unless this root's entry named like ``chain`` is that chain's held directory (C3, D-C3-3).

        POSIX only and read-only: the entry is examined without following symlinks and must be a directory
        whose ``(st_dev, st_ino)`` equals the held descriptor's. It never creates, opens, renames, removes or
        modifies anything. Detection at check time only: substitution of the audit root or an ancestor, and a
        swap and swap-back between two checks, are not detected; same-account processes are not prevented.
        """
        self._require_open()
        if type(chain) is not ChainDirectory:
            raise _fail(StorageErrorCode.INPUT_TYPE_INVALID, "chain:type")
        chain._require_open()
        capable = os.stat in os.supports_dir_fd and os.stat in os.supports_follow_symlinks
        if self._kind != "posix" or chain._kind != "posix" or not capable:
            raise _fail(StorageErrorCode.UNSUPPORTED_PLATFORM, "chain:verify-platform")
        entry: str | None = None
        try:
            entry = check_chain_directory_name(chain._path.rsplit("/", 1)[-1])
        except StorageError:
            entry = None
        if entry is None:
            raise _fail(StorageErrorCode.INTERNAL_INVARIANT, "chain:name")
        verdict: str | None = None
        try:
            held_directory = os.fstat(chain._fd)  # type: ignore[arg-type]
            entry_identity = _named_identity(self._fd, entry)  # type: ignore[arg-type]
            if not stat.S_ISDIR(entry_identity.st_mode) or _identity(entry_identity) != _identity(held_directory):
                verdict = "chain:replaced"
        except FileNotFoundError:
            verdict = "chain:missing"
        except OSError:
            verdict = "chain:verify"
        if verdict is not None:
            raise _fail(StorageErrorCode.UNSAFE_PATH, verdict)


class ChainDirectory(_AuditBase):
    """One chain's directory: segments, the anchor, its temp and quarantine names (D-C2C-7)."""

    __slots__ = ()
    _ROLE = "chain"

    def _allowed(self, name: str) -> bool:
        return _is_listed_member(name)

    def _dup_dir(self) -> int:
        try:
            return os.dup(self._fd)  # type: ignore[arg-type]
        except OSError:
            pass
        raise _fail(StorageErrorCode.STORAGE_UNAVAILABLE, "directory:dup")

    def acquire_writer_lock(self) -> WriterLock:
        """Take this chain's writer lock: one non-blocking attempt (C2-D). POSIX only.

        Contention raises ``LOCKED``. Every failure, including an exception raised by a signal handler,
        closes every descriptor this call opened. The returned lock is HELD.
        """
        self._require_posix_write()
        if not _lock_capable():
            raise _fail(StorageErrorCode.UNSUPPORTED_PLATFORM, "lock:platform")
        lock = WriterLock(_dfd=self._dup_dir())
        try:
            problem = lock._acquire()
        except BaseException:
            lock._end(LockState.INVALID)  # M-2: close everything, then let the original exception through
            raise
        if problem is not None:
            lock._end(LockState.INVALID)
            raise _fail(*problem)
        return lock

    def create_exclusive(self, name: object, *, max_size: object) -> SafeAppendFile:
        """Create a new segment (``O_EXCL``, mode 0o600, never overwrites) and return its append handle."""
        self._require_posix_write()
        checked = check_chain_member_name(name, kind="segment")
        limit = _check_limit(max_size, MAX_FILE_BYTES, "file:max-size")
        dfd = self._dup_dir()
        try:
            fd, st = _posix_create_member(self._fd, checked, limit)  # type: ignore[arg-type]
        except StorageError:
            _close_quietly(dfd)
            raise
        return SafeAppendFile(_fd=fd, _dfd=dfd, _name=checked, _st=st, _max=limit, _created=True)

    def open_append(self, name: object, *, max_size: object) -> SafeAppendFile:
        """Reopen an existing segment for appending; size and identity tracking start from ``fstat``."""
        self._require_posix_write()
        checked = check_chain_member_name(name, kind="segment")
        limit = _check_limit(max_size, MAX_FILE_BYTES, "file:max-size")
        dfd = self._dup_dir()
        try:
            fd, st = _posix_open_append_member(self._fd, checked, limit)  # type: ignore[arg-type]
        except StorageError:
            _close_quietly(dfd)
            raise
        return SafeAppendFile(_fd=fd, _dfd=dfd, _name=checked, _st=st, _max=limit, _created=False)

    def open_read(self, name: object, *, max_size: object) -> SafeReadFile:
        """Open a segment, the anchor, its temp or a quarantine file for bounded reading."""
        self._require_open()
        checked = check_chain_member_name(name, kind="readable")
        limit = _check_limit(max_size, MAX_FILE_BYTES, "file:max-size")
        if self._kind == "posix":
            dfd = self._dup_dir()
            try:
                fd, st = _posix_open_read_member(self._fd, checked, limit)  # type: ignore[arg-type]
            except StorageError:
                _close_quietly(dfd)
                raise
            return SafeReadFile(_kind="posix", _fd=fd, _st=st, _max=limit, _name=checked, _dfd=dfd)
        fd, st = _windows_open_read_member(self._path, self._identities, checked, limit)
        return SafeReadFile(_kind="nt", _fd=fd, _st=st, _max=limit, _name=checked, _path=self._path,
                            _identities=self._identities)

    def replace_atomically(self, name: object, data: object, *, max_bytes: object) -> Durability:
        """Replace the anchor atomically. ``DURABILITY_UNCERTAIN`` if the final directory sync fails."""
        self._require_posix_write()
        if type(name) is not str or name != ANCHOR_NAME:
            raise _fail(StorageErrorCode.UNSAFE_PATH, "path:member-name")
        limit = _check_limit(max_bytes, MAX_REPLACE_BYTES, "file:max-size")
        if type(data) is not bytes or not data:
            raise _fail(StorageErrorCode.INPUT_TYPE_INVALID, "file:data")
        if len(data) > limit:
            raise _fail(StorageErrorCode.FILE_TOO_LARGE, "file:limit")
        return _posix_replace(self._fd, name, data)  # type: ignore[arg-type]

    def link_no_replace(self, source: object, target: object) -> Durability:
        """Quarantine ``source`` (anchor or temp) under ``target`` (``.seq_anchor.qN``) without overwriting."""
        self._require_posix_write()
        checked_source = check_chain_member_name(source, kind="quarantine-source")
        checked_target = check_chain_member_name(target, kind="quarantine")
        return _posix_link_no_replace(self._fd, checked_source, checked_target)  # type: ignore[arg-type]

    def remove_created(self, token: object) -> bool:
        """Remove a file this process created, proven by its live token (correction A). Single use.

        Returns ``True`` if the file was removed, ``False`` if it was already gone. Refuses (and deletes
        nothing) if the name now refers to anything else; reports a detected cleanup race.
        """
        self._require_posix_write()
        if type(token) is not CreatedToken:
            raise _fail(StorageErrorCode.INPUT_TYPE_INVALID, "token:type")
        if token._closed:
            raise _fail(StorageErrorCode.FILE_UNSAFE, "token:closed")
        problem: tuple[StorageErrorCode, str] | None = None
        removed = False
        try:
            if _identity(os.fstat(token._dfd)) != _identity(os.fstat(self._fd)):  # type: ignore[arg-type]
                problem = (StorageErrorCode.INPUT_TYPE_INVALID, "token:directory")
            else:
                gone = os.fstat(token._fd).st_nlink == 0
                label = _posix_unlink_if_ours(token._dfd, token._name, token._fd, token._identity)
                if label is not None:
                    problem = (StorageErrorCode.FILE_UNSAFE, label)
                removed = not gone and label is None
        except OSError:
            problem = (StorageErrorCode.STORAGE_UNAVAILABLE, "token:check")
        token.close()  # single use, whatever happened
        if problem is not None:
            raise _fail(*problem)
        return removed


if hasattr(os, "register_at_fork"):  # POSIX: interpreter forks run the child hook (C-level forks may not)
    os.register_at_fork(after_in_child=_after_fork_in_child)
