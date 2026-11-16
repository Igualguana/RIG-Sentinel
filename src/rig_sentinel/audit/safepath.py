"""Safe filesystem primitives for key files (Genesis B2-M2-C2-B, minimum C2-C subset).

The only audit module allowed to touch the filesystem (founder decision F11, D-C2-3/D-C2-4).
It provides exactly what C2-B key files need: path rules, opening a key directory safely,
and reading or exclusively creating one small private file in it. There is no writer lock,
segment, anchor or recovery code here.

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
"""

from __future__ import annotations

import errno
import os
import re
import stat
from dataclasses import dataclass

try:  # POSIX only; used solely for F_FULLFSYNC on macOS (D-C2-4)
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

from rig_sentinel.audit.storage_errors import StorageError, StorageErrorCode

__all__ = [
    "MAX_COMPONENTS",
    "MAX_POSIX_PATH_BYTES",
    "MAX_WINDOWS_PATH",
    "SafeDirectory",
    "WindowsAttestation",
    "check_file_name",
    "check_posix_path",
    "check_windows_path",
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
