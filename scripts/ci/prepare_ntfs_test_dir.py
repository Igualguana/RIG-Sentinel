"""Create the isolated native NTFS test directory for Windows CI, or fail the job with a clear reason.

Usage: python scripts/ci/prepare_ntfs_test_dir.py --label <py3.13|mutants>

The directory is created directly under the canonical system temporary directory. Every precondition
is checked; any failure exits non-zero with "NTFS PRECONDITION FAILED". Nothing changes filesystem
configuration, ACLs or security policy: the checks are read-only queries plus creating (and
removing) one probe subdirectory inside the new test directory. On success the job environment
receives RIG_SENTINEL_NTFS_TEST_DIR and RIG_NTFS_BASE. Standard library only.
"""

import argparse
import os
import re
import stat
import sys
import tempfile

REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
MAX_WIDE_PATH = 32768  # extended-length path limit in UTF-16 units, including the terminator
PROBE_NAME = "averylongprobedirectoryname_8dot3"


class PreconditionFailed(Exception):
    pass


def _kernel32():
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetVolumePathNameW.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
    kernel32.GetVolumePathNameW.restype = wintypes.BOOL
    kernel32.GetVolumeInformationW.argtypes = (
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD)
    kernel32.GetVolumeInformationW.restype = wintypes.BOOL
    kernel32.GetShortPathNameW.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
    kernel32.GetShortPathNameW.restype = wintypes.DWORD
    return ctypes, wintypes, kernel32


def filesystem_of(path):
    ctypes, wintypes, kernel32 = _kernel32()
    root = ctypes.create_unicode_buffer(MAX_WIDE_PATH)
    if not kernel32.GetVolumePathNameW(path, root, MAX_WIDE_PATH):
        raise PreconditionFailed(f"cannot resolve the volume of {path}: {ctypes.WinError(ctypes.get_last_error())}")
    name = ctypes.create_unicode_buffer(261)  # MAX_PATH + 1, as documented for this API
    serial, max_component, flags = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
    if not kernel32.GetVolumeInformationW(root.value, None, 0, ctypes.byref(serial), ctypes.byref(max_component),
                                          ctypes.byref(flags), name, len(name)):
        raise PreconditionFailed(f"cannot query the filesystem of {root.value}: "
                                 f"{ctypes.WinError(ctypes.get_last_error())}")
    return root.value, name.value


def short_path(path):
    ctypes, _wintypes, kernel32 = _kernel32()
    buffer = ctypes.create_unicode_buffer(MAX_WIDE_PATH)
    length = kernel32.GetShortPathNameW(path, buffer, MAX_WIDE_PATH)
    if length == 0:
        raise PreconditionFailed(f"GetShortPathNameW failed for {path}: {ctypes.WinError(ctypes.get_last_error())}")
    if length >= MAX_WIDE_PATH:
        raise PreconditionFailed(f"short name of {path} exceeds the bounded buffer")
    return buffer.value


def is_reparse(st):
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & REPARSE)


def prepare(label):
    if os.name != "nt":
        raise PreconditionFailed("native NTFS tests need Windows")
    base = os.path.realpath(tempfile.gettempdir())
    if not os.path.isdir(base) or is_reparse(os.lstat(base)):
        raise PreconditionFailed(f"system temporary directory {base} is missing or is a reparse point")
    volume, filesystem = filesystem_of(base)
    print(f"system temporary directory: {base} (volume {volume}, filesystem {filesystem})")
    if filesystem != "NTFS":
        raise PreconditionFailed(f"{base} is on {filesystem or 'an unknown filesystem'}, not NTFS")
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "0")
    name = f"rig-ntfs-{run_id}-{attempt}-{label}"
    if not re.fullmatch(r"rig-ntfs-[A-Za-z0-9.-]{1,80}", name):
        raise PreconditionFailed(f"unexpected test directory name {name!r}")
    target = os.path.join(base, name)
    if os.path.lexists(target):
        raise PreconditionFailed(f"{target} already exists; refusing to reuse it")
    os.mkdir(target)  # fails if anything appeared in the meantime: the directory is new
    env_file = os.environ.get("GITHUB_ENV")
    if env_file:  # export first, so the always() cleanup step can remove the directory on failure
        with open(env_file, "a", encoding="utf-8") as handle:
            handle.write(f"RIG_SENTINEL_NTFS_TEST_DIR={target}\nRIG_NTFS_BASE={base}\n")
    st = os.lstat(target)
    if is_reparse(st) or not stat.S_ISDIR(st.st_mode) or os.path.realpath(target) != target:
        raise PreconditionFailed(f"{target} is not a new, canonical, ordinary directory")
    if os.listdir(target):
        raise PreconditionFailed(f"{target} is not empty")
    probe = os.path.join(target, PROBE_NAME)
    os.mkdir(probe)
    try:
        alias = short_path(probe)
    finally:
        os.rmdir(probe)
    if alias == probe:
        raise PreconditionFailed(f"8.3 short names are not generated on volume {volume}: CI blocker "
                                 "(the short-name test is mandatory; filesystem configuration is not changed)")
    print(f"8.3 short names supported on {volume} (probe alias {alias})")
    print(f"native NTFS test directory: {target}")
    return target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    args = parser.parse_args()
    try:
        prepare(args.label)
    except (PreconditionFailed, OSError) as error:
        print("NTFS PRECONDITION FAILED: " + str(error))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
