"""Remove the CI NTFS test directory without ever following a junction or symbolic link.

Usage: python scripts/ci/remove_ntfs_test_dir.py

Only the directory named by RIG_SENTINEL_NTFS_TEST_DIR is removed, and only when it is a canonical direct
child, named rig-ntfs-*, of RIG_NTFS_BASE, which must itself be the canonical system temporary directory
(both are exported by prepare_ntfs_test_dir.py). Reparse points (junctions, symlinks) are removed as
links; their targets are never entered. Standard library only.
"""

import os
import stat
import sys
import tempfile

REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def is_link(st):
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & REPARSE)


def remove_entry(path):
    st = os.lstat(path)
    if is_link(st):
        try:
            os.rmdir(path)  # directory junction or directory symlink: removes the link only
        except OSError:
            os.unlink(path)  # file symlink
        return
    if stat.S_ISDIR(st.st_mode):
        for name in os.listdir(path):
            remove_entry(os.path.join(path, name))
        os.rmdir(path)
        return
    try:
        os.unlink(path)
    except PermissionError:
        os.chmod(path, stat.S_IWRITE)
        os.unlink(path)


def main():
    target = os.environ.get("RIG_SENTINEL_NTFS_TEST_DIR", "")
    base = os.environ.get("RIG_NTFS_BASE", "")
    if not target or not base:
        print("nothing to remove: RIG_SENTINEL_NTFS_TEST_DIR or RIG_NTFS_BASE is not set")
        return 0
    if base != os.path.realpath(tempfile.gettempdir()):
        print("REFUSED: RIG_NTFS_BASE is not the canonical system temporary directory")
        return 1
    if (os.path.dirname(target) != base or not os.path.basename(target).startswith("rig-ntfs-")
            or os.path.realpath(target) != target):
        print("REFUSED: " + target + " is not a canonical rig-ntfs-* directory directly under " + base)
        return 1
    if not os.path.lexists(target):
        print("already removed: " + target)
        return 0
    if is_link(os.lstat(target)):
        print("REFUSED: the test directory itself is a reparse point")
        return 1
    remove_entry(target)
    print("removed: " + target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
