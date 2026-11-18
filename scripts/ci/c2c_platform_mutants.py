"""Run the C2-C (audit-storage) mutants: portable, POSIX-native, Linux-native or NTFS-native profile.

Usage: python scripts/ci/c2c_platform_mutants.py --profile {portable,posix,linux,ntfs}

Each mutant weakens one control in a temporary copy of src/ and runs tests/test_audit_c2c_safefs.py
against it; every mutant must make the tests fail. The repository is never modified. A missing
platform exits 2 ("unsupported, not a success"); a timeout counts as a failure of the run. Separate
from c2b_platform_mutants.py (C2-B coverage unchanged). Standard library only; synthetic data only.
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
TEST = "tests/test_audit_c2c_safefs.py"
TIMEOUT = 900

PORTABLE = [
    ("Windows write refusal removed (capability check reached instead)",
     "        windows = self._kind != \"posix\"" + NL + "        if windows:",
     "        windows = False" + NL + "        if windows:"),
    ("POSIX capability check removed",
     "        if not _posix_write_capable():" + NL
     + "            raise _fail(StorageErrorCode.UNSUPPORTED_PLATFORM, \"file:write-platform\")",
     "        if False:" + NL + "            raise _fail(StorageErrorCode.UNSUPPORTED_PLATFORM, \"file:write-platform\")"),
    ("create_exclusive does not refuse first",
     "        self._require_posix_write()" + NL + "        checked = check_chain_member_name(name, kind=\"segment\")" + NL
     + "        limit = _check_limit(max_size, MAX_FILE_BYTES, \"file:max-size\")" + NL + "        dfd = self._dup_dir()" + NL
     + "        try:" + NL + "            fd, st = _posix_create_member(",
     "        checked = check_chain_member_name(name, kind=\"segment\")" + NL
     + "        limit = _check_limit(max_size, MAX_FILE_BYTES, \"file:max-size\")" + NL + "        dfd = self._dup_dir()" + NL
     + "        try:" + NL + "            fd, st = _posix_create_member("),
    ("open_append does not refuse first",
     "        self._require_posix_write()" + NL + "        checked = check_chain_member_name(name, kind=\"segment\")" + NL
     + "        limit = _check_limit(max_size, MAX_FILE_BYTES, \"file:max-size\")" + NL + "        dfd = self._dup_dir()" + NL
     + "        try:" + NL + "            fd, st = _posix_open_append_member(",
     "        checked = check_chain_member_name(name, kind=\"segment\")" + NL
     + "        limit = _check_limit(max_size, MAX_FILE_BYTES, \"file:max-size\")" + NL + "        dfd = self._dup_dir()" + NL
     + "        try:" + NL + "            fd, st = _posix_open_append_member("),
    ("replace_atomically does not refuse first",
     "        self._require_posix_write()" + NL + "        if type(name) is not str or name != ANCHOR_NAME:",
     "        if type(name) is not str or name != ANCHOR_NAME:"),
    ("link_no_replace does not refuse first",
     "        self._require_posix_write()" + NL + "        checked_source =", "        checked_source ="),
    ("remove_created does not refuse first",
     "        self._require_posix_write()" + NL + "        if type(token) is not CreatedToken:",
     "        if type(token) is not CreatedToken:"),
    ("open_chain(create=True) does not refuse first",
     "            self._require_posix_write()" + NL + "        self._require_open()", "        self._require_open()"),
    ("segment names accept key files", r'_SEGMENT_RE = re.compile(r"seg-(?:0|[1-9][0-9]{0,15})\.jsonl")',
     r'_SEGMENT_RE = re.compile(r"seg-(?:0|[1-9][0-9]{0,15})\.jsonl|[a-z]+\.key")'),
    ("segment names accept leading zeros", r'_SEGMENT_RE = re.compile(r"seg-(?:0|[1-9][0-9]{0,15})\.jsonl")',
     r'_SEGMENT_RE = re.compile(r"seg-[0-9]{1,16}\.jsonl")'),
    ("chain directory names accept uppercase", r'_CHAIN_DIR_RE = re.compile(r"chain-[0-9a-f]{32}")',
     r'_CHAIN_DIR_RE = re.compile(r"chain-[0-9a-fA-F]{32}")'),
    ("quarantine accepts q8/q9", r'_QUARANTINE_RE = re.compile(r"\.seq_anchor\.q[0-7]")',
     r'_QUARANTINE_RE = re.compile(r"\.seq_anchor\.q[0-9]")'),
    ("caller limits not range-checked", "    if type(value) is not int or not 1 <= value <= upper:",
     "    if type(value) is not int:"),
    ("anchor size limit not enforced",
     "        if len(data) > limit:" + NL + "            raise _fail(StorageErrorCode.FILE_TOO_LARGE, \"file:limit\")",
     "        if False:" + NL + "            raise _fail(StorageErrorCode.FILE_TOO_LARGE, \"file:limit\")"),
    ("closed token accepted",
     "        if token._closed:" + NL + "            raise _fail(StorageErrorCode.FILE_UNSAFE, \"token:closed\")",
     "        if False:" + NL + "            raise _fail(StorageErrorCode.FILE_UNSAFE, \"token:closed\")"),
    ("durability always reported as FULLFSYNC",
     "    return Durability.FULLFSYNC if all(level is Durability.FULLFSYNC for level in levels) else Durability.FSYNC",
     "    return Durability.FULLFSYNC"),
    ("token repr leaks the file name", '        return f"CreatedToken(closed={self._closed})"',
     '        return f"CreatedToken(closed={self._closed}, name={self._name})"'),
    ("objects become picklable", '        raise TypeError(f"{type(self).__name__} cannot be pickled")',
     "        return object.__reduce_ex__(self, protocol)"),
    ("mountinfo: extra fields accepted", "        if len(fields) != separator + 4:", "        if len(fields) < separator + 4:"),
    ("mountinfo: NUL escape accepted", "        if value == 0 or value > 0xFF:", "        if value > 0xFF:"),
    ("mountinfo: non-ASCII accepted",
     "        if not line or len(line) > MAX_MOUNTINFO_LINE_BYTES or any(b < 0x20 or b > 0x7E for b in line):",
     "        if not line or len(line) > MAX_MOUNTINFO_LINE_BYTES or any(b < 0x20 for b in line):"),
    ("mountinfo: line length unbounded",
     "        if not line or len(line) > MAX_MOUNTINFO_LINE_BYTES or any(b < 0x20 or b > 0x7E for b in line):",
     "        if not line or any(b < 0x20 or b > 0x7E for b in line):"),
    ("mountinfo: line count unbounded", "    if len(lines) > MAX_MOUNTINFO_LINES:", "    if False:"),
    ("mountinfo: prefix not at a component boundary",
     '    return mount_point == b"/" or path == mount_point or path.startswith(mount_point + b"/")',
     '    return mount_point == b"/" or path == mount_point or path.startswith(mount_point)'),
    ("mountinfo: ambiguous tie accepted", "    if len(types) != 1:", "    if not types:"),
    ("nfs4 not refused", 'b"nfs", b"nfs4", b"cifs"', 'b"nfs", b"cifs"'),
    ("tmpfs not refused (H2)", '    b"tmpfs", b"ramfs",  # C2-C-H2', '    b"ramfs",  # C2-C-H2'),
    ("ramfs not refused (H2)", '    b"tmpfs", b"ramfs",  # C2-C-H2', '    b"tmpfs",  # C2-C-H2'),
    ("fuse.* not refused", '    return fstype in _REFUSED_FILESYSTEMS or fstype.startswith(b"fuse.")',
     "    return fstype in _REFUSED_FILESYSTEMS"),
    ("unreadable mountinfo accepted",
     '        return (StorageErrorCode.UNSUPPORTED_FILESYSTEM, "mountinfo:unreadable")', "        return None"),
    ("malformed mountinfo accepted", "        return (error.code, error.path)" + NL + "    if _is_refused_filesystem(fstype):",
     "        return None" + NL + "    if _is_refused_filesystem(fstype):"),
]

POSIX = [
    ("O_NOFOLLOW removed from chain-directory open",
     "    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC",
     "    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC"),
    ("chain-directory owner/mode check removed", "        code = _posix_directory_problem(st, euid, final=True)",
     "        code = None"),
    ("created chain directory not chmod-ed",
     "            os.fchmod(fd, 0o700)  # umask can only remove bits; set the exact mode on what we created",
     "            pass"),
    ("chain-directory identity re-check removed",
     "        elif _identity(_named_identity(dfd, name)) != _identity(st):" + NL
     + "            problem = (StorageErrorCode.UNSAFE_PATH, \"directory:changed\")",
     "        elif False:" + NL + "            problem = (StorageErrorCode.UNSAFE_PATH, \"directory:changed\")"),
    ("O_NOFOLLOW removed from read open",
     "    flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, \"O_NOCTTY\", 0)" + NL
     + "             | getattr(os, \"O_NONBLOCK\", 0))",
     "    flags = (os.O_RDONLY | os.O_CLOEXEC | getattr(os, \"O_NOCTTY\", 0)" + NL
     + "             | getattr(os, \"O_NONBLOCK\", 0))"),
    ("O_NOFOLLOW removed from append open",
     "    flags = (os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, \"O_NOCTTY\", 0)",
     "    flags = (os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | getattr(os, \"O_NOCTTY\", 0)"),
    ("O_EXCL removed from segment create",
     "    flags = (os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW",
     "    flags = (os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW"),
    ("member type/links/owner/mode check removed",
     "        label = _private_file_label(st, euid)" + NL + "        if label is not None:" + NL
     + "            problem = (StorageErrorCode.FILE_UNSAFE, label)" + NL + "        elif st.st_size > max_size:",
     "        label = None" + NL + "        if label is not None:" + NL
     + "            problem = (StorageErrorCode.FILE_UNSAFE, label)" + NL + "        elif st.st_size > max_size:"),
    ("member size bound removed", "        elif st.st_size > max_size:", "        elif False:"),
    ("member identity re-check removed",
     "        elif _identity(_named_identity(dfd, name)) != _identity(st):" + NL
     + "            problem = (StorageErrorCode.FILE_UNSAFE, \"file:changed\")",
     "        elif False:" + NL + "            problem = (StorageErrorCode.FILE_UNSAFE, \"file:changed\")"),
    ("created member not chmod-ed", "            os.fchmod(fd, 0o600)" + NL + "        else:", "            pass" + NL + "        else:"),
    ("append pre-check of links/owner/mode removed",
     "            label = _private_file_label(st, euid)" + NL + "            if label is None and (_identity(st)",
     "            label = None" + NL + "            if label is None and (_identity(st)"),
    ("append size tracking removed", " or st.st_size != self._size):", "):"),
    ("short write accepted", "                if written != len(data):", "                if written < 0:"),
    ("append failure does not seal",
     "        if problem is not None:" + NL + "            self._sealed = True" + NL + "            raise _fail(*problem)",
     "        if problem is not None:" + NL + "            raise _fail(*problem)"),
    ("sync failure does not seal",
     "        self._sealed = True" + NL + "        raise _fail(StorageErrorCode.DURABILITY_FAILED, \"file:sync\")",
     "        raise _fail(StorageErrorCode.DURABILITY_FAILED, \"file:sync\")"),
    ("verify_name never detects", "            problem = _identity(named) != self._identity or not stat.S_ISREG(named.st_mode)",
     "            problem = False"),
    ("O_EXCL removed from anchor temp",
     "    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, \"O_NOCTTY\", 0))",
     "    flags = (os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, \"O_NOCTTY\", 0))"),
    ("anchor target type check removed",
     "                if target is not None and (not stat.S_ISREG(target.st_mode) or target.st_nlink != 1):",
     "                if False:"),
    ("temp identity check before replace removed",
     "            if _identity(_named_identity(dfd, temp)) != identity:", "            if False:"),
    ("anchor identity check after replace removed",
     "            if _identity(_named_identity(dfd, name)) != identity:" + NL
     + "                problem = (StorageErrorCode.FILE_UNSAFE, \"file:replaced\")  # detection only",
     "            if False:" + NL + "                problem = (StorageErrorCode.FILE_UNSAFE, \"file:replaced\")  # detection only"),
    ("directory-sync failure after replace ignored",
     "            problem = (StorageErrorCode.DURABILITY_UNCERTAIN, \"directory:sync-after-replace\")", "            pass"),
    ("temp sync failure ignored",
     "                problem = (StorageErrorCode.DURABILITY_FAILED, \"file:sync\")" + NL + "        if problem is None:" + NL
     + "            if _identity(_named_identity(dfd, temp)) != identity:",
     "                pass" + NL + "        if problem is None:" + NL
     + "            if _identity(_named_identity(dfd, temp)) != identity:"),
    ("failed replace leaves its temp behind",
     "        _posix_unlink_if_ours(dfd, temp, fd, identity)  # our temp only; anything else is left alone",
     "        pass"),
    ("quarantine clobbers via replace",
     "            os.link(source, target, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)  # never clobbers",
     "            os.replace(source, target, src_dir_fd=dfd, dst_dir_fd=dfd)"),
    ("quarantine source link count not checked",
     "        label = _private_file_label(st, euid)  # S0 requires exactly one link", "        label = None"),
    ("cleanup ignores substitution",
     "        if _identity(named) != identity or not stat.S_ISREG(named.st_mode):" + NL + "            return \"file:substituted\"",
     "        if False:" + NL + "            return \"file:substituted\""),
    ("cleanup ignores extra links", "        if named.st_nlink != 1:" + NL + "            return \"file:links\"",
     "        if False:" + NL + "            return \"file:links\""),
    ("cleanup race not reported",
     "        if os.fstat(fd).st_nlink != 0:" + NL + "            return \"file:cleanup-race\"",
     "        if False:" + NL + "            return \"file:cleanup-race\""),
    ("moved object treated as gone", "            return \"file:moved\"", "            return None"),
    ("token directory not checked",
     "            if _identity(os.fstat(token._dfd)) != _identity(os.fstat(self._fd)):  # type: ignore[arg-type]",
     "            if False:"),
    ("listing bound removed",
     "        with os.scandir(dfd) as entries:" + NL + "            for entry in entries:" + NL
     + "                count += 1" + NL + "                if count > max_entries:",
     "        with os.scandir(dfd) as entries:" + NL + "            for entry in entries:" + NL
     + "                count += 1" + NL + "                if False:"),
    ("filesystem policy skipped for the audit root",
     "            problem = _linux_filesystem_problem(fd, path)  # type: ignore[arg-type]", "            problem = None"),
    ("filesystem policy skipped for chain directories",
     "            problem = _linux_filesystem_problem(fd, child_path)", "            problem = None"),
    ("read handle ignores growth", "            if now.st_nlink != 1 or not _stable(self._opened, now):",
     "            if now.st_nlink != 1:"),
]

LINUX = [
    ("descriptor leaked on a failed member open",
     "        _close_quietly(fd)" + NL + "        raise _fail(*problem)" + NL + "    return fd, st  # type: ignore[return-value]",
     "        raise _fail(*problem)" + NL + "    return fd, st  # type: ignore[return-value]"),
]

NTFS = [
    ("Windows member link count not checked",
     "        elif before.st_nlink != 1:" + NL + "            problem = (StorageErrorCode.FILE_UNSAFE, \"file:links\")",
     "        elif False:" + NL + "            problem = (StorageErrorCode.FILE_UNSAFE, \"file:links\")"),
    ("Windows read handle ignores growth", "            if now.st_nlink != 1 or not _stable(self._opened, now):",
     "            if now.st_nlink != 1:"),
]

PROFILES = {"portable": PORTABLE, "posix": POSIX, "linux": LINUX, "ntfs": NTFS}


def environment_problem(profile):
    if profile == "portable":
        return None
    if profile in ("posix", "linux"):
        capable = (os.name == "posix" and os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")
                   and os.link in os.supports_follow_symlinks and os.scandir in os.supports_fd)
        if not capable:
            return "POSIX profile needs Linux or macOS with dir_fd, O_NOFOLLOW, linkat and fd scandir"
        if profile == "linux" and sys.platform != "linux":
            return "Linux profile needs Linux"
        return None
    directory = os.environ.get("RIG_SENTINEL_NTFS_TEST_DIR")
    if os.name != "nt" or not directory or not os.path.isdir(directory):
        return "NTFS profile needs Windows and RIG_SENTINEL_NTFS_TEST_DIR naming an existing native NTFS directory"
    return None


def run_tests(src):
    env = dict(os.environ, PYTHONPATH=str(src), PYTHONDONTWRITEBYTECODE="1")
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
    work = pathlib.Path(tempfile.mkdtemp(prefix="rig-c2c-mutants-"))
    try:
        control_src = work / "control" / "src"
        shutil.copytree(REPO / "src", control_src)
        try:
            probe = subprocess.run([sys.executable, "-c", "import rig_sentinel.audit.safepath as s; print(s.__file__)"],
                                   env=dict(os.environ, PYTHONPATH=str(control_src)), capture_output=True, text=True,
                                   timeout=120)
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
            shutil.copytree(REPO / "src", src)
            target = src / "rig_sentinel" / "audit" / "safepath.py"
            text = target.read_text(encoding="utf-8")
            if text.count(old) != 1:
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
