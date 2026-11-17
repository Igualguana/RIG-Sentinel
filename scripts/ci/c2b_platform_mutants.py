"""Run the platform-specific C2-B mutants: 8 POSIX mutants or 4 native-NTFS mutants.

Usage: python scripts/ci/c2b_platform_mutants.py --profile {posix,ntfs}

Each mutant breaks one control in a temporary copy of src/ and runs the C2-B tests against it; every
mutant must make the tests fail. The script refuses to run (exit 2) when the required environment
is missing, so a missing platform is never reported as success. The repository is never modified.
Standard library only; synthetic key material only (the tests themselves enforce this).
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
S = "safepath.py"

POSIX_MUTANTS = [
    ("no O_NOFOLLOW in the directory walk",
     "            next_fd = os.open(component, flags | os.O_NOFOLLOW, dir_fd=fd)",
     "            next_fd = os.open(component, flags, dir_fd=fd)"),
    ("final directory mode not checked", "        if st.st_uid != euid or mode & 0o077:", "        if st.st_uid != euid:"),
    ("ancestor write bits not checked", "    elif st.st_uid not in (0, euid) or mode & 0o022:",
     "    elif st.st_uid not in (0, euid):"),
    ("key file mode not checked", "    if st.st_uid != euid or stat.S_IMODE(st.st_mode) & 0o077:",
     "    if st.st_uid != euid:"),
    ("hard-linked key files accepted",
     "    if st.st_nlink != 1:" + NL + "        return (StorageErrorCode.KEY_FILE_UNSAFE, \"file:links\")" + NL
     + "    if st.st_uid != euid",
     "    if st.st_uid != euid"),
    ("no O_NOFOLLOW on key file open", "    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC",
     "    flags = os.O_RDONLY | os.O_CLOEXEC"),
    ("exact mode not set after create",
     "        os.fchmod(fd, 0o600)  # umask can only remove bits; set the exact mode", "        pass"),
    ("non-canonical paths accepted", "    if os.path.realpath(path) != path:  # type: ignore[arg-type]", "    if False:"),
]
_WINDOWS_TAIL = (
    "    if st.st_nlink != 1:" + NL + "        return (StorageErrorCode.KEY_FILE_UNSAFE, \"file:links\")" + NL
    + "    if st.st_size > max_bytes:" + NL + "        return (StorageErrorCode.KEY_FILE_FORMAT, \"file:size\")" + NL
    + "    return None" + NL + NL + NL + "def _windows_read"
)
NTFS_MUTANTS = [
    ("Windows hard-link count not checked", _WINDOWS_TAIL, _WINDOWS_TAIL.split(NL, 2)[2]),
    ("post-open identity check removed",
     "            if _identity(opened) != _identity(before) or opened.st_nlink != 1:", "            if False:"),
    ("component reparse points accepted",
     "        if _is_reparse(st) or not stat.S_ISDIR(st.st_mode):" + NL
     + "            raise _fail(StorageErrorCode.UNSAFE_PATH, \"directory:reparse\")",
     "        if not stat.S_ISDIR(st.st_mode):" + NL + "            raise _fail(StorageErrorCode.UNSAFE_PATH, \"directory:reparse\")"),
    ("Windows key-file reparse points accepted",
     "    if _is_reparse(st) or not stat.S_ISREG(st.st_mode):" + NL
     + "        return (StorageErrorCode.KEY_FILE_UNSAFE, \"file:type\")" + NL + _WINDOWS_TAIL,
     "    if not stat.S_ISREG(st.st_mode):" + NL + "        return (StorageErrorCode.KEY_FILE_UNSAFE, \"file:type\")" + NL
     + _WINDOWS_TAIL),
]


def environment_problem(profile):
    if profile == "posix":
        if os.name != "posix" or os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
            return "POSIX profile needs Linux or macOS with dir_fd and O_NOFOLLOW"
        return None
    directory = os.environ.get("RIG_SENTINEL_NTFS_TEST_DIR")
    if os.name != "nt" or not directory or not os.path.isdir(directory):
        return "NTFS profile needs Windows and RIG_SENTINEL_NTFS_TEST_DIR naming an existing native NTFS directory"
    return None


def run_tests(src, junit):
    env = dict(os.environ, PYTHONPATH=str(src), PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "--tb=no", "-W", "error::Warning",
         "--junitxml", str(junit), str(REPO / "tests" / "test_audit_c2b_keyfile.py")],
        cwd=str(REPO), env=env, capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, choices=["posix", "ntfs"])
    args = parser.parse_args()
    problem = environment_problem(args.profile)
    if problem:
        print("UNSUPPORTED ENVIRONMENT (not a success): " + problem)
        return 2
    mutants = POSIX_MUTANTS if args.profile == "posix" else NTFS_MUTANTS
    work = pathlib.Path(tempfile.mkdtemp(prefix="rig-c2b-mutants-"))
    try:
        control_src = work / "control" / "src"
        shutil.copytree(REPO / "src", control_src)
        probe = subprocess.run([sys.executable, "-c", "import rig_sentinel.audit.safepath as s; print(s.__file__)"],
                               env=dict(os.environ, PYTHONPATH=str(control_src)), capture_output=True, text=True)
        if str(control_src) not in probe.stdout:
            print("CONTROL FAILED: the mutated copy would not be imported (" + probe.stdout.strip() + ")")
            return 1
        control = run_tests(control_src, work / "control.xml")
        if control.returncode != 0:
            print("CONTROL FAILED: unmutated tests do not pass" + NL + control.stdout[-2000:])
            return 1
        caught = 0
        for index, (name, old, new) in enumerate(mutants, 1):
            src = work / f"m{index}" / "src"
            shutil.copytree(REPO / "src", src)
            target = src / "rig_sentinel" / "audit" / S
            text = target.read_text(encoding="utf-8")
            if text.count(old) != 1:
                print(f"{index}. NOT APPLIED ({text.count(old)} matches): {name}")
                continue
            target.write_text(text.replace(old, new), encoding="utf-8")
            result = run_tests(src, work / f"m{index}.xml")
            status = "CAUGHT" if result.returncode != 0 else "NOT CAUGHT"
            caught += status == "CAUGHT"
            print(f"{index}. [{status}] {name}")
        print(f"profile {args.profile}: caught {caught}/{len(mutants)}")
        return 0 if caught == len(mutants) else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
