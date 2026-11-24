"""Fail CI unless the C3 writer tests and mutants really executed as required (Genesis B2-M2-C3-H3).

Usage:
  python scripts/ci/assert_c3_native_coverage.py --junit c3-junit.xml --profile {linux,macos,windows-portable}
  python scripts/ci/assert_c3_native_coverage.py --mutants-log c3-mutants-posix.log --mutant-profile posix
  python scripts/ci/assert_c3_native_coverage.py --mutants-log c3-mutants-portable.log --mutant-profile portable

JUnit mode reads the report of ``pytest tests/test_audit_c3_writer.py`` and fails unless:
* the exact native inventory (21 ``test_native_*`` cases, including the five SIGKILL crash-matrix scenarios) and
  the exact portable inventory (157 cases) were collected: nothing missing, nothing unexpected;
* no case failed or errored;
* ``linux``: all 21 native cases passed (zero skips anywhere);
* ``macos``: the 20 applicable native cases passed and exactly one case was skipped, namely
  ``test_native_no_descriptor_leak_in_verify`` with the reason ``Linux-only descriptor count`` (it counts
  descriptors through ``/proc/self/fd``). It is reported as SKIPPED BY POLICY, never as passed;
* ``windows-portable``: all 157 portable cases passed and every native case was skipped with exactly the
  POSIX-tier reason (portable regression only; no native evidence is claimed).

Mutant-log mode reads the output of ``scripts/ci/c3_platform_mutants.py`` and fails unless the control line shows
zero skips, every expected mutant id has a ``[CAUGHT]`` line, no line is NOT APPLIED / NOT CAUGHT / TIMEOUT /
ERROR / UNSUPPORTED, and the summary is exactly ``profile <p>: caught N/N`` with N the expected count.

The inventories must be updated together with the tests or the runner; a stale list fails closed.
Standard library only.
"""

import argparse
import re
import sys
import xml.etree.ElementTree as ET

MODULE = "tests.test_audit_c3_writer"
POSIX_TIER_REASON = "POSIX-only (flock, dir_fd): native tier"
LINUX_ONLY_TEST = "test_native_no_descriptor_leak_in_verify"
LINUX_ONLY_REASON = "Linux-only descriptor count"
CRASH_SCENARIOS = ("append", "size", "epoch", "auth", "chain")

NATIVE = (
    "test_native_genesis_append_rotation_close_resume_verify",
    "test_native_adopted_directory_with_open_permissions_is_refused_at_g3[488]",
    "test_native_adopted_directory_with_open_permissions_is_refused_at_g3[455]",
    "test_native_created_directory_is_private_regardless_of_umask",
    "test_native_second_writer_is_locked_out",
    "test_native_chain_directory_substitution_seals_and_writes_nothing_new",
    "test_native_verify_chain_named_detects_substitution[missing]",
    "test_native_verify_chain_named_detects_substitution[dir]",
    "test_native_verify_chain_named_detects_substitution[symlink]",
    "test_native_verify_chain_named_detects_substitution[file]",
    "test_native_verify_chain_named_root_level_move_is_the_documented_residual",
    "test_native_forked_child_cannot_write",
    "test_native_verify_chain_named_rejects_a_chain_from_a_foreign_root",
    "test_native_verify_chain_named_fails_closed_on_errors",
    "test_native_verify_chain_named_other_os_errors_fail_closed",
) + tuple(f"test_native_crash_matrix_sigkill_at_every_write_boundary[{s}]" for s in CRASH_SCENARIOS) + (
    LINUX_ONLY_TEST,
)
EXPECTED_NATIVE = 21
EXPECTED_PORTABLE = 157
EXPECTED_MUTANTS = {"portable": 65, "posix": 8}
POSIX_MUTANT_IDS = ("V1", "V3", "V4", "V5", "V7", "V8", "V10", "M-NAT-1")
JUNIT_PROFILES = ("linux", "macos", "windows-portable")


def read_cases(path):
    """{name: (state, skip reason)} for the C3 module; duplicates are an error."""
    cases = {}
    duplicates = []
    for case in ET.parse(path).getroot().iter("testcase"):
        if case.get("classname") != MODULE:
            continue
        name = case.get("name") or ""
        skipped = case.find("skipped")
        if case.find("failure") is not None or case.find("error") is not None:
            state, reason = "failed", ""
        elif skipped is not None:
            state, reason = "skipped", (skipped.get("message") or "").strip()
        else:
            state, reason = "passed", ""
        if name in cases:
            duplicates.append(name)
        cases[name] = (state, reason)
    return cases, duplicates


def check_junit(path, profile):
    problems = []
    cases, duplicates = read_cases(path)
    problems += [f"duplicate test case: {name}" for name in duplicates]
    native_seen = {name for name in cases if name.startswith("test_native_")}
    portable = {name: value for name, value in cases.items() if not name.startswith("test_native_")}
    expected = set(NATIVE)
    problems += [f"native test not collected: {name}" for name in sorted(expected - native_seen)]
    problems += [f"unexpected native test (update the inventory): {name}" for name in sorted(native_seen - expected)]
    if len(NATIVE) != EXPECTED_NATIVE or len(expected) != EXPECTED_NATIVE:
        problems.append("internal: native inventory is not 21 distinct cases")
    if len(portable) != EXPECTED_PORTABLE:
        problems.append(f"portable inventory: {len(portable)} cases collected, expected {EXPECTED_PORTABLE}")
    for scenario in CRASH_SCENARIOS:
        name = f"test_native_crash_matrix_sigkill_at_every_write_boundary[{scenario}]"
        if name not in cases:
            problems.append(f"crash-matrix scenario missing: {scenario}")
    problems += [f"failed: {name}" for name, (state, _) in sorted(cases.items()) if state == "failed"]
    for name, (state, reason) in sorted(portable.items()):
        if state != "passed":
            problems.append(f"portable test {state}: {name}" + (f" ({reason})" if reason else ""))
    passed = skipped_by_policy = tier_skipped = 0
    for name in NATIVE:
        state, reason = cases.get(name, ("missing", ""))
        if profile == "linux":
            ok = state == "passed"
        elif profile == "macos":
            if name == LINUX_ONLY_TEST:
                ok = state == "skipped" and reason == LINUX_ONLY_REASON
                skipped_by_policy += ok
                if not ok:
                    problems.append(f"{name}: expected SKIPPED with reason {LINUX_ONLY_REASON!r} on macOS, got "
                                    f"{state}" + (f" ({reason!r})" if reason else ""))
                continue
            ok = state == "passed"
        else:  # windows-portable: the native tier must be skipped for exactly the POSIX-tier reason
            ok = state == "skipped" and reason == POSIX_TIER_REASON
            tier_skipped += ok
        if ok:
            passed += profile != "windows-portable"
        else:
            problems.append(f"{name}: {state}" + (f" ({reason!r})" if reason else ""))
    if profile == "linux":
        print(f"profile linux: {passed}/{EXPECTED_NATIVE} native C3 tests passed; 0 skips allowed")
    elif profile == "macos":
        print(f"profile macos: {passed}/{EXPECTED_NATIVE - 1} applicable native C3 tests passed; "
              f"{skipped_by_policy}/1 SKIPPED BY POLICY ({LINUX_ONLY_TEST}: Linux-only, not passed)")
    else:
        print(f"profile windows-portable: native tier skipped with the POSIX-tier reason: {tier_skipped}/"
              f"{EXPECTED_NATIVE} (required; no native evidence is claimed)")
    print(f"portable C3 tests: {sum(1 for s, _ in portable.values() if s == 'passed')}/{EXPECTED_PORTABLE} passed")
    return problems


SUMMARY_RE = re.compile(r"^profile (portable|posix): caught (\d+)/(\d+)$")
CAUGHT_RE = re.compile(r"^(\S+)\. \[CAUGHT\] ")
BAD_RE = re.compile(r"NOT APPLIED|NOT CAUGHT|\[TIMEOUT\]|\[ERROR|ERROR \(pytest exit|UNSUPPORTED|CONTROL FAILED|INVALID MUTANT")
CONTROL_RE = re.compile(r"^control: (\d+) killing tests passed, 0 skipped$")


def check_mutants(path, profile):
    problems = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        lines = [line.rstrip("\r\n") for line in handle]
    expected = EXPECTED_MUTANTS[profile]
    if not any(CONTROL_RE.match(line) for line in lines):
        problems.append("no control line with zero skipped killing tests")
    problems += [f"bad line: {line}" for line in lines if BAD_RE.search(line)]
    caught = [CAUGHT_RE.match(line).group(1) for line in lines if CAUGHT_RE.match(line)]
    if len(caught) != len(set(caught)):
        problems.append("a mutant id is reported more than once")
    if profile == "posix" and set(caught) != set(POSIX_MUTANT_IDS):
        problems.append(f"posix mutants caught {sorted(caught)}, expected exactly {sorted(POSIX_MUTANT_IDS)}")
    summaries = [SUMMARY_RE.match(line) for line in lines if SUMMARY_RE.match(line)]
    if len(summaries) != 1:
        problems.append(f"expected exactly one summary line, found {len(summaries)}")
    else:
        match = summaries[0]
        found = (match.group(1), int(match.group(2)), int(match.group(3)))
        if found != (profile, expected, expected):
            problems.append(f"summary {found}, expected ({profile!r}, {expected}, {expected})")
    if len(caught) != expected:
        problems.append(f"{len(caught)} [CAUGHT] lines, expected {expected}")
    print(f"mutant profile {profile}: {len(caught)}/{expected} caught lines; summary lines {len(summaries)}")
    return problems


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--junit")
    parser.add_argument("--profile", choices=JUNIT_PROFILES)
    parser.add_argument("--mutants-log")
    parser.add_argument("--mutant-profile", choices=sorted(EXPECTED_MUTANTS))
    args = parser.parse_args()
    junit_mode = args.junit is not None or args.profile is not None
    mutant_mode = args.mutants_log is not None or args.mutant_profile is not None
    if junit_mode == mutant_mode or (junit_mode and not (args.junit and args.profile)) or (
            mutant_mode and not (args.mutants_log and args.mutant_profile)):
        parser.error("use exactly one mode: --junit with --profile, or --mutants-log with --mutant-profile")
    try:
        problems = check_junit(args.junit, args.profile) if junit_mode else check_mutants(args.mutants_log,
                                                                                         args.mutant_profile)
    except (OSError, ET.ParseError) as error:
        problems = [f"cannot read the report: {type(error).__name__}"]
    if problems:
        print("C3 COVERAGE FAILURE (skipped, missing, failed, unsupported or incomplete is not a success):")
        for problem in problems:
            print("  - " + problem)
        return 1
    print("C3 coverage requirements met")
    return 0


if __name__ == "__main__":
    sys.exit(main())
