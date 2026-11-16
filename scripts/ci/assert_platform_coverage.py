"""Fail CI unless the platform-specific security tests for this runner really executed and passed.

Usage: python scripts/ci/assert_platform_coverage.py --junit pytest-junit.xml --profile {linux,macos,windows-ntfs}

pytest skips platform tests when their environment is missing (no POSIX host, no NTFS directory).
That is right for local runs but must not pass silently in CI: this guard reads the JUnit report
and fails, with a clear message, unless every required test for the profile passed. Standard
library only.
"""

import argparse
import sys
import xml.etree.ElementTree as ET

MODULE = "tests.test_audit_c2b_keyfile"

NTFS = [
    "test_ntfs_stream_probe_classifies_the_directory",
    "test_ntfs_key_creation_is_refused_before_any_write",
    "test_ntfs_load_planted_synthetic_key",
    "test_ntfs_key_set_loads_independent_synthetic_keys",
    "test_ntfs_hard_link_is_refused",
    "test_ntfs_junction_components_are_refused",
    "test_ntfs_junction_inserted_after_open_is_refused",
    "test_ntfs_symlinked_key_file_is_refused",
    "test_ntfs_swapped_final_file_is_caught_by_identity",
    "test_ntfs_alternate_stream_does_not_change_loading",
    "test_ntfs_open_key_file_cannot_be_replaced",
    "test_ntfs_short_name_alias_is_refused",
    "test_ntfs_two_flip_read_race_is_detected_as_unsafe_path",
    "test_ntfs_four_flip_read_race_is_stopped_only_by_the_pin",
    "test_ntfs_create_race_path_is_unreachable",
]
POSIX = [
    "test_posix_create_and_load_with_pin",
    "test_posix_symlinks_are_refused",
    "test_posix_unsafe_key_modes_are_refused[416]",
    "test_posix_unsafe_key_modes_are_refused[388]",
    "test_posix_unsafe_key_modes_are_refused[432]",
    "test_posix_unsafe_directories_are_refused",
    "test_posix_hard_link_and_fifo_are_refused",
    "test_posix_held_directory_survives_rename",
    "test_posix_non_canonical_path_is_refused",
]
LINUX = ["test_posix_world_writable_ancestor_is_refused"]
PROFILES = {"windows-ntfs": NTFS, "linux": POSIX + LINUX, "macos": POSIX}


def outcomes(path):
    results = {}
    for case in ET.parse(path).getroot().iter("testcase"):
        if case.get("classname") != MODULE:
            continue
        if case.find("skipped") is not None:
            state = "skipped"
        elif case.find("failure") is not None or case.find("error") is not None:
            state = "failed"
        else:
            state = "passed"
        results[case.get("name")] = state
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--junit", required=True)
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES))
    args = parser.parse_args()
    results = outcomes(args.junit)
    required = PROFILES[args.profile]
    problems = []
    for name in required:
        state = results.get(name, "missing")
        if state != "passed":
            problems.append(f"{name}: {state}")
    passed = len(required) - len(problems)
    print(f"profile {args.profile}: {passed}/{len(required)} required platform tests passed")
    if problems:
        print("PLATFORM COVERAGE FAILURE: required platform tests did not pass (skipped means the platform "
              "environment was missing; this is not a success):")
        for problem in problems:
            print("  - " + problem)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
