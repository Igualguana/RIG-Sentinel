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
    # Windows short-name tests outside the NTFS directory (system temp volume, ctypes lookup on 3.11+)
    "test_short_path_query_reports_failure_instead_of_skipping",
    "test_short_name_alias_is_refused",
]
POSIX = [
    "test_posix_create_and_load_with_pin",
    "test_posix_symlinks_are_refused",
    "test_posix_walk_refuses_a_symlink_swapped_in_after_the_canonical_check",
    "test_posix_created_key_mode_is_exact_under_restrictive_umask",
    "test_posix_unsafe_key_modes_are_refused[416]",
    "test_posix_unsafe_key_modes_are_refused[388]",
    "test_posix_unsafe_key_modes_are_refused[432]",
    "test_posix_unsafe_directories_are_refused",
    "test_posix_hard_link_and_fifo_are_refused",
    "test_posix_held_directory_survives_rename",
    "test_posix_non_canonical_path_is_refused",
]
LINUX = ["test_posix_world_writable_ancestor_is_refused"]

# B2-M2-C2-C: audit-storage primitives (tests/test_audit_c2c_safefs.py). Mocked tests are never listed.
C2C_MODULE = "tests.test_audit_c2c_safefs"
C2C_NTFS = [
    "test_ntfs_audit_storage_is_read_only_and_writes_touch_nothing",
    "test_ntfs_junction_chain_directory_and_hard_linked_member_are_refused",
    "test_ntfs_open_member_cannot_be_replaced_and_growth_is_detected",
]
C2C_POSIX = [
    "test_posix_anchor_replacement",
    "test_posix_anchor_swapped_right_after_replace_is_detected",
    "test_posix_append_limit_does_not_seal",
    "test_posix_chain_directory_is_created_private_under_restrictive_umask",
    "test_posix_chain_directory_swapped_right_after_open_is_detected",
    "test_posix_cleanup_race_is_detected_not_prevented",
    "test_posix_directory_sync_failure_after_replace_is_uncertain_not_rolled_back",
    "test_posix_existing_unsafe_chain_directory_is_refused_and_never_chmodded",
    "test_posix_failed_creation_cleans_up_only_its_own_file",
    "test_posix_filesystem_refusal_is_enforced_when_opening",
    "test_posix_foreign_append_and_truncation_are_detected",
    "test_posix_hard_link_after_open_seals_the_segment",
    "test_posix_held_chain_directory_survives_replacement",
    "test_posix_key_directories_ignore_the_audit_filesystem_policy",
    "test_posix_listing_is_bounded_and_never_names_unknown_entries",
    "test_posix_member_swapped_right_after_open_is_detected",
    "test_posix_planted_temp_is_never_reused_or_deleted[directory]",
    "test_posix_planted_temp_is_never_reused_or_deleted[fifo]",
    "test_posix_planted_temp_is_never_reused_or_deleted[file]",
    "test_posix_planted_temp_is_never_reused_or_deleted[symlink]",
    "test_posix_quarantine_crash_between_link_and_unlink_fails_closed",
    "test_posix_quarantine_never_clobbers",
    "test_posix_read_detects_growth_and_change",
    "test_posix_remove_created_never_deletes_a_substituted_file[file]",
    "test_posix_remove_created_never_deletes_a_substituted_file[symlink]",
    "test_posix_remove_created_refuses_links_moves_and_other_directories",
    "test_posix_remove_created_removes_only_its_own_file",
    "test_posix_remove_created_reports_already_gone",
    "test_posix_renamed_or_replaced_segment_is_detected",
    "test_posix_segment_create_append_sync_and_read",
    "test_posix_short_write_seals_the_handle",
    "test_posix_symlink_fifo_and_directory_members_are_refused",
    "test_posix_symlinked_audit_root_and_chain_directory_are_refused",
    "test_posix_sync_failure_seals_and_reports_durability_failed",
    "test_posix_temp_swapped_before_replace_is_detected_and_not_deleted",
    "test_posix_temp_sync_or_replace_failure_leaves_anchor_unchanged",
    "test_posix_unsafe_anchor_target_is_never_replaced[directory]",
    "test_posix_unsafe_anchor_target_is_never_replaced[hardlink]",
    "test_posix_unsafe_anchor_target_is_never_replaced[symlink]",
    "test_posix_unsafe_member_permissions_and_missing_files",
]
C2C_LINUX = [
    "test_linux_descriptors_are_never_leaked",
    "test_linux_real_mountinfo_parses_and_the_audit_root_is_accepted",
]


def _qualify(module, names):
    return [module + "::" + name for name in names]


PROFILES = {  # C2-B lists unchanged (17, 12, 11); C2-C adds 3, 42, 40
    "windows-ntfs": _qualify(MODULE, NTFS) + _qualify(C2C_MODULE, C2C_NTFS),
    "linux": _qualify(MODULE, POSIX + LINUX) + _qualify(C2C_MODULE, C2C_POSIX + C2C_LINUX),
    "macos": _qualify(MODULE, POSIX) + _qualify(C2C_MODULE, C2C_POSIX),
}


def outcomes(path):
    results = {}
    for case in ET.parse(path).getroot().iter("testcase"):
        if case.get("classname") not in (MODULE, C2C_MODULE):
            continue
        if case.find("skipped") is not None:
            state = "skipped"
        elif case.find("failure") is not None or case.find("error") is not None:
            state = "failed"
        else:
            state = "passed"
        results[case.get("classname") + "::" + case.get("name")] = state
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
