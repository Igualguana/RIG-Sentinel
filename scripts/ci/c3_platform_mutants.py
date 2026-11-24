"""Run the C3 (persistent writer) mutants: portable or POSIX-native profile.

Usage: python scripts/ci/c3_platform_mutants.py --profile {portable,posix} [--list]

Each mutant weakens one control in a temporary copy of src/ (``jsonl.py`` or the C3-approved read-only
``AuditDirectory.verify_chain_named`` in ``safepath.py``) and runs **its documented killing tests** from
tests/test_audit_c3_writer.py against that copy. A mutant counts as CAUGHT only if those tests fail
(pytest exit code 1). An import or collection error, a timeout, or a run in which the killing tests were
skipped is never counted as caught. The repository is never modified. Every mutant must apply exactly once;
a compound mutant (one target, several exact anchors) requires every one of its anchors to match exactly once.

Profiles:
* ``portable``: killing tests that run on any host (the mocked C2-C/C2-D tier). Runs on Windows too.
* ``posix``: killing tests that need native POSIX (flock, dir_fd, fstatat without symlink following).
  On a host without them the profile exits 2 ("unsupported, not a success") and counts nothing.

The control run executes every killing test of the profile unmutated: all must pass and **none may be
skipped**; otherwise the run fails (exit 1) or, for a missing platform, exits 2.

Hardening (same rules as the approved C2 runners, which are not modified): fixed argv lists, ``shell=False``,
bounded timeouts, child environments without PYTEST_ADDOPTS, PYTEST_PLUGINS, PYTHONSTARTUP, PYTHONINSPECT or
PYTHONHOME, PYTHONDONTWRITEBYTECODE=1, and copies of src/ without bytecode. Standard library only.

Classified redundant and therefore **not** run (no coverage is claimed):
* M-CAP-4b: removing the call to ``_segment_capacity_ok`` (equivalent in every C1-valid state, plan R2.1).
* V2: removing ``S_ISDIR`` from ``verify_chain_named`` (the identity comparison alone already rejects every
  substitute: a symlink, file or FIFO has its own inode; equivalent).
* Removing the tail-window newline test in resume (``parse_record`` independently refuses a line without
  its newline: PARTIAL_LINE; equivalent).
* M-LOCK-SEAL (``_check`` does not seal before re-raising) and M-ORD-4 (``_write_failed`` does not seal):
  every public entry point (``append``, ``checkpoint``, the rotations, ``close``, genesis and resume) also
  seals on any exception, so the inner seal is defence in depth and the mutants are equivalent at the API.
  Both were run once (C3-H2) and survived for exactly that reason.
"""

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
NL = "\n"
TEST = "tests/test_audit_c3_writer.py"
TIMEOUT = 900
J = "jsonl.py"
S = "safepath.py"


def T(*names):
    return tuple(f"{TEST}::{name}" for name in names)


CAP_APPEND = ("        capacity = _capacity_problem(self._seq, self._generation, self._segment, reserve, new_segment=not direct)"
              + NL + "        if capacity is not None:  # P6: before any write")
RESERVE_APPEND = "        reserve = DIRECT_RESERVE if direct else SIZE_ROTATION_RESERVE" + NL + CAP_APPEND
P6_P7 = (CAP_APPEND + NL + "            raise _Refusal(StorageErrorCode.ENTRY_LIMIT_EXCEEDED, capacity)" + NL
         + "        if direct:  # P7" + NL + "            parsed, level = self._commit(line, event_id=event_id)")
SEALED_APPEND = ("            if self._state is not SinkState.READY:" + NL
                 + "                return _rejected(StorageErrorCode.SINK_SEALED")
W3 = ("            self._seg.append(line)  # W2: exactly one write" + NL
      + "            self._lock.verify_held()  # W3 (row SS: L, S)" + NL + "            self._seg.verify_name()" + NL
      + "            data_level = self._seg.sync()")

# (id, name, file, old, new, killing tests). Killing tests are the documented killers for the mutant.
PORTABLE = [
    # --- capacity (plan R2.1, M-CAP-1 ... M-CAP-9, plus operator-rotation and L-1) ---
    ("M-CAP-1", "direct path: generation capacity not verified", J, CAP_APPEND,
     CAP_APPEND.replace("_capacity_problem(self._seq, self._generation,",
                        "_capacity_problem(self._seq, 0 if direct else self._generation,"),
     T("test_t_cap_1_direct_append_near_max_generation")),
    ("M-CAP-2", "size rotation: generation capacity not verified", J, CAP_APPEND,
     CAP_APPEND.replace("_capacity_problem(self._seq, self._generation,",
                        "_capacity_problem(self._seq, self._generation if direct else 0,"),
     T("test_t_cap_3b_rotation_rejected_but_direct_record_still_fits")),
    ("M-CAP-3", "size-rotation seq reserve reverted to R1's +3", J, "SIZE_ROTATION_RESERVE = 4",
     "SIZE_ROTATION_RESERVE = 3", T("test_t_cap_3c_rotation_seq_reserve_is_four")),
    ("M-CAP-4a", "segment predicate always true", J, "    return segment + 1 <= MAX_POSITION", "    return True",
     T("test_t_cap_5a_segment_capacity_predicate")),
    ("M-CAP-4c", "segment predicate boundary <= becomes <", J, "    return segment + 1 <= MAX_POSITION",
     "    return segment + 1 < MAX_POSITION", T("test_t_cap_5a_segment_capacity_predicate")),
    ("M-CAP-4d", "segment predicate reserve dropped", J, "    return segment + 1 <= MAX_POSITION",
     "    return segment <= MAX_POSITION", T("test_t_cap_5a_segment_capacity_predicate")),
    ("M-CAP-5", "capacity checked after the write (R1 order)", J, P6_P7,
     ("        capacity = _capacity_problem(self._seq, self._generation, self._segment, reserve, new_segment=not direct)"
      + NL + "        if direct:  # P7" + NL + "            parsed, level = self._commit(line, event_id=event_id)" + NL
      + "        if capacity is not None:  # P6: before any write" + NL
      + "            raise _Refusal(StorageErrorCode.ENTRY_LIMIT_EXCEEDED, capacity)" + NL + "        if direct:  # P7" + NL
      + "            pass"),
     T("test_t_cap_1_direct_append_near_max_generation")),
    ("M-CAP-6", "resume generation bound reverted to <= M - 1", J, "RESUME_RESERVE = 2", "RESUME_RESERVE = 1",
     T("test_t_cap_7_resume_capacity")),
    ("M-CAP-7", "W1 defensive invariant removed", J,
     "        if not (_seq_capacity_ok(self._seq, 1) and _generation_capacity_ok(self._generation, 1)):",
     "        if False:", T("test_t_cap_8b_w1_guard_seals_before_any_write")),
    ("M-CAP-8", "P6 applies the direct reserve to the rotation path", J, RESERVE_APPEND,
     RESERVE_APPEND.replace("reserve = DIRECT_RESERVE if direct else SIZE_ROTATION_RESERVE",
                            "reserve = DIRECT_RESERVE"),
     T("test_t_cap_3b_rotation_rejected_but_direct_record_still_fits", "test_t_cap_3c_rotation_seq_reserve_is_four")),
    ("M-CAP-9s", "seq predicate boundary <= becomes <", J, "    return seq + reserve <= MAX_POSITION",
     "    return seq + reserve < MAX_POSITION",
     T("test_t_cap_8a_capacity_table_on_c1_valid_inputs", "test_t_cap_2_direct_append_near_max_seq")),
    ("M-CAP-9g", "generation predicate boundary <= becomes <", J, "    return generation + reserve <= MAX_POSITION",
     "    return generation + reserve < MAX_POSITION",
     T("test_t_cap_8a_capacity_table_on_c1_valid_inputs", "test_t_cap_1_direct_append_near_max_generation")),
    ("M-CAP-10", "operator-rotation reserve 3 becomes 2", J, "KEY_ROTATION_RESERVE = 3", "KEY_ROTATION_RESERVE = 2",
     T("test_t_cap_4_operator_rotations_near_max")),
    ("M-L1", "checkpoint reads the clock before its capacity check (Gemini H1 L-1)", J,
     "        self._check()  # row A" + NL + "        documents: list[bytes] = []",
     "        self._check()  # row A" + NL + "        self._next_timestamp()" + NL + "        documents: list[bytes] = []",
     T("test_l1_full_chain_checkpoint_is_refused_without_reading_the_clock")),
    # --- platform refusal (D-C3-11; Gemini H1 L-2) ---
    ("M-PLAT-1", "writer platform check: Windows kind not refused", J,
     "        if audit._kind != \"posix\" or not safepath._lock_capable():",
     "        if not safepath._lock_capable():", T("test_windows_writer_refused_before_any_io")),
    ("M-PLAT-2", "writer platform check: incapable POSIX not refused (capability check removed)", J,
     "        if audit._kind != \"posix\" or not safepath._lock_capable():",
     "        if audit._kind != \"posix\":", T("test_incapable_posix_refused_before_any_io")),
    ("V6", "verify_chain_named platform refusal removed", S,
     "        if self._kind != \"posix\" or chain._kind != \"posix\" or not capable:", "        if False:",
     T("test_verify_chain_named_refuses_windows_and_incapable_posix_before_any_os_call")),
    # --- lock verification (L) ---
    ("M-LOCK-A", "row A (append entry): lock check removed", J, "        self._check()  # P1 (row A)",
     "        self._check(lock=False)  # P1 (row A)", T("test_entry_checks_come_first")),
    ("M-LOCK-A2", "row A (checkpoint entry): lock check removed", J,
     "        self._check()  # row A" + NL + "        documents", "        self._check(lock=False)  # row A" + NL
     + "        documents", T("test_entry_checks_come_first")),
    ("M-LOCK-K", "rows RO/K (operator rotation): lock check removed", J, "        self._check()  # rows RO / K",
     "        self._check(lock=False)  # rows RO / K", T("test_entry_checks_come_first")),
    ("M-LOCK-CL", "row CL (close): lock check removed", J, "        self._check()  # row CL",
     "        self._check(lock=False)  # row CL", T("test_entry_checks_come_first")),
    ("M-LOCK-W", "row W: lock check removed", J, "        self._check()  # matrix row W",
     "        self._check(lock=False)  # matrix row W",
     T("test_every_protected_write_is_preceded_by_its_checks")),
    ("M-LOCK-SS", "row SS (W3): lock check removed before the data sync", J, W3,
     W3.replace("            self._lock.verify_held()  # W3 (row SS: L, S)" + NL, ""),
     T("test_every_protected_write_is_preceded_by_its_checks")),
    ("M-LOCK-X", "row X (anchor replace): lock check removed", J, "        self._check(segment=False)  # W4 (row X: L, D)",
     "        self._check(lock=False, segment=False)  # W4 (row X: L, D)",
     T("test_every_protected_write_is_preceded_by_its_checks")),
    ("M-LOCK-C", "row C (segment create): lock check removed", J, "        self._check(segment=False)  # row C" + NL,
     "        self._check(lock=False, segment=False)  # row C" + NL,
     T("test_every_protected_write_is_preceded_by_its_checks")),
    ("M-LOCK-CS", "row CS (directory sync): lock check removed", J, "        self._check(segment=False)  # row CS",
     "        self._check(lock=False, segment=False)  # row CS", T("test_every_protected_write_is_preceded_by_its_checks")),
    ("M-LOCK-G", "row G (genesis): lock check removed", J, "        self._lock.verify_held()  # G6 (matrix row G)" + NL,
     "", T("test_genesis_order_contents_and_first_anchor")),
    ("M-LOCK-R", "row R (resume): lock check removed", J, "        self._lock.verify_held()  # matrix row R" + NL, "",
     T("test_resume_checks_precede_listing_and_reads")),
    ("M-LOCK-R2", "row R2 (resume reads): lock check removed", J,
     "        self._lock.verify_held()  # matrix row R2: before the reads" + NL, "",
     T("test_resume_checks_precede_listing_and_reads")),
    ("M-LOCK-REL", "lock released before the final SHUTDOWN commit", J, "                    self._shutdown()",
     "                    self._lock.release()" + NL + "                    self._shutdown()",
     T("test_close_writes_shutdown_and_releases_the_lock_last")),
    # --- directory identity (D) and segment identity (S) ---
    ("M-DIR-A", "row A: directory identity check removed", J, "        self._check()  # P1 (row A)",
     "        self._check(directory=False)  # P1 (row A)", T("test_entry_checks_come_first")),
    ("M-DIR-W", "row W: directory identity check removed", J, "        self._check()  # matrix row W",
     "        self._check(directory=False)  # matrix row W",
     # C3-H2-F1: the substitution test is not an independent killer (the row A check masks this removal).
     T("test_every_protected_write_is_preceded_by_its_checks")),
    ("M-DIR-X", "row X: directory identity check removed", J, "        self._check(segment=False)  # W4 (row X: L, D)",
     "        self._check(directory=False, segment=False)  # W4 (row X: L, D)",
     T("test_every_protected_write_is_preceded_by_its_checks")),
    ("M-DIR-C", "row C: directory identity check removed", J, "        self._check(segment=False)  # row C" + NL,
     "        self._check(directory=False, segment=False)  # row C" + NL,
     T("test_every_protected_write_is_preceded_by_its_checks")),
    ("M-DIR-CS", "row CS: directory identity check removed", J, "        self._check(segment=False)  # row CS",
     "        self._check(directory=False, segment=False)  # row CS",
     T("test_every_protected_write_is_preceded_by_its_checks")),
    ("M-DIR-G", "row G: directory identity check removed", J,
     "        self._lock.verify_held()  # G6 (matrix row G)" + NL + "        self._audit.verify_chain_named(self._chain)" + NL,
     "        self._lock.verify_held()  # G6 (matrix row G)" + NL, T("test_genesis_order_contents_and_first_anchor")),
    ("M-DIR-R", "row R: directory identity check removed", J,
     "        self._lock.verify_held()  # matrix row R" + NL + "        self._audit.verify_chain_named(self._chain)" + NL,
     "        self._lock.verify_held()  # matrix row R" + NL, T("test_resume_checks_precede_listing_and_reads")),
    ("M-DIR-K", "rows RO/K: directory identity check removed", J, "        self._check()  # rows RO / K",
     "        self._check(directory=False)  # rows RO / K", T("test_entry_checks_come_first")),
    ("M-SEG-W", "row W: segment name check removed", J, "        self._check()  # matrix row W",
     "        self._check(segment=False)  # matrix row W", T("test_every_protected_write_is_preceded_by_its_checks")),
    ("M-SEG-SS", "row SS: segment name check removed before the data sync", J, W3,
     W3.replace("            self._seg.verify_name()" + NL, ""), T("test_every_protected_write_is_preceded_by_its_checks")),
    # --- anchor-commit ordering (I1-I4) ---
    ("M-ORD-1", "anchor written before the record append", J, "            self._seg.append(line)  # W2: exactly one write",
     "            self._chain.replace_atomically(ANCHOR_NAME, anchor, max_bytes=MAX_ANCHOR_BYTES)" + NL
     + "            self._seg.append(line)  # W2: exactly one write",
     T("test_append_commit_protocol_order_and_receipt", "test_write_failures_seal_without_receipt_or_further_write")),
    ("M-ORD-2", "data sync skipped before anchoring", J, "            data_level = self._seg.sync()",
     "            data_level = Durability.FSYNC", T("test_append_commit_protocol_order_and_receipt")),
    ("M-ORD-3", "STORED despite a failed anchor update", J, "        if failed:", "        if False:",
     T("test_write_failures_seal_without_receipt_or_further_write")),
    ("M-ORD-5", "generation not incremented per anchor", J, "        self._generation += 1", "        self._generation += 0",
     T("test_append_commit_protocol_order_and_receipt")),
    ("M-ORD-6", "SEALED writer accepts appends", J, SEALED_APPEND,
     "            if False:" + NL + "                return _rejected(StorageErrorCode.SINK_SEALED",
     T("test_write_failures_seal_without_receipt_or_further_write")),
    # --- duplicate before rotation, event id, rebuild ---
    ("M-DUP-1", "duplicate check removed", J, "        if event_id in self._index:  # P4",
     "        if False:  # P4", T("test_duplicate_event_id_rejected_without_write")),
    ("M-DUP-2", "duplicate checked only on the direct path (after the admission decision)", J,
     "        if event_id in self._index:  # P4", "        if event_id in self._index and self._admits(line):  # P4",
     T("test_duplicate_at_the_rotation_boundary_never_rotates")),
    ("M-DUP-3", "event id taken from the untrusted carrier", J, "        event_id = _event_id_or_none(line)  # P3",
     "        event_id = getattr(validated, \"event_id\", None)  # P3", T("test_carrier_event_id_is_never_trusted")),
    ("M-ROT-1", "event not rebuilt at the new position after rotation", J,
     "        record_line = rebuild(self._record_at(self._segment + 1, self._seq + 3, open_digest))",
     "        record_line = rebuild(self._record_at(self._segment, self._seq + 1, self._prev_digest))",
     T("test_size_rotation_rebuilds_the_event_at_the_new_position")),
    ("M-ROT-2", "CLOSE_RESERVE set to 0", J, "CLOSE_RESERVE = MAX_RECORD_LINE_BYTES", "CLOSE_RESERVE = 0",
     T("test_exact_fit_and_one_byte_over", "test_shutdown_and_rotation_fit_a_segment_filled_to_the_admission_limit")),
    ("M-ROT-3", "MIN_SEGMENT_BYTES check removed", J, "not MIN_SEGMENT_BYTES <= size <= MAX_FILE_BYTES",
     "not 1 <= size <= MAX_FILE_BYTES", T("test_sink_limits_boundaries")),
    ("M-ROT-4", "operator rotation key independence not checked", J,
     "            require_independent_keys(new_chain_key, new_auth, self._ref)", "            pass",
     T("test_rotation_to_a_key_sharing_k_ref_is_refused_after_an_unlinked_epoch")),
    ("M-ROT-5", "unchanged epoch accepted for an epoch rotation", J, "            if new_epoch == self._epoch:",
     "            if False:", T("test_rotation_parameters_refused_before_the_close")),
    # --- genesis, resume, keys, clock, threads ---
    ("M-GEN-1", "G2 pre-creation absence check removed", J,
     "        if name in self._audit.list_names().names:  # G2: pre-creation absence check (A2)", "        if False:",
     T("test_existing_name_refused_at_g2_without_mkdir")),
    ("M-GEN-2", "G7 exact initial contents not checked", J,
     "        if listing.names != (_LOCK_NAME,) or listing.other_entries != 0:", "        if False:",
     T("test_prepopulated_directory_adopted_in_race_is_refused_at_g7")),
    ("M-GEN-3", "generated chain id not validated (G1)", J,
     "        chain_id = new_chain_id()  # G1 (A1: secrets.token_hex(16))" + NL + "        if not _valid_chain_id(chain_id):",
     "        chain_id = new_chain_id()  # G1 (A1: secrets.token_hex(16))" + NL + "        if False:",
     T("test_malformed_generated_chain_id_is_an_invariant_breach_before_io")),
    ("M-RES-1", "caller chain id not validated before open (L-1)", J,
     "        if not _valid_chain_id(chain_id):" + NL + "            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, \"chain:id\")",
     "        if False:" + NL + "            raise StorageError(StorageErrorCode.INPUT_TYPE_INVALID, \"chain:id\")",
     T("test_malformed_chain_id_refused_before_open_chain")),
    ("M-RES-2", "generation not restored on resume (reset)", J,
     "        self._generation = anchor.generation  # M-1", "        self._generation = 1  # M-1",
     T("test_resume_cycles_restore_generation_and_continue_the_chain")),
    ("M-RES-3", "resume accepts a rotation-close tail", J,
     "        if record.kind is not RecordKind.SEGMENT_CLOSE or reason not in (CloseReason.SHUTDOWN.value,",
     "        if record.kind is not RecordKind.SEGMENT_CLOSE or reason in (\"none\",",
     T("test_rotation_close_tail_requires_recovery")),
    ("M-RES-4", "verify_on_resume ignored", J, "        if rings is not None:", "        if False:",
     T("test_verify_on_resume_refuses_mid_file_corruption")),
    ("M-RES-5", "verification keyrings not validated", J, "            if type(extra) is not dict:",
     "            if False:", T("test_l3_1_invalid_verification_keyrings_refused_before_any_io")),
    ("M-RES-6", "verified resume ignores a missing trailing newline in an earlier segment", J,
     "            if data and not data.endswith(b\"\\n\"):", "            if False:",
     T("test_l3_2_missing_trailing_newline_in_an_earlier_segment_refused_by_verified_resume")),
    ("M-KEY-1", "K_auth not checked against the epoch at open", J,
     "        _require_epoch_independent(epoch, chain_key, auth_key)", "        pass",
     T("test_k_auth_equal_to_epoch_ref_refused_before_genesis_header")),
    ("M-CLK-1", "clock monotonicity not checked", J, " or (self._last_timestamp is not None and value < self._last_timestamp)",
     "", T("test_bad_or_backwards_clock_refused_before_rotation_close")),
    ("M-THR-1", "concurrent entry not refused", J, "        return self._busy.acquire(blocking=False)",
     "        return True", T("test_concurrent_entry_is_refused_not_interleaved")),
]

#: Killed only by native POSIX tests (real fstatat / fstat on held descriptors).
POSIX = [
    ("V1", "verify_chain_named: identity comparison removed", S,
     " or _identity(entry_identity) != _identity(held_directory):", ":",
     T("test_native_verify_chain_named_detects_substitution", "test_native_verify_chain_named_rejects_a_chain_from_a_foreign_root")),
    ("V3", "verify_chain_named follows symlinks", S, "            entry_identity = _named_identity(self._fd, entry)",
     "            entry_identity = os.stat(entry, dir_fd=self._fd)",
     T("test_native_verify_chain_named_detects_substitution")),
    ("V4", "verify_chain_named swallows FileNotFoundError", S, "            verdict = \"chain:missing\"",
     "            verdict = None", T("test_native_verify_chain_named_detects_substitution")),
    ("V5", "verify_chain_named swallows other OSError", S, "            verdict = \"chain:verify\"",
     "            verdict = None", T("test_native_verify_chain_named_other_os_errors_fail_closed")),
    ("V7", "verify_chain_named takes the name from a constant, not the chain object", S,
     "            entry = check_chain_directory_name(chain._path.rsplit(\"/\", 1)[-1])",
     "            entry = check_chain_directory_name(\"chain-\" + \"0\" * 32)",
     T("test_native_verify_chain_named_detects_substitution")),
    ("V8", "verify_chain_named compares against the root, not the chain descriptor", S,
     "            held_directory = os.fstat(chain._fd)", "            held_directory = os.fstat(self._fd)",
     T("test_native_verify_chain_named_detects_substitution")),
    ("V10", "verify_chain_named raises inside except (exception context leak)", S,
     "            verdict = \"chain:missing\"", "            raise _fail(StorageErrorCode.UNSAFE_PATH, \"chain:missing\")",
     T("test_native_verify_chain_named_detects_substitution")),
    # C3-H2-F1 (Gemini L-H2-1): ONE compound mutation. It removes the append-path directory-identity checks at
    # P1 / row A and at _commit / row W together (row X is kept). It tests the combined loss of both, not the
    # necessity of either: each single removal is masked by the other on the native outcome test (documented,
    # not claimed as killed natively). With both removed, a record reaches the held (renamed-away) chain before
    # row X raises chain:replaced; the strengthened native test's byte snapshot of that directory detects it.
    ("M-NAT-1", "native: append path writes a record before detecting chain substitution (rows A and W "
     "directory checks removed together)", J,
     ("        self._check()  # P1 (row A)", "        self._check()  # matrix row W"),
     ("        self._check(directory=False)  # P1 (row A)", "        self._check(directory=False)  # matrix row W"),
     T("test_native_chain_directory_substitution_seals_and_writes_nothing_new")),
]
# V9 (C3 matrix column-D calls removed) is covered row by row by M-DIR-* above.

PROFILES = {"portable": PORTABLE, "posix": POSIX}
SUMMARY_RE = re.compile(r"(\d+) (passed|failed|skipped|errors?|deselected)")


def environment_problem(profile):
    if profile == "portable":
        return None
    try:
        import fcntl
    except ImportError:
        fcntl = None
    capable = (os.name == "posix" and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
               and os.stat in os.supports_follow_symlinks and hasattr(os, "O_NOFOLLOW")
               and os.scandir in os.supports_fd and fcntl is not None and hasattr(fcntl, "flock")
               and hasattr(os, "register_at_fork"))
    if not capable:
        return "POSIX profile needs Linux or macOS with dir_fd, O_NOFOLLOW, flock and register_at_fork"
    return None


#: Variables that could inject code or pytest options into the child runs; they are never inherited.
DROPPED_ENV = ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONSTARTUP", "PYTHONINSPECT", "PYTHONHOME")


def child_env(src):
    env = {key: value for key, value in os.environ.items() if key not in DROPPED_ENV}
    env.update(PYTHONPATH=str(src), PYTHONDONTWRITEBYTECODE="1")
    return env


def copy_src(destination):
    shutil.copytree(REPO / "src", destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def counts(output):
    found = {}
    for number, word in SUMMARY_RE.findall(output.splitlines()[-1] if output.strip() else ""):
        found[word.rstrip("s") if word.startswith("error") else word] = int(number)
    return found


def run_tests(src, tests):
    argv = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--tb=no", "-W", "error::Warning",
            "-rs", *tests]
    try:
        return subprocess.run(argv, cwd=str(REPO), env=child_env(src), capture_output=True, text=True,
                              timeout=TIMEOUT, shell=False)
    except subprocess.TimeoutExpired:
        return None


def edit_pairs(old, new):
    """A mutant is one (old, new) replacement, or ONE compound mutation given as equal-length tuples of exact
    anchors and replacements (all applied together; the mutant is caught or not as a whole)."""
    if isinstance(old, str) and isinstance(new, str):
        return [(old, new)]
    if (isinstance(old, tuple) and isinstance(new, tuple) and len(old) == len(new) >= 2
            and all(isinstance(x, str) for x in old + new)):
        return list(zip(old, new))
    return None


def apply_mutation(text, old, new):
    """Apply every anchor of the mutation; each must match exactly once in the text at the time it is applied.
    Returns (mutated text, None) or (None, reason)."""
    for before, after in edit_pairs(old, new):
        found = text.count(before)
        if found != 1:
            return None, f"{found} matches for anchor {before.strip()!r}"
        text = text.replace(before, after)
    return text, None


def validate(mutants):
    """Static checks: unique ids, a documented killing test for every mutant, killers exist in the test file."""
    source = (REPO / TEST).read_text(encoding="utf-8")
    ids = [mutant[0] for mutant in mutants]
    problems = [f"duplicate id {i}" for i in sorted(set(ids)) if ids.count(i) > 1]
    for ident, _, _, old, new, killers in mutants:
        if not killers:
            problems.append(f"{ident}: no killing test")
        edits = edit_pairs(old, new)
        if edits is None:
            problems.append(f"{ident}: malformed compound mutation")
        elif any(before == after for before, after in edits):
            problems.append(f"{ident}: no-op")
        for killer in killers:
            if f"def {killer.split('::')[-1]}(" not in source:
                problems.append(f"{ident}: killing test not found: {killer}")
    return problems


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES))
    parser.add_argument("--list", action="store_true", help="print the mutants and their killing tests")
    args = parser.parse_args()
    mutants = PROFILES[args.profile]
    problems = validate(mutants)
    if problems:
        print("INVALID MUTANT TABLE:" + NL + NL.join(problems))
        return 1
    if args.list:
        for ident, name, path, _, _, killers in mutants:
            print(f"{ident} [{path}] {name} <- {', '.join(k.split('::')[-1] for k in killers)}")
        return 0
    problem = environment_problem(args.profile)
    if problem:
        print("UNSUPPORTED ENVIRONMENT (not a success; nothing counted): " + problem)
        return 2
    killers = sorted({killer for mutant in mutants for killer in mutant[5]})
    work = pathlib.Path(tempfile.mkdtemp(prefix="rig-c3-mutants-"))
    try:
        control_src = work / "control" / "src"
        copy_src(control_src)
        try:
            probe = subprocess.run([sys.executable, "-c", "import rig_sentinel.audit.jsonl as j; print(j.__file__)"],
                                   env=child_env(control_src), capture_output=True, text=True, timeout=120, shell=False)
        except subprocess.TimeoutExpired:
            print("CONTROL FAILED: import probe timed out")
            return 1
        if str(control_src) not in probe.stdout:
            print("CONTROL FAILED: the mutated copy would not be imported (" + probe.stdout.strip() + ")")
            return 1
        control = run_tests(control_src, killers)
        if control is None or control.returncode != 0:
            print("CONTROL FAILED: unmutated killing tests do not pass" + NL
                  + ("timeout" if control is None else control.stdout[-3000:]))
            return 1
        control_counts = counts(control.stdout)
        if control_counts.get("skipped", 0):
            print(f"UNSUPPORTED (not a success): {control_counts['skipped']} killing tests were skipped in the control run")
            return 2
        print(f"control: {control_counts.get('passed', 0)} killing tests passed, 0 skipped")
        caught = 0
        failures = 0
        for index, (ident, name, path, old, new, tests) in enumerate(mutants, 1):
            src = work / f"m{index}" / "src"
            copy_src(src)
            target = src / "rig_sentinel" / "audit" / path
            mutated, reason = apply_mutation(target.read_text(encoding="utf-8"), old, new)
            if mutated is None:
                failures += 1
                print(f"{ident}. NOT APPLIED ({reason}): {name}")
                shutil.rmtree(src.parent, ignore_errors=True)
                continue
            target.write_text(mutated, encoding="utf-8")
            result = run_tests(src, list(tests))
            shutil.rmtree(src.parent, ignore_errors=True)
            if result is None:
                failures += 1
                print(f"{ident}. [TIMEOUT] {name}")
                continue
            if result.returncode == 1:
                caught += 1
                status = "CAUGHT"
            elif result.returncode == 0:
                status = "NOT CAUGHT"
            else:
                failures += 1
                status = f"ERROR (pytest exit {result.returncode}; not counted as caught)"
            print(f"{ident}. [{status}] {name}")
        print(f"profile {args.profile}: caught {caught}/{len(mutants)}")
        return 0 if caught == len(mutants) and failures == 0 else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
