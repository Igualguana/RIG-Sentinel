"""Genesis B2-M2-C3-H1: the persistent writer ``LocalJsonlSink`` and ``AuditDirectory.verify_chain_named``.

Two tiers:

* **Portable (mocked C2-C/C2-D):** every safepath object the writer uses is replaced, for the test only, by an
  in-memory model that keeps the C2-C/C2-D contract (single-write append with seal, ``O_EXCL`` create, atomic
  anchor replace, held-directory identity, lock verification) and logs every call. It runs on every platform,
  including Windows, and proves ordering, refusal-before-write and fault behaviour. It is a simulation: it is
  **not** native Linux/macOS evidence.
* **Native POSIX:** real files under a private temporary audit root (skipped where flock/dir_fd are missing).

Requirement ids (T-CAP-n, A-n, G-n, rows L/D/S) refer to ``M2_C3_IMPLEMENTATION_PLAN_R2_1.md`` and
``M2_C3_ARCHITECTURE_R2_1.md``.
"""

import ast
import contextlib
import copy
import inspect
import itertools
import os
import pickle
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from audit_fixtures import AUTH_MATERIAL, FIXED_AUDIT_NOW, REF_MATERIAL, auth_key, ref_key
from policy_fixtures import baseline_engine, make_request

from rig_sentinel.audit import (
    AUDIT_EVENT_SCHEMA_V3,
    AuditEventBuilder,
    AuditKey,
    AuditKeys,
    KeyPurpose,
    ProjectionEpoch,
    ProjectionProfile,
    check_projection_persistable,
    project,
)
from rig_sentinel.audit import jsonl
from rig_sentinel.audit import safepath as sp
from rig_sentinel.audit.chainverify import ChainStatus, verify_chain
from rig_sentinel.audit.jsonl import (
    CLOSE_RESERVE,
    MIN_SEGMENT_BYTES,
    LocalJsonlSink,
    ReceiptStatus,
    SinkLimits,
    SinkState,
)
from rig_sentinel.audit.keyfile import KeySet
from rig_sentinel.audit.records import (
    MAX_ANCHOR_BYTES,
    MAX_POSITION,
    MAX_RECORD_LINE_BYTES,
    ChainPosition,
    CloseReason,
    OpenReason,
    PreviousSegment,
    RecordKind,
    build_anchor,
    build_segment_close,
    build_segment_open,
    parse_record,
    verify_anchor,
    verify_checkpoint,
)
from rig_sentinel.audit.safepath import ANCHOR_NAME, ANCHOR_TEMP_NAME, AuditDirectory, ChainDirectory, Durability
from rig_sentinel.audit.storage_errors import StorageError, StorageErrorCode

M = MAX_POSITION
L = MAX_RECORD_LINE_BYTES
CHAIN_MATERIAL = bytes(range(200, 232))
CHAIN2_MATERIAL = bytes(range(160, 192))
AUTH2_MATERIAL = bytes(range(70, 102))
FIXED_ID = "ab" * 16
LOCK = ".writer.lock"
_IDS = itertools.count(1)

IS_POSIX_LOCK = sp._platform() == "posix" and sp._posix_write_capable() and sp._lock_capable()
posix_only = pytest.mark.skipif(not IS_POSIX_LOCK, reason="POSIX-only (flock, dir_fd): native tier")


# --- keys, epochs, projections, clock --------------------------------------------------------------------------


def chain_key(material=CHAIN_MATERIAL):
    return AuditKey.from_bytes(KeyPurpose.CHAIN, material)


def auth2():
    return AuditKey.from_bytes(KeyPurpose.AUTH, AUTH2_MATERIAL)


KEYED = ProjectionEpoch.keyed(ref_key())
KEYS = KeySet(auth=auth_key(), chain=chain_key(), ref=ref_key())


def validated(auth=None, unlinked=False, **overrides):
    auth = auth or auth_key()
    request = make_request(**overrides)
    record = baseline_engine().evaluate(request)
    keys = AuditKeys(auth=auth) if unlinked else AuditKeys(ref=ref_key(), auth=auth)
    builder = AuditEventBuilder(keys, clock=lambda: FIXED_AUDIT_NOW, id_factory=lambda: f"{next(_IDS):032x}",
                                event_schema=AUDIT_EVENT_SCHEMA_V3)
    profile = ProjectionProfile.UNLINKED if unlinked else ProjectionProfile.KEYED
    envelope = project(builder.build_envelope(record, request), keys, profile=profile)
    epoch = ProjectionEpoch.unlinked() if unlinked else KEYED
    result = check_projection_persistable(envelope, {auth.key_id: auth}, expected_epoch=epoch)
    assert result.ok
    return result.validated


class Clock:
    """Strictly increasing, C1-format timestamps."""

    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        n = self.calls
        return f"2026-11-23T{n // 3600 % 24:02d}:{n // 60 % 60:02d}:{n % 60:02d}.000000Z"


def error_of(fn, *args, **kwargs):
    with pytest.raises(StorageError) as info:
        fn(*args, **kwargs)
    assert info.value.__context__ is None and info.value.__cause__ is None
    return info.value


# --- the portable model of the C2-C / C2-D primitives -----------------------------------------------------------

WRITE_OPS = frozenset({"open_chain:create", "audit.sync", "create_exclusive", "chain.sync", "append", "seg.sync",
                       "replace_atomically", "link_no_replace", "remove_created"})
CHECK_OPS = {"verify_held": "L", "verify_chain_named": "D", "verify_name": "S"}


def fail(code, label):
    def action(*_args):
        raise StorageError(code, label)
    return action


class FakeFile:
    def __init__(self, data=b""):
        self.data = bytearray(data)


class FakeDir:
    def __init__(self):
        self.entries = {}


class FakeLock:
    def __init__(self, fs):
        self.fs = fs
        self.state = "held"

    def verify_held(self):
        self.fs.call("verify_held", self)
        if self.state != "held" or not self.fs.lock_ok:
            self.state = "invalid"
            raise StorageError(StorageErrorCode.LOCK_INVALID, "lock:changed")

    def release(self):
        self.fs.call("release", self)
        self.state = "released"


class FakeAppend:
    def __init__(self, fs, directory, name, max_size):
        self.fs, self.dir, self.name, self.max = fs, directory, name, max_size
        self.file = directory.entries[name]
        self.size = 0
        self.sealed = False
        self.closed = False

    def append(self, data):
        self.fs.call("append", self, data)
        if self.sealed or self.closed:
            raise StorageError(StorageErrorCode.FILE_UNSAFE, "file:sealed")
        assert type(data) is bytes and data
        if self.size + len(data) > self.max:
            raise StorageError(StorageErrorCode.FILE_TOO_LARGE, "file:limit")
        if self.dir.entries.get(self.name) is not self.file or len(self.file.data) != self.size:
            self.sealed = True
            raise StorageError(StorageErrorCode.FILE_UNSAFE, "file:changed")
        self.file.data += data
        self.size += len(data)

    def sync(self):
        self.fs.call("seg.sync", self)
        return Durability.FSYNC

    def verify_name(self):
        self.fs.call("verify_name", self)
        if self.dir.entries.get(self.name) is not self.file:
            raise StorageError(StorageErrorCode.FILE_UNSAFE, "file:replaced")

    def close(self):
        self.closed = True


class FakeRead:
    def __init__(self, fs, directory, name, max_size):
        self.fs, self.dir, self.name, self.max = fs, directory, name, max_size
        self.file = directory.entries[name]
        self.snapshot = bytes(self.file.data)
        self.pos = 0

    def read(self, max_bytes):
        chunk = self.snapshot[self.pos:self.pos + min(max_bytes, self.max - self.pos + 1)]
        if self.pos + len(chunk) > self.max:
            raise StorageError(StorageErrorCode.FILE_TOO_LARGE, "file:limit")
        self.pos += len(chunk)
        return chunk

    def verify_unchanged(self):
        if self.dir.entries.get(self.name) is not self.file or bytes(self.file.data) != self.snapshot:
            raise StorageError(StorageErrorCode.FILE_UNSAFE, "file:changed")

    def close(self):
        pass


class FakeFS:
    """In-memory audit root. ``calls`` logs every primitive call by name; ``on`` injects actions."""

    ROOT = "/fake/audit"

    def __init__(self):
        self.root = {}
        self.calls = []
        self.hooks = {}
        self.held = {}
        self.lock_ok = True
        self.removed = []

    def on(self, op, action, nth=1):
        self.hooks.setdefault(op, []).append((nth, action))

    def call(self, op, *args):
        self.calls.append(op)
        count = self.calls.count(op)
        for nth, action in self.hooks.get(op, ()):
            if nth == count:
                action(*args)

    def held_dir(self, chain):
        return self.held[id(chain)]

    def directory(self, chain_id):
        return self.root["chain-" + chain_id]

    def segment_numbers(self, chain_id):
        return sorted(int(n[4:-6]) for n in self.directory(chain_id).entries if n.startswith("seg-"))

    def segment(self, chain_id, number):
        return bytes(self.directory(chain_id).entries[f"seg-{number}.jsonl"].data)

    def lines(self, chain_id):
        out = []
        for number in self.segment_numbers(chain_id):
            out.extend(piece + b"\n" for piece in self.segment(chain_id, number).split(b"\n")[:-1])
        return out

    def anchor(self, chain_id, key=None):
        key = key or chain_key()
        return verify_anchor(bytes(self.directory(chain_id).entries[ANCHOR_NAME].data), {key.key_id: key})

    def snapshot(self):
        return {name: {k: bytes(v.data) for k, v in d.entries.items()} for name, d in self.root.items()}

    def writes_after(self, index):
        return [op for op in self.calls[index:] if op in WRITE_OPS]


def install(monkeypatch, fs):
    monkeypatch.setattr(sp, "_lock_capable", lambda: True)

    def audit_list(self, *, max_entries=sp.MAX_LIST_ENTRIES):
        fs.call("audit.list_names")
        return sp.ListResult(tuple(sorted(fs.root)), 0)

    def audit_sync(self):
        fs.call("audit.sync")
        return Durability.FSYNC

    def open_chain(self, name, *, create=False):
        name = sp.check_chain_directory_name(name)
        fs.call("open_chain:create" if create else "open_chain", name)
        if name not in fs.root:
            if not create:
                raise StorageError(StorageErrorCode.STORAGE_UNAVAILABLE, "directory:child")
            fs.root[name] = FakeDir()
        chain = ChainDirectory(_kind="posix", _fd=None, _path=FakeFS.ROOT + "/" + name, _identities=())
        fs.held[id(chain)] = fs.root[name]
        return chain

    def verify_chain_named(self, chain):
        fs.call("verify_chain_named", chain)
        name = chain._path.rsplit("/", 1)[-1]
        if name not in fs.root:
            raise StorageError(StorageErrorCode.UNSAFE_PATH, "chain:missing")
        if fs.root[name] is not fs.held_dir(chain):
            raise StorageError(StorageErrorCode.UNSAFE_PATH, "chain:replaced")

    def acquire(self):
        fs.call("acquire_writer_lock")
        fs.held_dir(self).entries.setdefault(LOCK, FakeFile())
        return FakeLock(fs)

    def chain_list(self, *, max_entries=sp.MAX_LIST_ENTRIES):
        fs.call("chain.list_names")
        names = sorted(n for n in fs.held_dir(self).entries if sp._is_listed_member(n))
        return sp.ListResult(tuple(names), len(fs.held_dir(self).entries) - len(names))

    def create_exclusive(self, name, *, max_size):
        fs.call("create_exclusive", name)
        sp.check_chain_member_name(name, kind="segment")
        directory = fs.held_dir(self)
        if name in directory.entries:
            raise StorageError(StorageErrorCode.FILE_EXISTS, "file:create")
        directory.entries[name] = FakeFile()
        return FakeAppend(fs, directory, name, max_size)

    def chain_sync(self):
        fs.call("chain.sync")
        return Durability.FSYNC

    def open_read(self, name, *, max_size):
        fs.call("open_read", name)
        sp.check_chain_member_name(name, kind="readable")
        directory = fs.held_dir(self)
        if name not in directory.entries:
            raise StorageError(StorageErrorCode.FILE_MISSING, "file:open")
        return FakeRead(fs, directory, name, max_size)

    def replace(self, name, data, *, max_bytes):
        fs.call("replace_atomically", name, data)
        assert name == ANCHOR_NAME and type(data) is bytes and len(data) <= max_bytes
        fs.held_dir(self).entries[ANCHOR_NAME] = FakeFile(data)
        return Durability.FSYNC

    def forbidden(*_args, **_kwargs):
        raise AssertionError("C3 must never call this primitive")

    for name, function in (("list_names", audit_list), ("sync", audit_sync), ("open_chain", open_chain),
                           ("verify_chain_named", verify_chain_named)):
        monkeypatch.setattr(AuditDirectory, name, function)
    for name, function in (("acquire_writer_lock", acquire), ("list_names", chain_list),
                           ("create_exclusive", create_exclusive), ("sync", chain_sync), ("open_read", open_read),
                           ("replace_atomically", replace), ("open_append", forbidden),
                           ("link_no_replace", forbidden), ("remove_created", forbidden)):
        monkeypatch.setattr(ChainDirectory, name, function)


@pytest.fixture
def fs(monkeypatch):
    model = FakeFS()
    install(monkeypatch, model)
    return model


def fake_root():
    return AuditDirectory(_kind="posix", _fd=None, _path=FakeFS.ROOT, _identities=())


def new_sink(fs, *, limits=None, clock=None, keys=KEYS, epoch=KEYED):
    return LocalJsonlSink.create_chain(fake_root(), keys=keys, epoch=epoch, limits=limits, clock=clock or Clock())


def resume(chain_id, *, limits=None, clock=None, keys=KEYS, epoch=KEYED, **kwargs):
    return LocalJsonlSink.resume_chain(fake_root(), chain_id, keys=keys, epoch=epoch, limits=limits,
                                       clock=clock or Clock(), **kwargs)


def assert_valid(fs, chain_id, chain_keys=None, auth_keys=None):
    chain_keys = chain_keys or [chain_key()]
    auth_keys = auth_keys or [auth_key()]
    report = verify_chain(fs.lines(chain_id), chain_keys={k.key_id: k for k in chain_keys},
                          auth_keys={k.key_id: k for k in auth_keys}, expected_chain_id=chain_id)
    assert report.status is ChainStatus.CHAIN_VALID, report.issues
    return report


def assert_no_write(fs, start, before):
    assert fs.writes_after(start) == []
    assert fs.snapshot() == before


SMALL = SinkLimits(segment_max_bytes=MIN_SEGMENT_BYTES, segment_max_records=3)  # one record per segment


# === 1. Construction, platform and input refusals (no I/O) =======================================================


def test_windows_writer_refused_before_any_io(fs):
    root = AuditDirectory(_kind="nt", _fd=None, _path="C:\\audit", _identities=())
    error = error_of(LocalJsonlSink.create_chain, root, keys=KEYS, epoch=KEYED)
    assert (error.code, error.path) == (StorageErrorCode.UNSUPPORTED_PLATFORM, "sink:platform")
    error = error_of(LocalJsonlSink.resume_chain, root, FIXED_ID, keys=KEYS, epoch=KEYED)
    assert error.code is StorageErrorCode.UNSUPPORTED_PLATFORM
    assert fs.calls == []


def test_incapable_posix_refused_before_any_io(fs, monkeypatch):
    monkeypatch.setattr(sp, "_lock_capable", lambda: False)
    assert error_of(new_sink, fs).code is StorageErrorCode.UNSUPPORTED_PLATFORM
    assert fs.calls == []


@pytest.mark.parametrize("kwargs, code", [
    ({"keys": (auth_key(), chain_key())}, StorageErrorCode.INPUT_TYPE_INVALID),
    ({"keys": KeySet(auth=chain_key(), chain=chain_key(), ref=None)}, StorageErrorCode.KEY_PURPOSE_MISMATCH),
    ({"keys": KeySet(auth=auth_key(), chain=AuditKey.from_bytes(KeyPurpose.CHAIN, AUTH_MATERIAL), ref=None)},
     StorageErrorCode.KEYS_NOT_INDEPENDENT),
    ({"epoch": "keyed"}, StorageErrorCode.INPUT_TYPE_INVALID),
    ({"limits": {"segment_max_bytes": 1}}, StorageErrorCode.INPUT_TYPE_INVALID),
    ({"clock": "now"}, StorageErrorCode.INPUT_TYPE_INVALID),
    ({"readable_labels": ["a"]}, StorageErrorCode.INPUT_TYPE_INVALID),
])
def test_invalid_configuration_refused_before_any_io(fs, kwargs, code):
    arguments = {"keys": KEYS, "epoch": KEYED, **kwargs}
    assert error_of(LocalJsonlSink.create_chain, fake_root(), **arguments).code is code
    assert fs.calls == []


def test_k_auth_equal_to_epoch_ref_refused_before_genesis_header(fs):
    """Item 2: C1 checks headers against K_chain only; C3 checks K_auth against the epoch itself."""
    sharing = AuditKey.from_bytes(KeyPurpose.AUTH, REF_MATERIAL)
    error = error_of(LocalJsonlSink.create_chain, fake_root(), keys=KeySet(auth=sharing, chain=chain_key(), ref=None),
                     epoch=KEYED)
    assert (error.code, error.path) == (StorageErrorCode.KEYS_NOT_INDEPENDENT, "epoch")
    assert fs.calls == []


def test_audit_root_must_be_an_audit_directory(fs):
    assert error_of(LocalJsonlSink.create_chain, object(), keys=KEYS, epoch=KEYED).code is \
        StorageErrorCode.INPUT_TYPE_INVALID
    assert fs.calls == []


@pytest.mark.parametrize("size, records, ok", [
    (MIN_SEGMENT_BYTES, 3, True), (MIN_SEGMENT_BYTES - 1, 3, False), (sp.MAX_FILE_BYTES, 3, True),
    (sp.MAX_FILE_BYTES + 1, 3, False), (True, 3, False), (MIN_SEGMENT_BYTES, 2, False),
    (MIN_SEGMENT_BYTES, M, True), (MIN_SEGMENT_BYTES, M + 1, False), (MIN_SEGMENT_BYTES, False, False),
])
def test_sink_limits_boundaries(size, records, ok):
    """H-2 / D-C3-8: 3L minimum (derived from C1), MAX_FILE_BYTES maximum, at least 3 records, exact int."""
    if ok:
        assert SinkLimits(size, records).event_id_index_max == records
    else:
        assert error_of(SinkLimits, size, records).code is StorageErrorCode.INPUT_TYPE_INVALID


def test_derived_constants_come_from_c1():
    assert CLOSE_RESERVE == MAX_RECORD_LINE_BYTES and MIN_SEGMENT_BYTES == 3 * MAX_RECORD_LINE_BYTES
    source = inspect.getsource(jsonl)
    assert "20_480" not in source and "20480" not in source and "61440" not in source


def test_sink_hygiene(fs):
    sink = new_sink(fs)
    assert repr(sink) == "LocalJsonlSink(state='ready')" and str(sink) == repr(sink)
    for action in (lambda: pickle.dumps(sink), lambda: copy.copy(sink), lambda: copy.deepcopy(sink)):
        with pytest.raises(TypeError):
            action()
    with pytest.raises(TypeError):
        LocalJsonlSink(_token=object(), audit=fake_root(), keys=KEYS, epoch=KEYED, limits=SinkLimits(), clock=Clock(),
                       readable_labels=None)
    sink.close()


# === 2. Genesis (A-5.2, X-1, X-7 Option A) =======================================================================


def test_genesis_order_contents_and_first_anchor(fs):
    sink = new_sink(fs)
    chain_id = sink.chain_id
    assert len(chain_id) == 32 and sink.state is SinkState.READY
    first_lock = fs.calls.index("acquire_writer_lock")
    assert [op for op in fs.calls[:first_lock] if op in WRITE_OPS] == ["open_chain:create", "audit.sync"]  # X-1
    assert fs.calls[:3] == ["audit.list_names", "open_chain:create", "audit.sync"]  # G2, G3, G4
    assert fs.calls[3:7] == ["acquire_writer_lock", "verify_held", "verify_chain_named", "chain.list_names"]  # G5-G7
    assert set(fs.directory(chain_id).entries) == {LOCK, "seg-0.jsonl", ANCHOR_NAME}
    header = parse_record(fs.segment(chain_id, 0))
    assert header.kind is RecordKind.SEGMENT_OPEN and header.header.reason is OpenReason.GENESIS
    assert (header.segment, header.seq, header.prev_record_digest) == (0, 0, None)
    anchor = fs.anchor(chain_id)
    assert (anchor.seq, anchor.generation, anchor.record_digest) == (0, 1, header.record_digest)
    sink.close()
    assert_valid(fs, chain_id)


def test_chain_ids_are_random_128_bit(monkeypatch):
    """A1: genesis uses records.new_chain_id (secrets.token_hex(16))."""
    ids = {jsonl.new_chain_id() for _ in range(1000)}
    assert len(ids) == 1000 and all(len(i) == 32 and i == i.lower() and int(i, 16) >= 0 for i in ids)
    assert "secrets.token_hex(16)" in inspect.getsource(sys.modules["rig_sentinel.audit.records"].new_chain_id)


def test_existing_name_refused_at_g2_without_mkdir(fs, monkeypatch):
    """A2: an existing directory is never treated as a fresh chain."""
    monkeypatch.setattr(jsonl, "new_chain_id", lambda: FIXED_ID)
    fs.root["chain-" + FIXED_ID] = FakeDir()
    error = error_of(new_sink, fs)
    assert (error.code, error.path) == (StorageErrorCode.FILE_EXISTS, "chain:exists")
    assert fs.calls == ["audit.list_names"]


@pytest.mark.parametrize("planted", ["seg-0.jsonl", ANCHOR_NAME, ANCHOR_TEMP_NAME, ".seq_anchor.q0", "foreign"])
def test_prepopulated_directory_adopted_in_race_is_refused_at_g7(fs, monkeypatch, planted):
    """A5: a racer's non-empty directory, adopted by the non-exclusive open_chain, fails closed; nothing removed."""
    monkeypatch.setattr(jsonl, "new_chain_id", lambda: FIXED_ID)

    def race(*_args):
        directory = FakeDir()
        directory.entries[planted] = FakeFile(b"x")
        fs.root["chain-" + FIXED_ID] = directory

    fs.on("open_chain:create", race)
    error = error_of(new_sink, fs)
    assert (error.code, error.path) == (StorageErrorCode.RECOVERY_REQUIRED, "genesis:not-fresh")
    assert planted in fs.directory(FIXED_ID).entries and fs.removed == []
    assert fs.calls[-1] == "release" and "create_exclusive" not in fs.calls


def test_empty_directory_adopted_in_race_is_the_documented_residual(fs, monkeypatch):
    """R-3c: an empty private directory planted between G2 and G3 is adopted; it holds nothing but our lock."""
    monkeypatch.setattr(jsonl, "new_chain_id", lambda: FIXED_ID)
    fs.on("open_chain:create", lambda *_a: fs.root.setdefault("chain-" + FIXED_ID, FakeDir()))
    sink = new_sink(fs)
    assert sink.chain_id == FIXED_ID and set(fs.directory(FIXED_ID).entries) == {LOCK, "seg-0.jsonl", ANCHOR_NAME}
    sink.close()


@pytest.mark.parametrize("op, code", [
    ("open_chain:create", StorageErrorCode.UNSAFE_PERMISSIONS), ("audit.sync", StorageErrorCode.DURABILITY_UNCERTAIN),
    ("acquire_writer_lock", StorageErrorCode.LOCKED), ("verify_held", StorageErrorCode.LOCK_INVALID),
    ("verify_chain_named", StorageErrorCode.UNSAFE_PATH), ("chain.list_names", StorageErrorCode.STORAGE_UNAVAILABLE),
    ("create_exclusive", StorageErrorCode.FILE_EXISTS), ("chain.sync", StorageErrorCode.DURABILITY_UNCERTAIN),
    ("append", StorageErrorCode.PARTIAL_WRITE), ("seg.sync", StorageErrorCode.DURABILITY_FAILED),
    ("replace_atomically", StorageErrorCode.DURABILITY_UNCERTAIN),
])
def test_genesis_failure_at_each_step_fails_closed_without_cleanup(fs, monkeypatch, op, code):
    """A6/A7: every failure refuses; no retry, no alternative name, no removal; the lock (if taken) is released."""
    ids = []
    monkeypatch.setattr(jsonl, "new_chain_id", lambda: ids.append(FIXED_ID) or FIXED_ID)
    fs.on(op, fail(code, "injected"))
    error = error_of(new_sink, fs)
    expected = StorageErrorCode.ANCHOR_UPDATE_FAILED if op == "replace_atomically" else code
    assert error.code is expected
    assert ids == [FIXED_ID] and fs.calls.count("open_chain:create") <= 1 and fs.removed == []
    if "acquire_writer_lock" in fs.calls and op != "acquire_writer_lock":
        assert fs.calls[-1] == "release"
    else:
        assert "release" not in fs.calls


def test_malformed_generated_chain_id_is_an_invariant_breach_before_io(fs, monkeypatch):
    monkeypatch.setattr(jsonl, "new_chain_id", lambda: "AB" * 16)
    assert error_of(new_sink, fs).code is StorageErrorCode.INTERNAL_INVARIANT
    assert fs.calls == []


def test_bad_clock_refused_at_genesis_before_the_segment_exists(fs):
    error = error_of(new_sink, fs, clock=lambda: "2026-11-23 12:00:00")
    assert (error.code, error.path) == (StorageErrorCode.INPUT_TYPE_INVALID, "clock")
    assert "create_exclusive" not in fs.calls and fs.calls[-1] == "release"


def test_jsonl_adds_no_c2c_write_path_and_opens_chains_only_as_approved():
    """X-7 Option A (structural): open_chain only with no create argument or the literal create=True."""
    tree = ast.parse(inspect.getsource(jsonl))
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "open_chain"]
    assert len(calls) == 2
    for call in calls:
        keywords = [(k.arg, ast.literal_eval(k.value)) for k in call.keywords]
        assert keywords in ([], [("create", True)])
    called = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not called & {"open_append", "link_no_replace", "remove_created", "created_token"}
    assert "import os" not in inspect.getsource(jsonl)


# === 3. Append, duplicates, checkpoints (A-6, A-9) ================================================================


def test_append_commit_protocol_order_and_receipt(fs):
    sink = new_sink(fs)
    start = len(fs.calls)
    receipt = sink.append(validated())
    assert receipt.status is ReceiptStatus.STORED and receipt.stored
    assert (receipt.segment, receipt.seq, receipt.durability) == (0, 1, Durability.FSYNC)
    assert receipt.anchor is jsonl.AnchorState.COMMITTED and receipt.code is None
    ops = [op for op in fs.calls[start:]]
    assert ops == ["verify_held", "verify_chain_named", "verify_name",  # P1 (row A)
                   "verify_held", "verify_chain_named", "verify_name",  # W1 (row W)
                   "append", "verify_held", "verify_name", "seg.sync",  # W2, W3 (row SS)
                   "verify_held", "verify_chain_named", "replace_atomically"]  # W4 (row X)
    assert fs.anchor(sink.chain_id).generation == 2 and fs.anchor(sink.chain_id).record_digest == receipt.record_digest
    sink.close()
    assert_valid(fs, sink.chain_id)


def test_duplicate_event_id_rejected_without_write(fs):
    sink = new_sink(fs)
    event = validated()
    assert sink.append(event).stored
    start, before = len(fs.calls), fs.snapshot()
    receipt = sink.append(event)
    assert (receipt.status, receipt.code) == (ReceiptStatus.REJECTED, StorageErrorCode.DUPLICATE_EVENT_ID)
    assert_no_write(fs, start, before)
    assert sink.state is SinkState.READY and sink.append(validated()).stored
    sink.close()


def test_carrier_event_id_is_never_trusted(fs):
    """Item 1: a mutated carrier event_id cannot bypass duplicate detection."""
    sink = new_sink(fs)
    event = validated()
    assert sink.append(event).stored
    object.__setattr__(event, "event_id", "f" * 32)
    assert sink.append(event).code is StorageErrorCode.DUPLICATE_EVENT_ID
    sink.close()


@pytest.mark.parametrize("bad", [None, b"{}", "projection"])
def test_unvalidated_input_rejected_and_writer_stays_ready(fs, bad):
    sink = new_sink(fs)
    start, before = len(fs.calls), fs.snapshot()
    receipt = sink.append(bad)
    assert (receipt.status, receipt.code) == (ReceiptStatus.REJECTED, StorageErrorCode.NOT_VALIDATED)
    assert fs.writes_after(start) == [] and fs.snapshot() == before and sink.state is SinkState.READY
    sink.close()


def test_projection_for_another_epoch_is_rejected_by_the_gate(fs):
    sink = new_sink(fs)
    receipt = sink.append(validated(unlinked=True))
    assert receipt.status is ReceiptStatus.REJECTED and receipt.code is StorageErrorCode.PROJECTION_REJECTED
    assert sink.state is SinkState.READY
    sink.close()


def test_checkpoint_marks_the_last_record_and_returns_custody_document(fs):
    sink = new_sink(fs)
    stored = sink.append(validated())
    document = sink.checkpoint()
    checkpoint = verify_checkpoint(document, {chain_key().key_id: chain_key()})
    anchor = fs.anchor(sink.chain_id)
    assert (checkpoint.seq, checkpoint.record_digest, checkpoint.anchor_generation) == (
        anchor.seq, anchor.record_digest, anchor.generation)
    marker = parse_record(fs.lines(sink.chain_id)[-1])
    assert marker.kind is RecordKind.CHECKPOINT_MARKER and marker.body == {
        "checkpoint_seq": stored.seq, "checkpoint_record_digest": stored.record_digest}
    sink.close()
    assert_valid(fs, sink.chain_id)


# === 4. Size rotation (H-1, A-6 P8, A-8) ===========================================================================


def test_size_rotation_rebuilds_the_event_at_the_new_position(fs):
    sink = new_sink(fs, limits=SMALL)
    first = sink.append(validated())
    assert (first.segment, first.seq) == (0, 1)
    second = sink.append(validated())  # records_in_segment + 2 > 3: rotation
    lines = fs.lines(sink.chain_id)
    close, opened, event = (parse_record(line) for line in lines[2:5])
    assert close.kind is RecordKind.SEGMENT_CLOSE and close.body["reason"] == CloseReason.SIZE.value
    assert opened.header.reason is OpenReason.ROTATION and opened.seq == close.seq + 1
    assert (second.segment, second.seq) == (1, close.seq + 2)
    assert event.prev_record_digest == opened.record_digest and event.segment == 1
    assert fs.segment_numbers(sink.chain_id) == [0, 1]
    sink.close()
    assert_valid(fs, sink.chain_id)


def test_duplicate_at_the_rotation_boundary_never_rotates(fs):
    sink = new_sink(fs, limits=SMALL)
    event = validated()
    assert sink.append(event).stored  # segment 0 is now full for events
    start, before = len(fs.calls), fs.snapshot()
    assert sink.append(event).code is StorageErrorCode.DUPLICATE_EVENT_ID
    assert_no_write(fs, start, before)
    assert fs.segment_numbers(sink.chain_id) == [0]
    sink.close()


def measured_prefix(fs):
    """With default limits: k events and the segment size after the open and k events (>= 2L), plus the
    length of event k + 1. Line lengths depend on seq digits, so sizes are measured, never assumed."""
    sink = new_sink(fs)
    while len(fs.segment(sink.chain_id, 0)) < 2 * L:
        sink.append(validated())
    sink.append(validated())
    lines = fs.lines(sink.chain_id)
    sink.close()
    fs.root.clear()
    k = len(lines) - 2
    return k, sum(len(line) for line in lines[:k + 1]), len(lines[k + 1])


def test_exact_fit_and_one_byte_over(fs):
    k, size_after_k, next_len = measured_prefix(fs)
    exact = size_after_k + next_len + CLOSE_RESERVE  # >= 3L
    for limit, rotates in ((exact, False), (exact - 1, True)):
        sink = new_sink(fs, limits=SinkLimits(segment_max_bytes=limit))
        for _ in range(k):
            assert sink.append(validated()).segment == 0
        assert sink.append(validated()).segment == (1 if rotates else 0)
        sink.close()
        assert_valid(fs, sink.chain_id)


def test_checkpoint_at_the_rotation_boundary(fs):
    sink = new_sink(fs, limits=SMALL)
    sink.append(validated())
    document = sink.checkpoint()  # does not fit: rotates and names the new segment's open
    checkpoint = verify_checkpoint(document, {chain_key().key_id: chain_key()})
    assert checkpoint.segment == 1 and checkpoint.anchor_generation == fs.anchor(sink.chain_id).generation
    sink.close()
    assert_valid(fs, sink.chain_id)


def test_shutdown_and_rotation_fit_a_segment_filled_to_the_admission_limit(fs):
    k, size_after_k, next_len = measured_prefix(fs)
    exact = size_after_k + CLOSE_RESERVE + next_len - 1  # event k + 1 misses by one byte
    sink = new_sink(fs, limits=SinkLimits(segment_max_bytes=exact))
    for _ in range(k):
        assert sink.append(validated()).segment == 0
    assert sink.append(validated()).segment == 1  # rotation: its close fits by the reserve
    sink.close()  # shutdown close fits too
    assert_valid(fs, sink.chain_id)


def test_measured_maximum_segment_close_fits_the_reserve():
    position = ChainPosition("f" * 32, M - 1, M, "f" * 64)
    line = build_segment_close(position=position, chain_key=chain_key(), record_count=M + 1,
                               reason=CloseReason.CHAIN_KEY_ROTATION)
    assert len(line) <= CLOSE_RESERVE


# === 5. Operator rotations (D-C3-10, A-8) ============================================================================


def test_epoch_auth_and_chain_key_rotations_verify(fs):
    sink = new_sink(fs)
    sink.append(validated())
    sink.rotate_epoch(ProjectionEpoch.unlinked())
    assert sink.append(validated(unlinked=True)).stored
    sink.rotate_auth_key(auth2())
    assert sink.append(validated(auth=auth2(), unlinked=True)).stored
    sink.rotate_chain_key(chain_key(CHAIN2_MATERIAL))
    assert sink.append(validated(auth=auth2(), unlinked=True)).stored
    anchor = fs.anchor(sink.chain_id, chain_key(CHAIN2_MATERIAL))
    assert anchor.auth_key_id == auth2().key_id and anchor.chain_key_id == chain_key(CHAIN2_MATERIAL).key_id
    sink.close()
    assert_valid(fs, sink.chain_id, [chain_key(), chain_key(CHAIN2_MATERIAL)], [auth_key(), auth2()])
    reasons = [parse_record(line).body.get("reason") for line in fs.lines(sink.chain_id)
               if parse_record(line).kind is not RecordKind.EVENT and parse_record(line).body]
    assert "epoch_rotation" in reasons and "key_rotation" in reasons and "chain_key_rotation" in reasons


@pytest.mark.parametrize("call, code", [
    (lambda s: s.rotate_auth_key(auth_key()), StorageErrorCode.KEYS_NOT_INDEPENDENT),
    (lambda s: s.rotate_auth_key(AuditKey.from_bytes(KeyPurpose.AUTH, CHAIN_MATERIAL)),
     StorageErrorCode.KEYS_NOT_INDEPENDENT),
    (lambda s: s.rotate_auth_key(AuditKey.from_bytes(KeyPurpose.AUTH, REF_MATERIAL)),
     StorageErrorCode.KEYS_NOT_INDEPENDENT),
    (lambda s: s.rotate_chain_key(chain_key()), StorageErrorCode.KEYS_NOT_INDEPENDENT),
    (lambda s: s.rotate_chain_key(auth2()), StorageErrorCode.KEY_PURPOSE_MISMATCH),
    (lambda s: s.rotate_chain_key(AuditKey.from_bytes(KeyPurpose.CHAIN, bytes(range(33, 65)))),
     StorageErrorCode.KEYS_NOT_INDEPENDENT),
    (lambda s: s.rotate_epoch(KEYED), StorageErrorCode.INPUT_TYPE_INVALID),
    (lambda s: s.rotate_epoch("unlinked"), StorageErrorCode.INPUT_TYPE_INVALID),
])
def test_rotation_parameters_refused_before_the_close(fs, call, code):
    sink = new_sink(fs)
    start, before = len(fs.calls), fs.snapshot()
    assert error_of(call, sink).code is code
    assert_no_write(fs, start, before)
    assert sink.state is SinkState.READY and sink.append(validated()).stored
    sink.close()


@pytest.mark.parametrize("material", ["ref", "eref"])
def test_rotation_to_a_key_sharing_k_ref_is_refused_after_an_unlinked_epoch(fs, material):
    """With an unlinked epoch the epoch check cannot see K_ref; the K_ref/K_eref independence check still must."""
    from rig_sentinel.audit import derive_engine_ref_key

    sink = new_sink(fs)
    sink.rotate_epoch(ProjectionEpoch.unlinked())
    shared = REF_MATERIAL if material == "ref" else derive_engine_ref_key(ref_key())._material
    start, before = len(fs.calls), fs.snapshot()
    error = error_of(sink.rotate_auth_key, AuditKey.from_bytes(KeyPurpose.AUTH, shared))
    assert (error.code, error.path) == (StorageErrorCode.KEYS_NOT_INDEPENDENT, "keys")
    assert_no_write(fs, start, before)
    sink.close()


def test_bad_or_backwards_clock_refused_before_rotation_close(fs):
    clock = Clock()
    sink = new_sink(fs, clock=clock)
    for value in ("not a time", "2026-02-30T00:00:00.000000Z", "2000-01-01T00:00:00.000000Z"):
        start, before = len(fs.calls), fs.snapshot()
        broken = sink._clock
        sink._clock = lambda value=value: value
        error = error_of(sink.rotate_epoch, ProjectionEpoch.unlinked())
        sink._clock = broken
        assert (error.code, error.path) == (StorageErrorCode.INPUT_TYPE_INVALID, "clock")
        assert_no_write(fs, start, before)
    sink.close()


# === 6. Close and clean resume (A-5.3, M-1) ============================================================================


def test_close_writes_shutdown_and_releases_the_lock_last(fs):
    sink = new_sink(fs)
    sink.append(validated())
    sink.close()
    assert fs.calls[-1] == "release" and sink.state is SinkState.CLOSED
    tail = parse_record(fs.lines(sink.chain_id)[-1])
    assert tail.kind is RecordKind.SEGMENT_CLOSE and tail.body["reason"] == "shutdown"
    sink.close()  # idempotent: nothing further
    assert fs.calls[-1] == "release" and fs.calls.count("release") == 1
    receipt = sink.append(validated())
    assert (receipt.code, receipt.detail) == (StorageErrorCode.SINK_SEALED, "sink:closed")
    assert error_of(sink.checkpoint).code is StorageErrorCode.SINK_SEALED


def test_resume_cycles_restore_generation_and_continue_the_chain(fs):
    sink = new_sink(fs)
    chain_id = sink.chain_id
    sink.append(validated())
    sink.close()
    generations = [fs.anchor(chain_id).generation]
    for cycle in range(5):
        sink = resume(chain_id)
        opened = parse_record(fs.lines(chain_id)[-1])
        assert opened.header.reason is OpenReason.WRITER_RESTART and opened.segment == cycle + 1
        assert fs.anchor(chain_id).generation == generations[-1] + 1  # restored, then +1 (M-1, I5)
        sink.append(validated())
        sink.close()
        generations.append(fs.anchor(chain_id).generation)
    assert generations == sorted(set(generations))
    assert_valid(fs, chain_id)


def test_resume_after_size_close_without_next_segment_is_clean(fs):
    sink = new_sink(fs, limits=SMALL)
    sink.append(validated())
    fs.on("create_exclusive", fail(StorageErrorCode.STORAGE_UNAVAILABLE, "file:create"), nth=2)
    error_of(sink.append, validated())  # close(SIZE) committed, the next segment never created
    assert sink.state is SinkState.SEALED
    sink.close()
    resumed = resume(sink.chain_id, limits=SMALL)
    assert parse_record(fs.lines(sink.chain_id)[-1]).header.reason is OpenReason.WRITER_RESTART
    resumed.close()
    assert_valid(fs, sink.chain_id)


def test_malformed_chain_id_refused_before_open_chain(fs):
    for bad in ("AB" * 16, "ab" * 15, "ab" * 17, "../" + "a" * 29, 123, None, "chain-" + "a" * 26):
        assert error_of(resume, bad).code is StorageErrorCode.INPUT_TYPE_INVALID
    assert fs.calls == []


def closed_chain(fs, *, limits=None, events=1):
    sink = new_sink(fs, limits=limits)
    for _ in range(events):
        sink.append(validated())
    sink.close()
    fs.calls.clear()
    return sink.chain_id


def tamper_last_byte(data):
    return data[:-2] + bytes([data[-2] ^ 1]) + data[-1:]


@pytest.mark.parametrize("damage, label", [
    (lambda d, c: d.entries.__setitem__(ANCHOR_TEMP_NAME, FakeFile(b"x")), "resume:pending-anchor"),
    (lambda d, c: d.entries.__setitem__(".seq_anchor.q3", FakeFile(b"x")), "resume:pending-anchor"),
    (lambda d, c: d.entries.__setitem__("notes.txt", FakeFile(b"x")), "resume:unexpected-entry"),
    (lambda d, c: d.entries.pop(ANCHOR_NAME), "resume:no-anchor"),
    (lambda d, c: d.entries.__setitem__("seg-5.jsonl", FakeFile(b"")), "resume:segments"),
    (lambda d, c: d.entries.__setitem__(ANCHOR_NAME, FakeFile(tamper_last_byte(bytes(d.entries[ANCHOR_NAME].data)))),
     "resume:anchor"),
    (lambda d, c: d.entries["seg-0.jsonl"].data.extend(b'{"partial'), "resume:tail"),
    (lambda d, c: d.entries.__setitem__("seg-0.jsonl", FakeFile(tamper_last_byte(bytes(d.entries["seg-0.jsonl"].data)))),
     "resume:tail"),
    (lambda d, c: d.entries.__setitem__("seg-1.jsonl", FakeFile(b"")), "resume:anchor"),
])
def test_resume_refuses_unclean_states_without_writing(fs, damage, label):
    chain_id = closed_chain(fs)
    damage(fs.directory(chain_id), chain_id)
    before = fs.snapshot()
    error = error_of(resume, chain_id)
    assert (error.code, error.path) == (StorageErrorCode.RECOVERY_REQUIRED, label)
    assert_no_write(fs, 0, before)
    assert fs.calls[-1] == "release"


def synthetic_chain(fs, *, s0, g0, n=0, reason=CloseReason.SHUTDOWN, auth=None, key=None, chain_id=FIXED_ID):
    """F-RESUME(s0, g0, n): seg-n ends in an authenticated close at (n, s0); its anchor has generation g0."""
    key = key or chain_key()
    directory = FakeDir()
    directory.entries[LOCK] = FakeFile()  # the permanent lock file of an earlier writer
    for number in range(n):
        directory.entries[f"seg-{number}.jsonl"] = FakeFile(b"")
    line = build_segment_close(position=ChainPosition(chain_id, n, s0, "cd" * 32), chain_key=key, record_count=2,
                               reason=reason)
    directory.entries[f"seg-{n}.jsonl"] = FakeFile(line)
    directory.entries[ANCHOR_NAME] = FakeFile(build_anchor(
        chain_id=chain_id, segment=n, seq=s0, record_digest=parse_record(line).record_digest,
        auth_key_id=(auth or auth_key()).key_id, generation=g0, chain_key=key))
    fs.root["chain-" + chain_id] = directory
    return chain_id


@pytest.mark.parametrize("reason", [CloseReason.EPOCH_ROTATION, CloseReason.KEY_ROTATION,
                                    CloseReason.CHAIN_KEY_ROTATION])
def test_rotation_close_tail_requires_recovery(fs, reason):
    """L-2: after a rotation close the only valid next open is the matching rotation open (C4)."""
    synthetic_chain(fs, s0=5, g0=6, n=1, reason=reason)
    before = fs.snapshot()
    error = error_of(resume, FIXED_ID)
    assert (error.code, error.path) == (StorageErrorCode.RECOVERY_REQUIRED, "resume:not-clean")
    assert fs.snapshot() == before and fs.writes_after(0) == []


def test_auth_key_change_requires_rotation(fs):
    synthetic_chain(fs, s0=5, g0=6, auth=auth2())
    error = error_of(resume, FIXED_ID)
    assert error.code is StorageErrorCode.KEY_CHANGE_REQUIRES_ROTATION and fs.writes_after(0) == []


def test_chain_key_change_is_not_authenticated(fs):
    synthetic_chain(fs, s0=5, g0=6, key=chain_key(CHAIN2_MATERIAL))
    assert error_of(resume, FIXED_ID).code is StorageErrorCode.RECOVERY_REQUIRED


@pytest.mark.parametrize("g0", [0])
def test_generation_zero_refused(fs, g0):
    synthetic_chain(fs, s0=5, g0=g0)
    assert error_of(resume, FIXED_ID).path == "resume:anchor"


def test_segment_larger_than_the_configured_limit_refused(fs):
    chain_id = closed_chain(fs, limits=SinkLimits(segment_max_bytes=4 * L))
    padding = parse_record(fs.lines(chain_id)[-1])  # still a valid close at the tail
    assert padding.kind is RecordKind.SEGMENT_CLOSE
    fs.directory(chain_id).entries["seg-0.jsonl"].data[:0] = b"x" * (3 * L)
    error = error_of(resume, chain_id, limits=SinkLimits(segment_max_bytes=MIN_SEGMENT_BYTES))
    assert (error.code, error.path) == (StorageErrorCode.RECOVERY_REQUIRED, "resume:segment")


def test_l2_windows_on_disk_require_recovery(fs):
    """A-8.3: each half-finished rotation state is refused with no write and the lock released."""
    # (1) epoch rotation: close committed, next segment never created
    sink = new_sink(fs)
    fs.on("create_exclusive", fail(StorageErrorCode.STORAGE_UNAVAILABLE, "file:create"), nth=2)
    error_of(sink.rotate_epoch, ProjectionEpoch.unlinked())
    sink.close()
    assert error_of(resume, sink.chain_id).path == "resume:not-clean"
    # (2) new segment created, header not durable (HEADER_INCOMPLETE)
    fs.hooks.clear()
    sink = new_sink(fs, limits=SMALL)
    sink.append(validated())
    fs.on("append", fail(StorageErrorCode.PARTIAL_WRITE, "file:partial"), nth=fs.calls.count("append") + 2)
    error_of(sink.append, validated())
    sink.close()
    assert error_of(resume, sink.chain_id, limits=SMALL).path == "resume:anchor"
    # (3) chain-key rotation: close under the old key, open under the new key not anchored
    fs.hooks.clear()
    sink = new_sink(fs)
    fs.on("replace_atomically", fail(StorageErrorCode.DURABILITY_UNCERTAIN, "directory:sync"),
          nth=fs.calls.count("replace_atomically") + 2)
    assert error_of(sink.rotate_chain_key, chain_key(CHAIN2_MATERIAL)).code is StorageErrorCode.ANCHOR_UPDATE_FAILED
    sink.close()
    assert error_of(resume, sink.chain_id).code is StorageErrorCode.RECOVERY_REQUIRED
    # (4) size rotation: open committed, event not written
    fs.hooks.clear()
    sink = new_sink(fs, limits=SMALL)
    sink.append(validated())
    fs.on("append", fail(StorageErrorCode.PARTIAL_WRITE, "file:partial"), nth=fs.calls.count("append") + 3)
    error_of(sink.append, validated())
    sink.close()
    assert error_of(resume, sink.chain_id, limits=SMALL).path == "resume:not-clean"
    assert fs.calls[-1] == "release"


def test_verify_on_resume_refuses_mid_file_corruption(fs):
    """D-C3-7 / founder H1 requirement 1: corruption before the tail is caught only with verify_on_resume=True."""
    chain_id = closed_chain(fs, events=3)
    segment = fs.directory(chain_id).entries["seg-0.jsonl"]
    lines = bytes(segment.data).split(b"\n")
    lines[1] = lines[1].replace(b'"seq":1', b'"seq":9')  # an event in the middle; the tail stays valid
    segment.data = bytearray(b"\n".join(lines))
    before = fs.snapshot()
    error = error_of(resume, chain_id, verify_on_resume=True)
    assert (error.code, error.path) == (StorageErrorCode.RECOVERY_REQUIRED, "verify:chain")
    assert_no_write(fs, 0, before)
    sink = resume(chain_id)  # residual R-8: without the option the tail window alone passes
    sink.close()


def test_verify_on_resume_accepts_a_valid_chain_and_retired_keys(fs):
    sink = new_sink(fs)
    sink.append(validated())
    sink.rotate_auth_key(auth2())
    sink.close()
    keys = KeySet(auth=auth2(), chain=chain_key(), ref=ref_key())
    assert error_of(resume, sink.chain_id, keys=keys, verify_on_resume=True).path == "verify:chain"
    resumed = resume(sink.chain_id, keys=keys, verify_on_resume=True, verify_auth_keys={auth_key().key_id: auth_key()})
    resumed.close()
    assert error_of(resume, sink.chain_id, verify_on_resume="yes").code is StorageErrorCode.INPUT_TYPE_INVALID


# === 7. Commit-protocol faults (I1-I4) ===============================================================================


@pytest.mark.parametrize("op, code, raised", [
    ("append", StorageErrorCode.PARTIAL_WRITE, StorageErrorCode.PARTIAL_WRITE),
    ("append", StorageErrorCode.FILE_TOO_LARGE, StorageErrorCode.FILE_TOO_LARGE),
    ("seg.sync", StorageErrorCode.DURABILITY_FAILED, StorageErrorCode.DURABILITY_FAILED),
    ("replace_atomically", StorageErrorCode.DURABILITY_UNCERTAIN, StorageErrorCode.ANCHOR_UPDATE_FAILED),
    ("replace_atomically", StorageErrorCode.STORAGE_UNAVAILABLE, StorageErrorCode.ANCHOR_UPDATE_FAILED),
])
def test_write_failures_seal_without_receipt_or_further_write(fs, op, code, raised):
    sink = new_sink(fs)
    anchor_before = bytes(fs.directory(sink.chain_id).entries[ANCHOR_NAME].data)
    fs.on(op, fail(code, "injected"), nth=fs.calls.count(op) + 1)
    error = error_of(sink.append, validated())
    assert error.code is raised and sink.state is SinkState.SEALED
    if op != "replace_atomically":
        assert bytes(fs.directory(sink.chain_id).entries[ANCHOR_NAME].data) == anchor_before  # I1
    start = len(fs.calls)
    receipt = sink.append(validated())
    assert (receipt.code, receipt.detail) == (StorageErrorCode.SINK_SEALED, "sink:sealed")
    assert error_of(sink.rotate_epoch, ProjectionEpoch.unlinked()).code is StorageErrorCode.SINK_SEALED
    sink.close()
    assert fs.writes_after(start) == [] and fs.calls[-1] == "release"  # I4: SEALED makes no further write


def test_partial_write_is_not_anchored(fs):
    sink = new_sink(fs)

    def half(seg, data):
        seg.file.data += data[:10]
        seg.sealed = True
        raise StorageError(StorageErrorCode.PARTIAL_WRITE, "file:partial")

    fs.on("append", half, nth=fs.calls.count("append") + 1)
    assert error_of(sink.append, validated()).code is StorageErrorCode.PARTIAL_WRITE
    assert fs.anchor(sink.chain_id).seq == 0
    sink.close()
    assert error_of(resume, sink.chain_id).path == "resume:tail"


def test_base_exception_inside_a_step_seals_and_propagates(fs):
    sink = new_sink(fs)

    def interrupt(*_args):
        raise KeyboardInterrupt

    fs.on("seg.sync", interrupt, nth=fs.calls.count("seg.sync") + 1)
    with pytest.raises(KeyboardInterrupt):
        sink.append(validated())
    assert sink.state is SinkState.SEALED
    sink.close()
    assert fs.calls[-1] == "release"


# === 8. Mandatory verification matrix (A-11, M-2) ======================================================================

REQUIRED_BEFORE = {"append": {"L", "D", "S"}, "seg.sync": {"L", "S"}, "replace_atomically": {"L", "D"},
                   "create_exclusive": {"L", "D"}, "chain.sync": {"L", "D"}}


def full_scenario(fs):
    sink = new_sink(fs, limits=SMALL)
    sink.append(validated())
    sink.append(validated())  # size rotation
    sink.checkpoint()  # checkpoint with rotation
    sink.rotate_epoch(ProjectionEpoch.unlinked())
    sink.rotate_auth_key(auth2())
    sink.rotate_chain_key(chain_key(CHAIN2_MATERIAL))
    sink.close()
    keys = KeySet(auth=auth2(), chain=chain_key(CHAIN2_MATERIAL), ref=None)
    resumed = resume(sink.chain_id, keys=keys, epoch=ProjectionEpoch.unlinked(), limits=SMALL)
    resumed.append(validated(auth=auth2(), unlinked=True))
    resumed.close()
    return sink.chain_id


def test_every_protected_write_is_preceded_by_its_checks(fs):
    chain_id = full_scenario(fs)
    seen = set()
    locked = False
    for op in fs.calls:
        if op == "acquire_writer_lock":
            locked = True
        if op in CHECK_OPS:
            seen.add(CHECK_OPS[op])
        elif op in REQUIRED_BEFORE:
            assert locked and REQUIRED_BEFORE[op] <= seen, (op, seen)
            seen = set()
        elif op == "release":
            locked = False
    assert_valid(fs, chain_id, [chain_key(), chain_key(CHAIN2_MATERIAL)], [auth_key(), auth2()])


@pytest.mark.parametrize("check, code", [("verify_held", StorageErrorCode.LOCK_INVALID),
                                         ("verify_chain_named", StorageErrorCode.UNSAFE_PATH),
                                         ("verify_name", StorageErrorCode.FILE_UNSAFE)])
def test_a_failed_check_at_any_point_seals_before_the_guarded_call(fs, check, code):
    """Inject the failure at every occurrence of the check in the full scenario: no write follows it."""
    reference = FakeFS()
    with pytest.MonkeyPatch.context() as patch:
        install(patch, reference)
        full_scenario(reference)
    total = reference.calls.count(check)
    assert total > 10
    for nth in range(1, total + 1):
        fs.root.clear()
        fs.calls.clear()
        fs.hooks.clear()
        fs.on(check, fail(code, "injected"), nth=nth)
        with contextlib.suppress(StorageError):
            full_scenario(fs)
        failed_at = [i for i, op in enumerate(fs.calls) if op == check][nth - 1]
        later = fs.writes_after(failed_at + 1)
        assert later == [], (check, nth, later)


def test_chain_directory_substitution_between_appends_seals(fs):
    sink = new_sink(fs)
    sink.append(validated())
    name = "chain-" + sink.chain_id
    fs.root["moved"] = fs.root.pop(name)
    fs.root[name] = FakeDir()
    start = len(fs.calls)
    error = error_of(sink.append, validated())
    assert (error.code, error.path) == (StorageErrorCode.UNSAFE_PATH, "chain:replaced")
    assert fs.writes_after(start) == [] and fs.root[name].entries == {} and sink.state is SinkState.SEALED
    sink.close()


def test_lock_loss_seals_and_forbids_unlocked_writing(fs):
    sink = new_sink(fs)
    fs.lock_ok = False
    start = len(fs.calls)
    assert error_of(sink.append, validated()).code is StorageErrorCode.LOCK_INVALID
    assert sink.state is SinkState.SEALED
    sink.close()  # SEALED: no SHUTDOWN close is attempted without the lock
    assert fs.writes_after(start) == [] and sink.state is SinkState.CLOSED and fs.calls[-1] == "release"


# === 9. Threads (D-C3-5) ==============================================================================================


def test_concurrent_entry_is_refused_not_interleaved(fs):
    sink = new_sink(fs)
    assert sink._busy.acquire(blocking=False)
    start = len(fs.calls)
    assert sink.append(validated()).code is StorageErrorCode.SINK_BUSY
    assert error_of(sink.checkpoint).code is StorageErrorCode.SINK_BUSY
    assert error_of(sink.close).code is StorageErrorCode.SINK_BUSY
    assert fs.calls[start:] == []
    sink._busy.release()
    events = [validated() for _ in range(40)]
    results = []
    barrier = threading.Barrier(4)

    def worker(chunk):
        barrier.wait()
        results.extend(sink.append(event) for event in chunk)

    threads = [threading.Thread(target=worker, args=(events[i::4],)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert all(r.stored or r.code is StorageErrorCode.SINK_BUSY for r in results) and len(results) == 40
    sink.close()
    assert_valid(fs, sink.chain_id)


# === 10. Capacity (L-R1-1; T-CAP-1 to T-CAP-9) ==========================================================================


def no_write_rejection(fs, sink, action, code, detail):
    """T-CAP-6 NO-WRITE: receipt or error, READY, no state change, no write call, identical files; 10 times."""
    state = (sink._seq, sink._generation, sink._segment, sink._prev_digest, sink._records_in_segment, set(sink._index))
    before = fs.snapshot()
    for _ in range(10):
        start = len(fs.calls)
        outcome = action()
        assert (outcome.code, outcome.detail) == (code, detail)
        assert all(op in CHECK_OPS for op in fs.calls[start:]), fs.calls[start:]
    assert fs.snapshot() == before and sink.state is SinkState.READY
    assert state == (sink._seq, sink._generation, sink._segment, sink._prev_digest, sink._records_in_segment,
                     set(sink._index))


def rejected_append(sink, event):
    return lambda: sink.append(event)


def rejected_call(call):
    def run():
        error = error_of(call)
        return jsonl._rejected(error.code, error.path)
    return run


def clean_close_at(fs, sink, *, seq, generation, key=None):
    """T-CAP-9: exactly one SHUTDOWN close at seq, anchor generation, CLOSED, lock released last."""
    before = len(fs.lines(sink.chain_id))
    sink.close()
    lines = fs.lines(sink.chain_id)
    assert len(lines) == before + 1 and sink.state is SinkState.CLOSED and fs.calls[-1] == "release"
    tail = parse_record(lines[-1])
    assert tail.kind is RecordKind.SEGMENT_CLOSE and tail.body["reason"] == "shutdown" and tail.seq == seq
    anchor = fs.anchor(sink.chain_id, key)
    assert (anchor.seq, anchor.generation, anchor.record_digest) == (seq, generation, tail.record_digest)


def test_t_cap_1_direct_append_near_max_generation(fs):
    synthetic_chain(fs, s0=10, g0=M - 3)
    sink = resume(FIXED_ID)
    assert (sink._generation, sink._seq) == (M - 2, 11)
    assert sink.append(validated()).stored and sink._generation == M - 1
    no_write_rejection(fs, sink, rejected_append(sink, validated()), StorageErrorCode.ENTRY_LIMIT_EXCEEDED,
                       "chain:generation")
    clean_close_at(fs, sink, seq=13, generation=M)


def test_t_cap_2_direct_append_near_max_seq(fs):
    synthetic_chain(fs, s0=M - 3, g0=5)
    sink = resume(FIXED_ID)
    assert (sink._seq, sink._generation) == (M - 2, 6)
    assert sink.append(validated()).seq == M - 1
    no_write_rejection(fs, sink, rejected_append(sink, validated()), StorageErrorCode.ENTRY_LIMIT_EXCEEDED, "chain:seq")
    clean_close_at(fs, sink, seq=M, generation=8)


def size_rotation_ready(fs, *, s0, g0):
    """A writer whose next event must rotate (one record per segment), at the given resumed position."""
    synthetic_chain(fs, s0=s0, g0=g0)
    sink = resume(FIXED_ID, limits=SMALL)
    assert sink.append(validated()).stored  # the segment is now full for events: the next one rotates
    return sink


def test_t_cap_3a_rotation_at_the_generation_boundary_is_accepted(fs):
    sink = size_rotation_ready(fs, s0=10, g0=M - 6)  # after open and one event: g = M - 4
    assert sink._generation == M - 4
    receipt = sink.append(validated())
    assert receipt.stored and receipt.segment == 2 and sink._generation == M - 1
    clean_close_at(fs, sink, seq=receipt.seq + 1, generation=M)


def test_t_cap_3b_rotation_rejected_but_direct_record_still_fits(fs):
    sink = size_rotation_ready(fs, s0=10, g0=M - 5)  # g = M - 3: rotation needs + 4
    no_write_rejection(fs, sink, rejected_append(sink, validated()), StorageErrorCode.ENTRY_LIMIT_EXCEEDED,
                       "chain:generation")
    assert "create_exclusive" not in fs.calls[-30:]
    sink._limits = SinkLimits(segment_max_bytes=MIN_SEGMENT_BYTES, segment_max_records=4)  # P5 now selects direct
    assert sink.append(validated()).segment == 1 and sink._generation == M - 2  # direct path: g + 2 <= M
    clean_close_at(fs, sink, seq=sink._seq + 1, generation=M - 1)


def test_t_cap_3c_rotation_seq_reserve_is_four(fs):
    sink = size_rotation_ready(fs, s0=M - 5, g0=5)  # after open and one event: s = M - 3; R1's "+3" would accept
    assert sink._seq == M - 3
    no_write_rejection(fs, sink, rejected_append(sink, validated()), StorageErrorCode.ENTRY_LIMIT_EXCEEDED, "chain:seq")
    clean_close_at(fs, sink, seq=M - 2, generation=sink._generation + 1)


def test_t_cap_3d_rotation_at_the_seq_boundary_is_accepted(fs):
    sink = size_rotation_ready(fs, s0=M - 6, g0=5)  # s = M - 4
    receipt = sink.append(validated())
    assert receipt.stored and receipt.seq == M - 1
    clean_close_at(fs, sink, seq=M, generation=sink._generation + 1)


@pytest.mark.parametrize("rotate", ["epoch", "auth", "chain"])
def test_t_cap_4_operator_rotations_near_max(fs, rotate, monkeypatch):
    calls = {"epoch": lambda s: s.rotate_epoch(ProjectionEpoch.unlinked()),
             "auth": lambda s: s.rotate_auth_key(auth2()),
             "chain": lambda s: s.rotate_chain_key(chain_key(CHAIN2_MATERIAL))}
    synthetic_chain(fs, s0=10, g0=M - 4)  # after the open: g = M - 3, so + 3 = M is accepted
    sink = resume(FIXED_ID)
    calls[rotate](sink)
    assert sink._generation == M - 1
    clean_close_at(fs, sink, seq=sink._seq + 1, generation=M, key=sink._chain_key)
    fs.root.clear()
    synthetic_chain(fs, s0=10, g0=M - 3)  # g = M - 2: + 3 = M + 1
    clock = Clock()
    sink = resume(FIXED_ID, clock=clock)
    reads = clock.calls
    no_write_rejection(fs, sink, rejected_call(lambda: calls[rotate](sink)), StorageErrorCode.ENTRY_LIMIT_EXCEEDED,
                       "chain:generation")
    assert clock.calls == reads  # refused before the clock is read (A-8.1 step 0)
    assert sink._chain_key.key_id == chain_key().key_id and sink._auth.key_id == auth_key().key_id
    assert sink.append(validated()).stored  # the old keys and epoch remain in force


def test_t_cap_5a_segment_capacity_predicate():
    assert [jsonl._segment_capacity_ok(k) for k in (0, M - 2, M - 1, M)] == [True, True, True, False]
    assert all(type(jsonl._segment_capacity_ok(k)) is bool for k in (0, M))


def test_t_cap_5b_seq_refuses_before_segment_exhaustion_in_c1_valid_states(fs):
    """k <= s always (C1); W-STATE k = s near M is refused by chain:seq, never by chain:segment."""
    sink = new_sink(fs, limits=SMALL)
    sink.append(validated())  # full for events
    for k, accepted in ((M - 4, True), (M - 3, False)):
        sink._segment = sink._seq = k  # W-STATE: C1-valid (segment <= seq)
        if accepted:
            assert jsonl._capacity_problem(k, sink._generation, k, jsonl.SIZE_ROTATION_RESERVE,
                                           new_segment=True) is None
        else:
            event = validated()
            outcome = sink.append(event)
            assert (outcome.code, outcome.detail) == (StorageErrorCode.ENTRY_LIMIT_EXCEEDED, "chain:seq")
    sink._segment = sink._seq = M - 2
    error = error_of(sink.rotate_epoch, ProjectionEpoch.unlinked())
    assert (error.code, error.path) == (StorageErrorCode.ENTRY_LIMIT_EXCEEDED, "chain:seq")


def test_t_cap_5b_rotation_at_m_minus_4_creates_the_segment(fs):
    synthetic_chain(fs, s0=M - 6, g0=5, n=0)
    sink = resume(FIXED_ID, limits=SMALL)  # open in segment 1 at seq M - 5
    sink.append(validated())  # s = M - 4, k = 1
    receipt = sink.append(validated())
    assert receipt.stored and receipt.segment == 2 and receipt.seq == M - 1
    sink.close()


def test_t_cap_7_resume_capacity(fs):
    for g0, ok in ((M - 2, True), (M - 1, False), (M, False)):
        fs.root.clear()
        synthetic_chain(fs, s0=10, g0=g0)
        before = fs.snapshot()
        if ok:
            sink = resume(FIXED_ID)
            assert sink._generation == M - 1
            no_write_rejection(fs, sink, rejected_append(sink, validated()), StorageErrorCode.ENTRY_LIMIT_EXCEEDED,
                               "chain:generation")
            clean_close_at(fs, sink, seq=12, generation=M)
            fs.calls.clear()
            error = error_of(resume, FIXED_ID)  # terminally full chain
            assert (error.code, error.path) == (StorageErrorCode.ENTRY_LIMIT_EXCEEDED, "anchor:generation")
        else:
            fs.calls.clear()
            error = error_of(resume, FIXED_ID)
            assert (error.code, error.path) == (StorageErrorCode.ENTRY_LIMIT_EXCEEDED, "anchor:generation")
            assert fs.snapshot() == before and fs.writes_after(0) == [] and fs.calls[-1] == "release"
    for s0, ok in ((M - 2, True), (M - 1, False)):
        fs.root.clear()
        fs.calls.clear()
        synthetic_chain(fs, s0=s0, g0=5)
        if ok:
            resume(FIXED_ID).close()
        else:
            error = error_of(resume, FIXED_ID)
            assert (error.code, error.path) == (StorageErrorCode.ENTRY_LIMIT_EXCEEDED, "chain:seq")
            assert fs.writes_after(0) == []


@pytest.mark.parametrize("reserve", [jsonl.DIRECT_RESERVE, jsonl.SIZE_ROTATION_RESERVE, jsonl.KEY_ROTATION_RESERVE,
                                     jsonl.RESUME_RESERVE])
def test_t_cap_8a_capacity_table_on_c1_valid_inputs(reserve):
    for x in (0, M - reserve - 1, M - reserve, M - reserve + 1, M):
        expected = None if x + reserve <= M else "chain:seq"
        assert jsonl._capacity_problem(x, 1, 0, reserve, new_segment=True) == expected
        expected = None if x + reserve <= M else "chain:generation"
        assert jsonl._capacity_problem(0, x, 0, reserve, new_segment=True) == expected
    assert jsonl._capacity_problem(M, M, 0, reserve, new_segment=True) == "chain:seq"  # fixed order
    assert (reserve, jsonl.DIRECT_RESERVE, jsonl.SIZE_ROTATION_RESERVE, jsonl.KEY_ROTATION_RESERVE,
            jsonl.RESUME_RESERVE)[1:] == (2, 4, 3, 2)


def test_t_cap_8b_w1_guard_seals_before_any_write(fs):
    sink = new_sink(fs)
    line = build_segment_close(position=ChainPosition(sink.chain_id, 0, 1, sink._prev_digest), chain_key=chain_key(),
                               record_count=2, reason=CloseReason.SHUTDOWN)
    sink._generation = M  # W-STATE: P6 bypassed by calling the internal commit directly
    start = len(fs.calls)
    error = error_of(sink._commit, line)
    assert (error.code, error.path) == (StorageErrorCode.INTERNAL_INVARIANT, "capacity:w1")
    assert sink.state is SinkState.SEALED and fs.writes_after(start) == []
    sink.close()


def test_t_cap_9_checkpoint_near_max_and_close_after_each_rejection(fs):
    synthetic_chain(fs, s0=10, g0=M - 3)
    sink = resume(FIXED_ID)
    sink.append(validated())  # g = M - 1
    no_write_rejection(fs, sink, rejected_call(sink.checkpoint), StorageErrorCode.ENTRY_LIMIT_EXCEEDED,
                       "chain:generation")
    clean_close_at(fs, sink, seq=13, generation=M)


# === 11. verify_chain_named (D-C3-3), portable ==========================================================================


def test_verify_chain_named_refuses_windows_and_incapable_posix_before_any_os_call(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("os call")

    monkeypatch.setattr(sp.os, "stat", forbidden)
    monkeypatch.setattr(sp.os, "fstat", forbidden)
    root = AuditDirectory(_kind="nt", _fd=None, _path="C:\\a", _identities=())
    chain = ChainDirectory(_kind="nt", _fd=None, _path="C:\\a\\chain-" + FIXED_ID, _identities=())
    error = error_of(root.verify_chain_named, chain)
    assert (error.code, error.path) == (StorageErrorCode.UNSUPPORTED_PLATFORM, "chain:verify-platform")
    posix_root = AuditDirectory(_kind="posix", _fd=None, _path="/a", _identities=())
    assert error_of(posix_root.verify_chain_named, chain).code is StorageErrorCode.UNSUPPORTED_PLATFORM


def test_verify_chain_named_argument_and_state_checks():
    root = AuditDirectory(_kind="posix", _fd=None, _path="/a", _identities=())
    assert error_of(root.verify_chain_named, object()).path == "chain:type"
    chain = ChainDirectory(_kind="posix", _fd=None, _path="/a/chain-" + FIXED_ID, _identities=())
    chain.close()
    assert error_of(root.verify_chain_named, chain).path == "directory:closed"
    root.close()
    assert error_of(root.verify_chain_named, chain).code is StorageErrorCode.STORAGE_UNAVAILABLE


def test_verify_chain_named_is_read_only_by_construction():
    tree = ast.parse(inspect.getsource(AuditDirectory.verify_chain_named).strip())
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called.add(ast.unparse(node.func))
    assert called <= {"self._require_open", "type", "_fail", "chain._require_open", "check_chain_directory_name",
                      "chain._path.rsplit", "os.fstat", "_named_identity", "stat.S_ISDIR", "_identity"}, called
    assert not any(isinstance(n, ast.Attribute) and n.attr.startswith("O_") for n in ast.walk(tree))


def test_verify_chain_named_bad_name_is_an_invariant(monkeypatch):
    if not IS_POSIX_LOCK:
        monkeypatch.setattr(sp.os, "supports_dir_fd", {sp.os.stat})
        monkeypatch.setattr(sp.os, "supports_follow_symlinks", {sp.os.stat})
    root = AuditDirectory(_kind="posix", _fd=None, _path="/a", _identities=())
    chain = ChainDirectory(_kind="posix", _fd=None, _path="/a/not-a-chain", _identities=())
    error = error_of(root.verify_chain_named, chain)
    assert (error.code, error.path) == (StorageErrorCode.INTERNAL_INVARIANT, "chain:name")


# === 11b. C3-H2: Gemini H1 review findings L-1, L-3 (L-2 is covered by the platform tests above and mutants) ======


def test_l1_full_chain_checkpoint_is_refused_without_reading_the_clock(fs):
    """L-1: the direct-path capacity refusal is decided before the clock callable is invoked."""
    synthetic_chain(fs, s0=10, g0=M - 3)
    clock = Clock()
    sink = resume(FIXED_ID, clock=clock)
    sink.append(validated())  # g = M - 1: only the reserved SHUTDOWN close remains
    reads = clock.calls
    no_write_rejection(fs, sink, rejected_call(sink.checkpoint), StorageErrorCode.ENTRY_LIMIT_EXCEEDED,
                       "chain:generation")
    assert clock.calls == reads
    clean_close_at(fs, sink, seq=13, generation=M)


def test_l1_rotation_path_checkpoint_is_refused_without_reading_the_clock(fs):
    synthetic_chain(fs, s0=10, g0=M - 5)
    clock = Clock()
    sink = resume(FIXED_ID, limits=SMALL, clock=clock)
    sink.append(validated())  # g = M - 3 and the segment is full: a checkpoint must rotate (+ 4)
    reads = clock.calls
    no_write_rejection(fs, sink, rejected_call(sink.checkpoint), StorageErrorCode.ENTRY_LIMIT_EXCEEDED,
                       "chain:generation")
    assert clock.calls == reads


def test_l1_checkpoint_with_capacity_still_reads_the_clock_once(fs):
    clock = Clock()
    sink = new_sink(fs, clock=clock)
    reads = clock.calls
    sink.checkpoint()
    assert clock.calls == reads + 1
    sink.close()


@pytest.mark.parametrize("kwargs, label", [
    ({"verify_chain_keys": [chain_key()]}, "verify_chain_keys"),
    ({"verify_chain_keys": {chain_key().key_id: auth_key()}}, "verify_chain_keys"),
    ({"verify_chain_keys": {"0" * 32: chain_key()}}, "verify_chain_keys"),
    ({"verify_chain_keys": {chain_key().key_id: "key"}}, "verify_chain_keys"),
    ({"verify_auth_keys": (auth_key(),)}, "verify_auth_keys"),
    ({"verify_auth_keys": {auth_key().key_id: chain_key()}}, "verify_auth_keys"),
    ({"verify_auth_keys": {"0" * 32: auth_key()}}, "verify_auth_keys"),
])
def test_l3_1_invalid_verification_keyrings_refused_before_any_io(fs, kwargs, label):
    chain_id = closed_chain(fs)
    before = fs.snapshot()
    error = error_of(resume, chain_id, verify_on_resume=True, **kwargs)
    assert (error.code, error.path) == (StorageErrorCode.KEYRING_INVALID, label)
    assert fs.calls == [] and fs.snapshot() == before


def test_l3_2_missing_trailing_newline_in_an_earlier_segment_refused_by_verified_resume(fs):
    chain_id = closed_chain(fs)
    resume(chain_id).close()  # seg-1 now holds the clean tail; seg-0 is an earlier segment
    fs.calls.clear()
    segment = fs.directory(chain_id).entries["seg-0.jsonl"]
    segment.data = segment.data[:-1]  # drop the final newline of seg-0 only
    before = fs.snapshot()
    error = error_of(resume, chain_id, verify_on_resume=True)
    assert (error.code, error.path) == (StorageErrorCode.RECOVERY_REQUIRED, "verify:segment")
    assert_no_write(fs, 0, before)
    assert fs.calls[-1] == "release"


def test_l3_2_missing_trailing_newline_in_the_last_segment_refused_at_the_tail(fs):
    chain_id = closed_chain(fs)
    segment = fs.directory(chain_id).entries["seg-0.jsonl"]
    segment.data = segment.data[:-1]
    before = fs.snapshot()
    for verify in (True, False):
        fs.calls.clear()
        error = error_of(resume, chain_id, verify_on_resume=verify)
        assert (error.code, error.path) == (StorageErrorCode.RECOVERY_REQUIRED, "resume:tail")
        assert_no_write(fs, 0, before)


ROTATIONS = {"epoch": lambda s: s.rotate_epoch(ProjectionEpoch.unlinked()),
             "auth": lambda s: s.rotate_auth_key(auth2()),
             "chain": lambda s: s.rotate_chain_key(chain_key(CHAIN2_MATERIAL))}


@pytest.mark.parametrize("rotate", sorted(ROTATIONS))
def test_l3_3_operator_rotation_at_the_exact_byte_admission_limit(fs, rotate):
    """The segment is filled so that size + CLOSE_RESERVE == segment_max_bytes: the rotation close still fits."""
    k, size_after_k, _ = measured_prefix(fs)
    sink = new_sink(fs, limits=SinkLimits(segment_max_bytes=size_after_k + CLOSE_RESERVE))
    for _ in range(k):
        assert sink.append(validated()).segment == 0
    assert sink._seg.size + CLOSE_RESERVE == sink._limits.segment_max_bytes  # exactly at the admission limit
    ROTATIONS[rotate](sink)
    close = parse_record(fs.lines(sink.chain_id)[k + 1])
    assert close.kind is RecordKind.SEGMENT_CLOSE and close.segment == 0 and sink._segment == 1
    assert len(fs.segment(sink.chain_id, 0)) <= sink._limits.segment_max_bytes
    sink.close()
    assert_valid(fs, sink.chain_id, [chain_key(), chain_key(CHAIN2_MATERIAL)], [auth_key(), auth2()])


@pytest.mark.parametrize("rotate", sorted(ROTATIONS))
def test_l3_3_operator_rotation_at_the_exact_record_admission_limit(fs, rotate):
    sink = new_sink(fs, limits=SinkLimits(segment_max_bytes=MIN_SEGMENT_BYTES, segment_max_records=4))
    sink.append(validated())
    sink.append(validated())  # records_in_segment = 3: only the close (record 4) may follow
    assert sink._records_in_segment + 1 == sink._limits.segment_max_records
    ROTATIONS[rotate](sink)
    close = parse_record(fs.lines(sink.chain_id)[3])
    assert close.kind is RecordKind.SEGMENT_CLOSE and close.body["record_count"] == 4
    sink.close()
    assert_valid(fs, sink.chain_id, [chain_key(), chain_key(CHAIN2_MATERIAL)], [auth_key(), auth2()])


ENTRY_OPERATIONS = {"append": lambda s: s.append(validated()), "checkpoint": lambda s: s.checkpoint(),
                    "close": lambda s: s.close(), **ROTATIONS}


@pytest.mark.parametrize("operation", sorted(ENTRY_OPERATIONS))
def test_entry_checks_come_first(fs, operation):
    """A-11 rows A, RO/K, CL: L, D and S run before anything else the operation does (pins the order)."""
    sink = new_sink(fs)
    start = len(fs.calls)
    ENTRY_OPERATIONS[operation](sink)
    assert fs.calls[start:start + 3] == ["verify_held", "verify_chain_named", "verify_name"]
    with contextlib.suppress(StorageError):
        sink.close()


def test_resume_checks_precede_listing_and_reads(fs):
    """A-11 rows R and R2: L and D right after the lock, and again before the anchor and tail reads."""
    chain_id = closed_chain(fs)
    resume(chain_id).close()
    calls = fs.calls
    first = calls.index("acquire_writer_lock")
    assert calls[first + 1:first + 6] == ["verify_held", "verify_chain_named", "chain.list_names",
                                          "verify_held", "verify_chain_named"]
    assert calls[first + 6] == "open_read"


# === 12. Native POSIX tier (skipped where flock/dir_fd are unavailable) =================================================


@pytest.fixture
def native_root():
    import shutil
    import tempfile

    home = os.path.realpath(os.path.expanduser("~"))
    base = tempfile.mkdtemp(prefix="rig-c3-", dir=home)
    os.chmod(base, 0o700)
    yield base
    for directory, _, _ in os.walk(base):
        with contextlib.suppress(OSError):
            os.chmod(directory, 0o700)
    shutil.rmtree(base, ignore_errors=True)
    sp._HELD_LOCKS.clear()


def native_lines(root, chain_id):
    directory = Path(root) / ("chain-" + chain_id)
    numbers = sorted(int(p.name[4:-6]) for p in directory.glob("seg-*.jsonl"))
    lines = []
    for number in numbers:
        data = (directory / f"seg-{number}.jsonl").read_bytes()
        lines.extend(piece + b"\n" for piece in data.split(b"\n")[:-1])
    return lines


@posix_only
def test_native_genesis_append_rotation_close_resume_verify(native_root):
    with AuditDirectory.open(native_root) as audit:
        sink = LocalJsonlSink.create_chain(audit, keys=KEYS, epoch=KEYED, limits=SMALL, clock=Clock())
        chain_id = sink.chain_id
        for _ in range(3):
            assert sink.append(validated()).stored
        sink.checkpoint()
        sink.close()
        directory = Path(native_root) / ("chain-" + chain_id)
        assert oct(directory.stat().st_mode & 0o777) == "0o700"
        resumed = LocalJsonlSink.resume_chain(audit, chain_id, keys=KEYS, epoch=KEYED, limits=SMALL, clock=Clock(),
                                              verify_on_resume=True)
        resumed.append(validated())
        resumed.close()
    report = verify_chain(native_lines(native_root, chain_id), chain_keys={chain_key().key_id: chain_key()},
                          auth_keys={auth_key().key_id: auth_key()}, expected_chain_id=chain_id)
    assert report.status is ChainStatus.CHAIN_VALID


@posix_only
@pytest.mark.parametrize("mode", [0o750, 0o707])
def test_native_adopted_directory_with_open_permissions_is_refused_at_g3(native_root, monkeypatch, mode):
    """A4: the race-adopted directory must pass C2-C's private-directory checks (unchanged C2-C)."""
    monkeypatch.setattr(jsonl, "new_chain_id", lambda: FIXED_ID)
    path = os.path.join(native_root, "chain-" + FIXED_ID)
    os.mkdir(path)
    os.chmod(path, mode)
    with AuditDirectory.open(native_root) as audit:
        monkeypatch.setattr(AuditDirectory, "list_names", lambda self, **_: sp.ListResult((), 0))  # G2 saw nothing
        error = error_of(LocalJsonlSink.create_chain, audit, keys=KEYS, epoch=KEYED, clock=Clock())
    assert error.code is StorageErrorCode.UNSAFE_PERMISSIONS and os.listdir(path) == []


@posix_only
def test_native_created_directory_is_private_regardless_of_umask(native_root):
    previous = os.umask(0)
    try:
        with AuditDirectory.open(native_root) as audit:
            sink = LocalJsonlSink.create_chain(audit, keys=KEYS, epoch=KEYED, clock=Clock())
            path = os.path.join(native_root, "chain-" + sink.chain_id)
            assert os.stat(path).st_mode & 0o777 == 0o700
            sink.close()
    finally:
        os.umask(previous)


@posix_only
def test_native_second_writer_is_locked_out(native_root):
    with AuditDirectory.open(native_root) as audit:
        sink = LocalJsonlSink.create_chain(audit, keys=KEYS, epoch=KEYED, clock=Clock())
        error = error_of(LocalJsonlSink.resume_chain, audit, sink.chain_id, keys=KEYS, epoch=KEYED)
        assert error.code is StorageErrorCode.LOCKED
        sink.close()


@posix_only
def test_native_chain_directory_substitution_seals_and_writes_nothing_new(native_root):
    """Rename-and-recreate substitution: the append is refused BEFORE any audit-record write.

    C3-H2-F1 (L-H2-1): besides the refusal, the empty replacement and the seal, the ORIGINAL chain directory
    (renamed away, still held by the writer) must not gain a byte or a file. A later layer (row X) would also
    raise ``chain:replaced`` after a record had already been written; only this snapshot reveals that.
    """
    with AuditDirectory.open(native_root) as audit:
        sink = LocalJsonlSink.create_chain(audit, keys=KEYS, epoch=KEYED, clock=Clock())
        name = "chain-" + sink.chain_id
        original, moved = os.path.join(native_root, name), os.path.join(native_root, "moved")
        before = directory_bytes(original)  # every entry name and its complete contents
        assert any(n.startswith("seg-") for n in before) and ANCHOR_NAME in before
        os.rename(original, moved)
        os.mkdir(original, 0o700)
        error = error_of(sink.append, validated())
        assert (error.code, error.path) == (StorageErrorCode.UNSAFE_PATH, "chain:replaced")
        assert os.listdir(original) == [] and sink.state is SinkState.SEALED
        assert directory_bytes(moved) == before  # no record, anchor update or new file reached the held chain
        assert sink.append(validated()).code is StorageErrorCode.SINK_SEALED  # sealed permanently
        sink.close()
        assert directory_bytes(moved) == before and os.listdir(original) == []


@posix_only
@pytest.mark.parametrize("swap", ["missing", "dir", "symlink", "file"])
def test_native_verify_chain_named_detects_substitution(native_root, swap):
    with AuditDirectory.open(native_root) as audit:
        name = "chain-" + FIXED_ID
        chain = audit.open_chain(name, create=True)
        audit.verify_chain_named(chain)
        audit.verify_chain_named(chain)
        path = os.path.join(native_root, name)
        os.rename(path, os.path.join(native_root, "moved"))
        if swap == "dir":
            os.mkdir(path, 0o700)
        elif swap == "symlink":
            os.symlink(os.path.join(native_root, "moved"), path)
        elif swap == "file":
            Path(path).write_bytes(b"x")
        error = error_of(audit.verify_chain_named, chain)
        assert (error.code, error.path) == (
            StorageErrorCode.UNSAFE_PATH, "chain:missing" if swap == "missing" else "chain:replaced")
        chain.close()


@posix_only
def test_native_verify_chain_named_root_level_move_is_the_documented_residual(native_root, tmp_path):
    with AuditDirectory.open(native_root) as audit:
        chain = audit.open_chain("chain-" + FIXED_ID, create=True)
        moved = native_root + "-moved"
        os.rename(native_root, moved)
        try:
            audit.verify_chain_named(chain)  # R-D1: still passes (relative to the held root)
        finally:
            os.rename(moved, native_root)
            chain.close()


@posix_only
def test_native_forked_child_cannot_write(native_root):
    with AuditDirectory.open(native_root) as audit:
        sink = LocalJsonlSink.create_chain(audit, keys=KEYS, epoch=KEYED, clock=Clock())
        event = validated()
        pid = os.fork()
        if pid == 0:  # child: the lock is inherited, never owned
            code = 1
            try:
                sink.append(event)
            except StorageError as error:
                code = 0 if error.code is StorageErrorCode.LOCK_INVALID else 2
            except BaseException:
                code = 3
            os._exit(code)
        _, status = os.waitpid(pid, 0)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        assert sink.append(validated()).stored  # the parent still owns the lock
        sink.close()


@posix_only
def test_native_verify_chain_named_rejects_a_chain_from_a_foreign_root(native_root):
    """L-3.4 (spec test 8): a ChainDirectory opened from another root with the same chain id is refused;
    the same root opened twice is accepted. Read-only: neither directory changes."""
    other = native_root + "-foreign"
    os.mkdir(other, 0o700)
    try:
        name = "chain-" + FIXED_ID
        with AuditDirectory.open(native_root) as audit, AuditDirectory.open(other) as foreign:
            mine = audit.open_chain(name, create=True)
            theirs = foreign.open_chain(name, create=True)
            before = (sorted(os.listdir(native_root)), sorted(os.listdir(other)))
            error = error_of(audit.verify_chain_named, theirs)
            assert (error.code, error.path) == (StorageErrorCode.UNSAFE_PATH, "chain:replaced")
            error = error_of(foreign.verify_chain_named, mine)
            assert (error.code, error.path) == (StorageErrorCode.UNSAFE_PATH, "chain:replaced")
            with AuditDirectory.open(native_root) as again:
                again.verify_chain_named(mine)  # the same root, opened twice: correct
            assert (sorted(os.listdir(native_root)), sorted(os.listdir(other))) == before
            mine.close()
            theirs.close()
    finally:
        import shutil

        shutil.rmtree(other, ignore_errors=True)


@posix_only
def test_native_verify_chain_named_fails_closed_on_errors(native_root):
    """Spec test 10 (portion runnable as any user): ENOTDIR-like replacement and a vanished name fail closed."""
    with AuditDirectory.open(native_root) as audit:
        chain = audit.open_chain("chain-" + FIXED_ID, create=True)
        path = os.path.join(native_root, "chain-" + FIXED_ID)
        os.rename(path, path + ".x")
        os.mkfifo(path, 0o600)
        error = error_of(audit.verify_chain_named, chain)
        assert (error.code, error.path) == (StorageErrorCode.UNSAFE_PATH, "chain:replaced")
        os.unlink(path)
        os.rename(path + ".x", path)
        audit.verify_chain_named(chain)
        chain.close()


@posix_only
def test_native_verify_chain_named_other_os_errors_fail_closed(native_root):
    """Spec test 10 / V5: an OSError other than ENOENT (here EBADF on the root descriptor) is chain:verify."""
    with AuditDirectory.open(native_root) as audit:
        chain = audit.open_chain("chain-" + FIXED_ID, create=True)
        saved = audit._fd
        spare = os.dup(saved)
        os.close(saved)
        try:
            error = error_of(audit.verify_chain_named, chain)
            assert (error.code, error.path) == (StorageErrorCode.UNSAFE_PATH, "chain:verify")
        finally:
            os.dup2(spare, saved)
            os.close(spare)
        audit.verify_chain_named(chain)
        chain.close()


# --- Native crash matrix (C3-H2; test-only harness: no crash hook exists in any production module) -----------------

CRASH_CHILD = r"""
import os, signal, sys
sys.path.insert(0, sys.argv[1])
import test_audit_c3_writer as t
from rig_sentinel.audit import safepath as sp
from rig_sentinel.audit.jsonl import LocalJsonlSink

root, scenario, target, nth, when = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), sys.argv[6]
armed, seen = [False], [0]

def wrap(cls, name, label):
    real = getattr(cls, name)
    def wrapper(self, *args, **kwargs):
        hit = armed[0] and label == target
        if hit:
            seen[0] += 1
            if seen[0] == nth and when == "before":
                os.kill(os.getpid(), signal.SIGKILL)
        result = real(self, *args, **kwargs)
        if hit and seen[0] == nth and when == "after":
            os.kill(os.getpid(), signal.SIGKILL)
        return result
    setattr(cls, name, wrapper)

wrap(sp.SafeAppendFile, "append", "append")
wrap(sp.SafeAppendFile, "sync", "seg.sync")
wrap(sp.ChainDirectory, "replace_atomically", "replace")
wrap(sp.ChainDirectory, "create_exclusive", "create")
wrap(sp.ChainDirectory, "sync", "dirsync")
with sp.AuditDirectory.open(root) as audit:
    limits = t.SMALL if scenario == "size" else None
    sink = LocalJsonlSink.create_chain(audit, keys=t.KEYS, epoch=t.KEYED, limits=limits, clock=t.Clock())
    print(sink.chain_id, flush=True)
    sink.append(t.validated())
    armed[0] = True
    if scenario in ("append", "size"):
        sink.append(t.validated())
    else:
        t.ROTATIONS[scenario](sink)
    print("done", flush=True)
    os._exit(0)
"""
CRASH_SCENARIOS = ("append", "size", "epoch", "auth", "chain")
CRASH_TARGETS = ("append", "seg.sync", "replace", "create", "dirsync")
#: Crash points that leave a clean SIZE close as the anchored tail; C3 may resume only from these.
CLEAN_CRASH_POINTS = {("size", "replace", "after", 1), ("size", "create", "before", 1)}


def directory_bytes(path):
    return {name: Path(path, name).read_bytes() for name in sorted(os.listdir(path))}


def keys_named_by_anchor(chain_dir):
    import json

    anchor = json.loads(Path(chain_dir, ANCHOR_NAME).read_bytes())
    auth = {k.key_id: k for k in (auth_key(), auth2())}[anchor["auth_key_id"]]
    chain = {k.key_id: k for k in (chain_key(), chain_key(CHAIN2_MATERIAL))}[anchor["chain_key_id"]]
    return KeySet(auth=auth, chain=chain, ref=None)


@posix_only
@pytest.mark.parametrize("scenario", CRASH_SCENARIOS)
def test_native_crash_matrix_sigkill_at_every_write_boundary(native_root, scenario):
    """SIGKILL immediately before and after every write primitive of the operation; then C3 resume must refuse
    with RECOVERY_REQUIRED without changing a byte, except from the two clean SIZE-close states."""
    tests_dir = str(Path(__file__).parent)
    env = {k: v for k, v in os.environ.items() if k not in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONSTARTUP",
                                                                "PYTHONINSPECT")}
    env["PYTHONPATH"] = os.pathsep.join([str(Path(jsonl.__file__).parents[2]), tests_dir])
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    outcomes = {}
    for target in CRASH_TARGETS:
        for when in ("before", "after"):
            for nth in itertools.count(1):
                child = subprocess.run([sys.executable, "-c", CRASH_CHILD, tests_dir, native_root, scenario, target,
                                        str(nth), when], capture_output=True, text=True, env=env, timeout=120,
                                       shell=False)
                lines = child.stdout.split()
                if child.returncode == 0:
                    assert lines[-1] == "done"
                    break
                assert child.returncode == -9, child.stderr[-2000:]
                chain_id = lines[0]
                chain_dir = os.path.join(native_root, "chain-" + chain_id)
                before = directory_bytes(chain_dir)
                point = (scenario, target, when, nth)
                try:
                    with AuditDirectory.open(native_root) as audit:
                        sink = LocalJsonlSink.resume_chain(audit, chain_id, keys=keys_named_by_anchor(chain_dir),
                                                           epoch=KEYED, limits=SMALL, clock=Clock())
                        sink.close()
                    outcomes[point] = "resumed"
                    assert point in CLEAN_CRASH_POINTS, point
                    report = verify_chain(native_lines(native_root, chain_id),
                                          chain_keys={chain_key().key_id: chain_key()},
                                          auth_keys={auth_key().key_id: auth_key()}, expected_chain_id=chain_id)
                    assert report.status is ChainStatus.CHAIN_VALID, (point, report.issues)
                except StorageError as error:
                    outcomes[point] = error.code.value
                    assert point not in CLEAN_CRASH_POINTS, point
                    assert error.code is StorageErrorCode.RECOVERY_REQUIRED, (point, error.code, error.path)
                    assert directory_bytes(chain_dir) == before, point  # no repair, truncation or deletion
    assert outcomes and set(outcomes.values()) <= {"resumed", "recovery_required"}
    assert any(target == "replace" for _, target, _, _ in outcomes)


@posix_only
def test_native_no_descriptor_leak_in_verify(native_root):
    if not os.path.isdir("/proc/self/fd"):
        pytest.skip("Linux-only descriptor count")
    with AuditDirectory.open(native_root) as audit:
        chain = audit.open_chain("chain-" + FIXED_ID, create=True)
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(1000):
            audit.verify_chain_named(chain)
        assert len(os.listdir("/proc/self/fd")) == before
        chain.close()


def test_isolation_subprocess_import_of_jsonl_touches_no_filesystem():
    code = ("import builtins, io\n"
            "def no(*a, **k): raise AssertionError('io')\n"
            "import rig_sentinel.audit.jsonl as j\n"
            "builtins.open = no; io.open = no\n"
            "j.SinkLimits(); print('ok')\n")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, [str(Path(jsonl.__file__).parents[2]),
                                                                       os.environ.get("PYTHONPATH")])))
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=60)
    assert out.stdout.strip() == "ok", out.stderr
