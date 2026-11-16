"""M2-B isolation: policy never depends on audit; audit performs no I/O."""

import ast
import builtins
import io
import pathlib
import socket
from pathlib import Path

from audit_fixtures import auth_key, builder, evaluated

import rig_sentinel.audit as audit_package
import rig_sentinel.policy as policy_package
from rig_sentinel.audit import MemorySink, keyring

AUDIT_DIR = Path(audit_package.__file__).resolve().parent
POLICY_DIR = Path(policy_package.__file__).resolve().parent
AUDIT_FILES = sorted(AUDIT_DIR.glob("*.py"))

FORBIDDEN_MODULES = {
    "os", "io", "pathlib", "shutil", "tempfile", "sqlite3", "dbm", "shelve", "pickle", "marshal",
    "socket", "ssl", "http", "urllib", "ftplib", "smtplib", "telnetlib", "webbrowser",
    "subprocess", "multiprocessing", "concurrent", "asyncio", "ctypes", "importlib", "runpy",
    "logging", "sys",
    # B2-M2-C2-B: platform I/O modules are forbidden too, except where allowlisted below.
    "fcntl", "msvcrt", "nt", "posix", "_winapi", "winreg",
}
# F11 (amended by D-C2-3/D-C2-4): the only audit module that may touch the filesystem.
IO_ALLOWED = {"safepath.py": frozenset({"os", "fcntl"})}
FORBIDDEN_CALLS = {"open", "eval", "exec", "compile", "__import__", "input", "breakpoint", "print"}
THREADING_ALLOWED = {"sinks.py"}


def _imports(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            yield node.module or ""


def test_expected_audit_modules_exist():
    names = {path.name for path in AUDIT_FILES}
    assert names == {
        "__init__.py", "builder.py", "chain.py", "errors.py", "events.py", "keys.py",
        "projection.py", "redaction.py", "sinks.py", "validation.py",
        # B2-M2-C1 (F11): pure chain modules; the I/O and call restrictions below apply unchanged.
        "bounded_json.py", "chainverify.py", "records.py", "storage_errors.py",
        # B2-M2-C2-B: key files; safepath.py is the single filesystem module.
        "keyfile.py", "safepath.py",
    }


def test_policy_package_never_imports_audit():
    for path in sorted(POLICY_DIR.glob("*.py")):
        for module in _imports(ast.parse(path.read_text(encoding="utf-8"))):
            assert not module.startswith("rig_sentinel.audit"), path.name


def test_audit_modules_import_no_io_or_network_modules():
    for path in AUDIT_FILES:
        for module in _imports(ast.parse(path.read_text(encoding="utf-8"))):
            root = module.split(".")[0]
            allowed = IO_ALLOWED.get(path.name, frozenset())
            assert root not in FORBIDDEN_MODULES or root in allowed, f"{path.name} imports {module}"
            if root == "threading":
                assert path.name in THREADING_ALLOWED, path.name
            if root == "rig_sentinel":
                assert module.startswith(("rig_sentinel.audit", "rig_sentinel.policy")), module


def test_audit_modules_make_no_dangerous_calls():
    for path in AUDIT_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in FORBIDDEN_CALLS, f"{path.name} calls {node.func.id}()"


def test_audit_source_is_ascii_without_invisible_characters():
    for path in AUDIT_FILES + sorted(Path(__file__).parent.glob("test_audit_*.py")):
        data = path.read_bytes()
        assert all(byte < 128 for byte in data), path.name
        assert not any(byte < 32 and byte not in (9, 10, 13) for byte in data), path.name


def test_build_seal_append_and_verify_perform_no_file_or_network_io(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("I/O attempted")

    request, record = evaluated()
    build = builder()
    sink = MemorySink(verify_keys=keyring([auth_key()]))
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(io, "open", forbidden)
    monkeypatch.setattr(pathlib.Path, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)

    envelope = build.build_envelope(record, request)
    receipt = sink.append(envelope)
    assert receipt.stored
    assert sink.envelopes()[0].verify(keyring([auth_key()])).value == "authentic"


def test_only_safepath_imports_filesystem_modules():
    importers = set()
    for path in AUDIT_FILES:
        for module in _imports(ast.parse(path.read_text(encoding="utf-8"))):
            if module.split(".")[0] in {"os", "fcntl", "msvcrt", "nt", "posix", "_winapi", "winreg"}:
                importers.add(path.name)
    assert importers == {"safepath.py"}
