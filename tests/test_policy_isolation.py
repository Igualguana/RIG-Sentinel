"""The policy package must not execute tools, perform I/O during evaluation,
or depend on the scanner, CLI or any runtime adapter."""

import ast
import builtins
import io
import pathlib
from pathlib import Path

import pytest
from policy_fixtures import BASELINE_POLICY, fixed_clock, make_request

import rig_sentinel.policy as policy_package
from rig_sentinel.policy import Decision, PolicyEngine, load_policy_text

PACKAGE_DIR = Path(policy_package.__file__).resolve().parent
SOURCE_FILES = sorted(PACKAGE_DIR.glob("*.py"))
SRC_DIR = PACKAGE_DIR.parent

FORBIDDEN_MODULES = {
    "subprocess", "os", "socket", "ssl", "http", "urllib", "ftplib", "smtplib",
    "telnetlib", "importlib", "ctypes", "multiprocessing", "threading", "asyncio",
    "pickle", "marshal", "shelve", "shutil", "tempfile", "webbrowser", "runpy",
}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "open", "input", "breakpoint"}


def _is_policy_package(module):
    return module == "rig_sentinel.policy" or module.startswith("rig_sentinel.policy.")


def _imports(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            yield node.module or ""


def test_source_files_present():
    names = {path.name for path in SOURCE_FILES}
    assert {"engine.py", "model.py", "validation.py", "loader.py"} <= names


@pytest.mark.parametrize("path", SOURCE_FILES, ids=lambda p: p.name)
def test_no_execution_or_network_imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for module in _imports(tree):
        root = module.split(".")[0]
        assert root not in FORBIDDEN_MODULES, f"{path.name} imports {module}"
        if root == "rig_sentinel":
            assert _is_policy_package(module), (
                f"{path.name} depends on {module}; the engine must stay independent"
            )


@pytest.mark.parametrize("path", SOURCE_FILES, ids=lambda p: p.name)
def test_no_dynamic_code_execution(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in FORBIDDEN_CALLS, f"{path.name} calls {node.func.id}()"


def test_existing_modules_do_not_import_policy_engine():
    for path in sorted(SRC_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for module in _imports(tree):
            assert not _is_policy_package(module), (
                f"{path.name} imports the policy engine; M1 must not change the scanner or CLI"
            )


def test_evaluation_performs_no_file_io(monkeypatch):
    engine = PolicyEngine(load_policy_text(BASELINE_POLICY), clock=fixed_clock)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("file access during evaluation")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(io, "open", forbidden)
    monkeypatch.setattr(pathlib.Path, "open", forbidden)
    monkeypatch.setattr(pathlib.Path, "read_bytes", forbidden)
    monkeypatch.setattr(pathlib.Path, "read_text", forbidden)

    record = engine.evaluate(make_request())
    assert record.decision is Decision.ALLOW
    assert record.reason_code.value == "RULE_ALLOW"


def test_engine_never_loads_policies_by_itself(tmp_path, monkeypatch):
    (tmp_path / "policy.toml").write_text(BASELINE_POLICY, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    engine = PolicyEngine(None, clock=fixed_clock)
    assert engine.evaluate(make_request()).decision is Decision.DENY
    engine = PolicyEngine(str(tmp_path / "policy.toml"), clock=fixed_clock)  # type: ignore[arg-type]
    assert engine.evaluate(make_request()).decision is Decision.DENY
