from pathlib import Path

from rig_sentinel.repository import RepositoryWalker


def test_repository_walker_ignores_dependencies(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("print('hello')", encoding="utf-8")

    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    dependency = node_modules / "dependency.js"
    dependency.write_text("console.log('ignore me')", encoding="utf-8")

    walker = RepositoryWalker(tmp_path)

    files = list(walker.walk())
    relative_paths = {str(item.relative_path) for item in files}

    assert "app.py" in relative_paths
    assert str(Path("node_modules") / "dependency.js") not in relative_paths


def test_repository_walker_ignores_virtualenv(tmp_path: Path) -> None:
    source = tmp_path / "main.py"
    source.write_text("print('hello')", encoding="utf-8")

    venv = tmp_path / ".venv"
    venv.mkdir()
    dependency = venv / "package.py"
    dependency.write_text("ignore = True", encoding="utf-8")

    walker = RepositoryWalker(tmp_path)

    files = list(walker.walk())
    relative_paths = {str(item.relative_path) for item in files}

    assert "main.py" in relative_paths
    assert str(Path(".venv") / "package.py") not in relative_paths


def test_repository_walker_ignores_unsupported_files(tmp_path: Path) -> None:
    image = tmp_path / "image.png"
    image.write_bytes(b"\x89PNG")

    source = tmp_path / "main.py"
    source.write_text("print('hello')", encoding="utf-8")

    walker = RepositoryWalker(tmp_path)

    files = list(walker.walk())
    relative_paths = {str(item.relative_path) for item in files}

    assert "main.py" in relative_paths
    assert "image.png" not in relative_paths


def test_repository_walker_supports_dockerfile(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.13", encoding="utf-8")

    walker = RepositoryWalker(tmp_path)

    files = list(walker.walk())
    relative_paths = {str(item.relative_path) for item in files}

    assert "Dockerfile" in relative_paths

def test_repository_walker_ignores_tests_directory(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from openai import OpenAI",
        encoding="utf-8",
    )

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()

    test_file = tests_dir / "test_agent.py"
    test_file.write_text(
        "from anthropic import Anthropic",
        encoding="utf-8",
    )

    walker = RepositoryWalker(tmp_path)

    files = list(walker.walk())

    relative_paths = {
        str(item.relative_path)
        for item in files
    }

    assert "app.py" in relative_paths

    assert str(
        Path("tests") / "test_agent.py"
    ) not in relative_paths