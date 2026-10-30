from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


DEFAULT_IGNORED_DIRS = {
    ".git",
    ".venv",
    ".venv-1",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".next",
    "coverage",
    "vendor",
    "tests",
     "test",
    "__tests__",
    "fixtures",
    "examples",
}

SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".md",
    ".env",
    ".txt",
    ".ini",
    ".cfg",
    ".sh",
    ".ps1",
}

SUPPORTED_FILENAMES = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env.example",
    ".env.sample",
}


@dataclass(frozen=True)
class RepositoryFile:
    path: Path
    relative_path: Path
    size: int


class RepositoryWalker:
    def __init__(
        self,
        root: Path,
        ignored_dirs: set[str] | None = None,
        max_file_size: int = 1_000_000,
    ) -> None:
        self.root = root.resolve()
        self.ignored_dirs = ignored_dirs or DEFAULT_IGNORED_DIRS
        self.max_file_size = max_file_size

    def should_ignore_path(self, path: Path) -> bool:
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            return True

        return any(part in self.ignored_dirs for part in relative.parts)

    def is_supported_file(self, path: Path) -> bool:
        if path.name in SUPPORTED_FILENAMES:
            return True

        return path.suffix.lower() in SUPPORTED_EXTENSIONS

    def walk(self) -> Iterator[RepositoryFile]:
        if not self.root.exists():
            raise FileNotFoundError(f"Repository path does not exist: {self.root}")

        if not self.root.is_dir():
            raise NotADirectoryError(f"Repository path is not a directory: {self.root}")

        for path in self.root.rglob("*"):
            if not path.is_file():
                continue

            if self.should_ignore_path(path):
                continue

            if not self.is_supported_file(path):
                continue

            try:
                size = path.stat().st_size
            except OSError:
                continue

            if size > self.max_file_size:
                continue

            yield RepositoryFile(
                path=path,
                relative_path=path.relative_to(self.root),
                size=size,
            )