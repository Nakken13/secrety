"""Shared fixtures: throw-away Git repositories built with the ``git`` CLI."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

# The fixture's own git calls ignore the developer's global and system
# config (signing, hooks, autocrlf...), so commits are identical everywhere.
_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Test Author",
    "GIT_AUTHOR_EMAIL": "author@example.com",
    "GIT_COMMITTER_NAME": "Test Author",
    "GIT_COMMITTER_EMAIL": "author@example.com",
    # Config for the fixture's own commands, without a `git config` spawn each.
    "GIT_CONFIG_COUNT": "2",
    "GIT_CONFIG_KEY_0": "core.autocrlf",
    "GIT_CONFIG_VALUE_0": "false",
    "GIT_CONFIG_KEY_1": "commit.gpgsign",
    "GIT_CONFIG_VALUE_1": "false",
}
BASE_DATE = "2024-01-{day:02d}T12:00:00+00:00"


@dataclass
class GitRepo:
    """A temporary repository with helpers to write files and commit them."""

    path: Path
    _day: int = field(default=0, init=False)

    def git(self, *args: str) -> str:
        """Run ``git args`` in the repository and return its stdout."""
        env = {**os.environ, **_GIT_ENV}
        if self._day:
            env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = BASE_DATE.format(day=self._day)
        result = subprocess.run(
            ["git", *args], cwd=self.path, env=env, check=True, capture_output=True, text=True
        )
        return result.stdout.strip()

    def write(self, name: str, content: str | bytes) -> None:
        """Write ``content`` to ``name`` (LF line endings kept as is)."""
        target = self.path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode("utf-8") if isinstance(content, str) else content
        target.write_bytes(data)

    def commit(self, message: str, **files: str | bytes) -> str:
        """Write ``files`` (``name=content``), commit everything, return the SHA.

        Each commit is dated one day after the previous one, from 2024-01-01.
        """
        for name, content in files.items():
            self.write(name.replace("__", "/"), content)
        self._day += 1
        self.git("add", "--all")
        self.git("commit", "--quiet", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")


@pytest.fixture
def git_repo(tmp_path: Path) -> Iterator[GitRepo]:
    """An empty repository on branch ``main``."""
    path = tmp_path / "repo"
    path.mkdir()
    repo = GitRepo(path)
    repo.git("init", "--quiet", "--initial-branch=main")
    yield repo
