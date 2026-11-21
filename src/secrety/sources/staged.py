"""Read the content of the Git index (what ``git commit`` is about to record).

Only the staged blobs are scanned, never the worktree: an unstaged edit that
hides a secret on disk must not hide it from a pre-commit check. ``GIT_INDEX_FILE``
is left alone: during ``git commit -a`` or ``git commit <paths>`` git points it at
the temporary index that holds what will really be committed.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from secrety.sources.base import ScanStats, SourceFile
from secrety.sources.filesystem import (
    BINARY_SNIFF_SIZE,
    DEFAULT_MAX_FILE_SIZE,
    decode,
    is_binary,
)

_SYMLINK_MODE = "120000"
_SUBMODULE_MODE = "160000"


def _git(cwd: Path, *args: str) -> bytes:
    """Run ``git args`` in ``cwd`` and return its stdout.

    Raises:
        ValueError: ``git`` is missing or the command failed.
    """
    try:
        result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False)
    except OSError as exc:
        raise ValueError(f"cannot run git: {exc}") from exc
    if result.returncode:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(message or f"git {args[0]} failed")
    return result.stdout


def repo_root(path: Path) -> Path:
    """Top-level folder of the repository that contains ``path``.

    Raises:
        ValueError: ``path`` is not inside a Git repository.
    """
    folder = path if path.is_dir() else path.parent
    try:
        out = _git(folder, "rev-parse", "--show-toplevel")
    except ValueError as exc:
        raise ValueError(f"{path} is not a Git repository ({exc})") from exc
    return Path(out.decode("utf-8", errors="replace").strip())


def staged_file_text(root: Path, name: str) -> str | None:
    """Content of ``name`` as staged in the index, or ``None`` if it is not staged.

    Used for ``.secrety.toml``: reading it from the worktree would let an
    unstaged edit silence findings in the staged content.
    """
    try:
        return decode(_git(root, "show", f":{name}"))
    except ValueError:
        return None


@dataclass
class StagedSource:
    """Iterate over the files added or modified in the index.

    Paths are relative to the repository root with ``/`` separators, wherever
    ``path`` points inside the repository, so path allowlists match the same
    way in a pre-commit run and in a full scan. Deleted files, symlinks and
    submodules are skipped; renames are scanned under their new name.
    """

    path: Path
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    stats: ScanStats = field(default_factory=ScanStats)

    def __iter__(self) -> Iterator[SourceFile]:
        """Yield every staged text file."""
        self.stats = ScanStats()
        root = repo_root(self.path)
        raw = _git(
            root, "diff", "--cached", "--raw", "-z", "--no-renames", "--no-abbrev",
            "--diff-filter=AM",
        )  # fmt: skip
        parts = raw.split(b"\x00")
        # Records alternate: ":<modes> <shas> <status>" then the path.
        for meta, name in zip(parts[0::2], parts[1::2], strict=False):
            fields = meta.lstrip(b":").decode("ascii", errors="replace").split()
            if len(fields) < 5:
                continue
            new_mode, blob = fields[1], fields[3]
            if new_mode == _SYMLINK_MODE:
                self.stats.skipped_links += 1
                continue
            if new_mode == _SUBMODULE_MODE:
                continue
            rel = name.decode("utf-8", errors="replace")
            if file := self._read(root, blob, rel):
                yield file

    def _read(self, root: Path, blob: str, rel: str) -> SourceFile | None:
        """Return the staged blob as a :class:`SourceFile`, or ``None`` if skipped."""
        try:
            size = int(_git(root, "cat-file", "-s", blob))
            if size > self.max_file_size:
                self.stats.skipped_large += 1
                return None
            data = _git(root, "cat-file", "blob", blob)
        except ValueError:
            self.stats.unreadable += 1
            return None
        if is_binary(data[:BINARY_SNIFF_SIZE]):
            self.stats.skipped_binary += 1
            return None
        self.stats.scanned += 1
        return SourceFile(path=rel, text=decode(data))
