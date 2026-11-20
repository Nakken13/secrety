"""Read the text files of a local folder."""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MAX_FILE_SIZE = 1_000_000  # bytes
BINARY_SNIFF_SIZE = 8192  # bytes; the same window Git uses
DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    }
)


@dataclass(frozen=True, slots=True)
class SourceFile:
    """One file's content, ready to be handed to detectors.

    Attributes:
        path: Path relative to the scan root, with ``/`` separators.
        text: Decoded content (invalid UTF-8 bytes replaced by U+FFFD).
    """

    path: str
    text: str


@dataclass(slots=True)
class ScanStats:
    """Counters reported at the end of a scan."""

    scanned: int = 0
    skipped_binary: int = 0
    skipped_large: int = 0


def is_binary(chunk: bytes) -> bool:
    """Return True if ``chunk`` looks binary (contains a NUL byte), like Git."""
    return b"\x00" in chunk


@dataclass
class FilesystemSource:
    """Iterate over the text files under ``root`` (a folder or a single file).

    Symbolic links are never followed, so a scan cannot escape ``root``.
    Iteration order is sorted, so results are reproducible.
    """

    root: Path
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    excluded_dirs: Iterable[str] = DEFAULT_EXCLUDED_DIRS
    stats: ScanStats = field(default_factory=ScanStats)

    def __iter__(self) -> Iterator[SourceFile]:
        """Yield every readable text file under :attr:`root`."""
        root = Path(self.root)
        if not root.exists():
            raise FileNotFoundError(root)
        if root.is_file():
            yield from self._read(root, root.name)
            return
        excluded = set(self.excluded_dirs)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Prune in place so os.walk never descends into excluded folders.
            dirnames[:] = sorted(d for d in dirnames if d not in excluded)
            for name in sorted(filenames):
                path = Path(dirpath) / name
                yield from self._read(path, path.relative_to(root).as_posix())

    def _read(self, path: Path, rel: str) -> Iterator[SourceFile]:
        """Yield ``path`` as a :class:`SourceFile` unless it must be skipped."""
        if path.is_symlink() or not path.is_file():
            return
        if path.stat().st_size > self.max_file_size:
            self.stats.skipped_large += 1
            return
        data = path.read_bytes()
        if is_binary(data[:BINARY_SNIFF_SIZE]):
            self.stats.skipped_binary += 1
            return
        self.stats.scanned += 1
        yield SourceFile(path=rel, text=data.decode("utf-8", errors="replace"))
