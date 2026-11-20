"""Read the text files of a local folder."""

from __future__ import annotations

import codecs
import os
import stat
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from secrety.sources.base import ScanStats, SourceFile

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
_UTF16_BOMS = (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)


def is_binary(chunk: bytes) -> bool:
    """Return True if ``chunk`` looks binary (contains a NUL byte), like Git."""
    return b"\x00" in chunk


def decode(data: bytes) -> str | None:
    """Decode file bytes to text, or return ``None`` if the file is binary.

    UTF-16 files (the default of PowerShell 5.1 ``Out-File``) are full of NUL
    bytes, so their byte-order mark is checked before the binary heuristic.
    Anything else is read as UTF-8, replacing invalid bytes.
    """
    if data.startswith(_UTF16_BOMS):
        return data.decode("utf-16", errors="replace")
    if is_binary(data[:BINARY_SNIFF_SIZE]):
        return None
    return data.decode("utf-8", errors="replace")


def is_link(path: Path) -> bool:
    """Return True for symbolic links and Windows junctions / reparse points.

    ``Path.is_symlink`` and ``os.walk(followlinks=False)`` do not recognise
    NTFS junctions on Python 3.11, so the reparse-point attribute is checked
    too.
    """
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


@dataclass
class FilesystemSource:
    """Iterate over the text files under ``root`` (a folder or a single file).

    Links found during the walk (symlinks, junctions) are never followed, so a
    scan cannot escape ``root``; a ``root`` given explicitly is used as is.
    Iteration order is sorted, so results are reproducible. Files that cannot
    be read are counted in :attr:`stats` instead of aborting the scan.
    """

    root: Path
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    excluded_dirs: Iterable[str] = DEFAULT_EXCLUDED_DIRS
    stats: ScanStats = field(default_factory=ScanStats)

    def __iter__(self) -> Iterator[SourceFile]:
        """Yield every readable text file under :attr:`root`."""
        self.stats = ScanStats()
        root = Path(self.root)
        if not root.exists():
            raise FileNotFoundError(root)
        if root.is_file():
            yield from self._read(root, root.name)
            return
        excluded = set(self.excluded_dirs)
        for dirpath, dirnames, filenames in os.walk(
            root, onerror=self._on_walk_error, followlinks=False
        ):
            here = Path(dirpath)
            # Prune in place so os.walk never descends into excluded folders or links.
            dirnames[:] = sorted(d for d in dirnames if d not in excluded and not is_link(here / d))
            for name in sorted(filenames):
                path = here / name
                if is_link(path):
                    continue
                yield from self._read(path, path.relative_to(root).as_posix())

    def _on_walk_error(self, error: OSError) -> None:
        """Count a folder that ``os.walk`` could not list."""
        self.stats.unreadable += 1

    def _read(self, path: Path, rel: str) -> Iterator[SourceFile]:
        """Yield ``path`` as a :class:`SourceFile` unless it must be skipped."""
        try:
            if not path.is_file():
                return
            if path.stat().st_size > self.max_file_size:
                self.stats.skipped_large += 1
                return
            data = path.read_bytes()
        except OSError:
            self.stats.unreadable += 1
            return
        text = decode(data)
        if text is None:
            self.stats.skipped_binary += 1
            return
        self.stats.scanned += 1
        yield SourceFile(path=rel, text=text)
