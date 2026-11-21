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
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
# Bit 29 of a reparse tag: the reparse point names another path (IsReparseTagNameSurrogate).
_NAME_SURROGATE = 0x20000000


def is_binary(head: bytes) -> bool:
    """True if the first bytes of a file contain a NUL, as in Git.

    UTF-16 files (the PowerShell 5.1 ``Out-File`` default) are full of NULs
    but are text: they are recognised by their byte-order mark.
    """
    return b"\x00" in head and not head.startswith(_UTF16_BOMS)


def decode(data: bytes) -> str:
    """Decode text bytes: UTF-16 when a BOM says so, else UTF-8 with replacement."""
    if data.startswith(_UTF16_BOMS):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def _is_link(info: os.stat_result) -> bool:
    """Symbolic link or Windows junction, from ``lstat``.

    ``Path.is_symlink`` and ``os.walk(followlinks=False)`` do not recognise
    NTFS junctions on Python 3.11, hence the reparse-point check. Only
    reparse points whose tag is a *name surrogate* (they point at another
    path: symlinks, junctions) count as links. Other reparse points are
    ordinary files stored differently, such as OneDrive placeholders or
    deduplicated files, and must still be scanned.
    """
    attributes = getattr(info, "st_file_attributes", 0)
    tag = getattr(info, "st_reparse_tag", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & _REPARSE_POINT and tag & _NAME_SURROGATE)


def is_link(path: Path) -> bool:
    """Return True if ``path`` is a symlink or a junction (never followed)."""
    try:
        return _is_link(os.lstat(path))
    except OSError:
        return False


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
        root = self.root
        if not root.exists():
            raise FileNotFoundError(root)
        if root.is_file():
            if file := self._read(root, root.name, follow_link=True):
                yield file
            return
        excluded = set(self.excluded_dirs)
        for dirpath, dirnames, filenames in os.walk(
            root, onerror=self._on_walk_error, followlinks=False
        ):
            here = Path(dirpath)
            # Prune in place so os.walk never descends into excluded folders or links.
            kept = []
            for d in sorted(dirnames):
                if d in excluded:
                    continue
                if is_link(here / d):
                    self.stats.skipped_links += 1
                    continue
                kept.append(d)
            dirnames[:] = kept
            for name in sorted(filenames):
                path = here / name
                if file := self._read(path, path.relative_to(root).as_posix()):
                    yield file

    def _on_walk_error(self, error: OSError) -> None:
        """Count a folder that ``os.walk`` could not list."""
        self.stats.unreadable += 1

    def _read(self, path: Path, rel: str, follow_link: bool = False) -> SourceFile | None:
        """Return ``path`` as a :class:`SourceFile`, or ``None`` if skipped.

        One ``lstat`` gives the link check, the file type and the size. Only
        the first 8 KiB are read before the binary check, so a large binary
        file is never read in full.
        """
        try:
            info = os.stat(path) if follow_link else os.lstat(path)
            if _is_link(info):
                self.stats.skipped_links += 1
                return None
            if not stat.S_ISREG(info.st_mode):
                return None
            if info.st_size > self.max_file_size:
                self.stats.skipped_large += 1
                return None
            with path.open("rb") as handle:
                head = handle.read(BINARY_SNIFF_SIZE)
                if is_binary(head):
                    self.stats.skipped_binary += 1
                    return None
                data = head + handle.read()
        except OSError:
            self.stats.unreadable += 1
            return None
        self.stats.scanned += 1
        return SourceFile(path=rel, text=decode(data))
