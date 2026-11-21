"""Common types for every source of scanned text."""

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class SourceFile:
    """One file's content, ready to be handed to detectors.

    Attributes:
        path: Path relative to the scan root, with ``/`` separators.
        text: Decoded content (invalid bytes replaced by U+FFFD).
        commit: SHA of the commit this version comes from (Git history
            source), or ``None`` for a file on disk.
        author: ``Name <email>`` of the commit author (Git history only).
        date: Author date of the commit, ISO 8601 (Git history only).
    """

    path: str
    text: str
    commit: str | None = None
    author: str | None = None
    date: str | None = None


@dataclass(slots=True)
class ScanStats:
    """Counters reported at the end of a scan, so nothing is skipped silently."""

    scanned: int = 0
    commits: int = 0
    skipped_binary: int = 0
    skipped_large: int = 0
    unreadable: int = 0


@runtime_checkable
class Source(Protocol):
    """Anything that yields :class:`SourceFile` objects and counts what it skipped."""

    stats: ScanStats

    def __iter__(self) -> Iterator[SourceFile]:
        """Yield the files to scan; resets :attr:`stats` at the start."""
        ...
