"""Where scanned text comes from (local folder, Git history...)."""

from secrety.sources.base import ScanStats, Source, SourceFile
from secrety.sources.filesystem import FilesystemSource

__all__ = ["FilesystemSource", "ScanStats", "Source", "SourceFile"]
