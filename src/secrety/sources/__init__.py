"""Where scanned text comes from (local folder, Git history...)."""

from secrety.sources.filesystem import FilesystemSource, ScanStats, SourceFile

__all__ = ["FilesystemSource", "ScanStats", "SourceFile"]
