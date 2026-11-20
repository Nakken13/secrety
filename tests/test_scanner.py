from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import fakes
from secrety.detectors import RegexDetector
from secrety.rules import load_rules
from secrety.scanner import ScanResult, scan
from secrety.sources import FilesystemSource, ScanStats, SourceFile


@dataclass
class ListSource:
    """In-memory source, for tests that do not need files on disk."""

    files: list[SourceFile]
    stats: ScanStats = field(default_factory=ScanStats)

    def __iter__(self) -> Iterator[SourceFile]:
        self.stats = ScanStats(scanned=len(self.files))
        return iter(self.files)


def test_scan_runs_every_detector_on_every_file(tmp_path: Path) -> None:
    (tmp_path / "a.env").write_text(f"TOKEN={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    (tmp_path / "b.py").write_text(f'k = "{fakes.STRIPE_SECRET_KEY}"\n', encoding="utf-8")
    (tmp_path / "clean.txt").write_text("nothing here\n", encoding="utf-8")
    result = scan(FilesystemSource(tmp_path), [RegexDetector(load_rules())])
    assert [(f.path, f.rule_id) for f in result.findings] == [
        ("a.env", "github-token"),
        ("b.py", "stripe-secret-key"),
    ]


def test_scan_returns_the_source_stats(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "b.bin").write_bytes(b"\x00\x01")
    result = scan(FilesystemSource(tmp_path), [])
    assert result == ScanResult(findings=[], stats=ScanStats(scanned=1, skipped_binary=1))


def test_scan_copies_the_source_commit_onto_findings() -> None:
    source = ListSource([SourceFile(path="a.env", text=f"T={fakes.GITHUB_TOKEN}\n", commit="abc")])
    (finding,) = scan(source, [RegexDetector(load_rules())]).findings
    assert finding.commit == "abc"
