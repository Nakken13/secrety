from pathlib import Path

import fakes
from secrety.detectors import RegexDetector
from secrety.rules import load_rules
from secrety.scanner import scan
from secrety.sources import FilesystemSource


def test_scan_runs_every_detector_on_every_file(tmp_path: Path) -> None:
    (tmp_path / "a.env").write_text(f"TOKEN={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    (tmp_path / "b.py").write_text(f'k = "{fakes.STRIPE_SECRET_KEY}"\n', encoding="utf-8")
    (tmp_path / "clean.txt").write_text("nothing here\n", encoding="utf-8")
    findings = scan(FilesystemSource(tmp_path), [RegexDetector(load_rules())])
    assert [(f.path, f.rule_id) for f in findings] == [
        ("a.env", "github-token"),
        ("b.py", "stripe-secret-key"),
    ]


def test_scan_without_detectors_finds_nothing(tmp_path: Path) -> None:
    (tmp_path / "a.env").write_text(f"TOKEN={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    assert scan(FilesystemSource(tmp_path), []) == []
