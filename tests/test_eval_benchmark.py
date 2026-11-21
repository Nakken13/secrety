"""Normalising gitleaks and trufflehog output, and timing helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evaluation.benchmark import median_seconds, parse_gitleaks, parse_trufflehog


def test_parse_gitleaks_maps_files_to_corpus_relative_lines(tmp_path: Path) -> None:
    root = tmp_path / "files"
    report = json.dumps(
        [
            {"RuleID": "r", "File": str(root / "src" / "a.py"), "StartLine": 5, "EndLine": 5},
            {"RuleID": "r", "File": str(root / "k.pem"), "StartLine": 1, "EndLine": 3},
        ]
    )
    assert parse_gitleaks(report, root) == {
        ("src/a.py", 5),
        ("k.pem", 1),
        ("k.pem", 2),
        ("k.pem", 3),
    }


def test_parse_gitleaks_accepts_an_empty_report(tmp_path: Path) -> None:
    assert parse_gitleaks("[]", tmp_path) == set()
    assert parse_gitleaks("", tmp_path) == set()


def test_parse_trufflehog_reads_json_lines(tmp_path: Path) -> None:
    root = tmp_path / "files"
    lines = [
        {"SourceMetadata": {"Data": {"Filesystem": {"file": str(root / "x" / "b.js"), "line": 8}}}},
        {"SourceMetadata": {"Data": {"Filesystem": {"file": str(root / "c.py"), "line": 2}}}},
        {"level": "info", "msg": "not a finding"},
    ]
    text = "\n".join(json.dumps(line) for line in lines) + "\n"
    assert parse_trufflehog(text, root) == {("x/b.js", 8), ("c.py", 2)}


def test_median_seconds_runs_the_command_that_many_times() -> None:
    calls: list[int] = []

    def fake() -> None:
        calls.append(1)

    assert median_seconds(fake, runs=3) >= 0.0
    assert len(calls) == 3


def test_median_seconds_needs_a_positive_run_count() -> None:
    with pytest.raises(ValueError, match="runs"):
        median_seconds(lambda: None, runs=0)
