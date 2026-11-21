"""Results table and plots."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("matplotlib")

from evaluation.metrics import Row, Scores
from evaluation.plots import plot_comparison, plot_family_rates
from evaluation.report import family_table, format_table

ROWS = [Row("regex", Scores(tp=90, fp=10, fn=10)), Row("gitleaks", Scores(tp=50, fp=0, fn=50))]


def test_format_table_has_a_header_and_one_line_per_row() -> None:
    lines = format_table(ROWS).splitlines()
    assert lines[0].startswith("| Configuration")
    assert set(lines[1]) <= {"|", "-", " ", ":"}
    assert len(lines) == 2 + len(ROWS)


def test_format_table_rounds_to_three_decimals() -> None:
    text = format_table(ROWS)
    assert "0.900" in text  # regex precision and recall
    assert "1.000" in text  # gitleaks precision
    assert "0.500" in text  # gitleaks recall


def test_family_table_lists_rates_before_and_after() -> None:
    before = {"uuid": (34, 34), "token": (9, 10)}
    after = {"uuid": (0, 34), "token": (9, 10)}
    text = family_table(before, after)
    assert "| uuid | 34/34 | 0/34 |" in text
    assert "| token | 9/10 | 9/10 |" in text


def test_plots_are_written_as_png(tmp_path: Path) -> None:
    plot_comparison(ROWS, tmp_path / "comparison.png")
    plot_family_rates({"uuid": (34, 34)}, {"uuid": (0, 34)}, tmp_path / "families.png")
    for name in ("comparison.png", "families.png"):
        assert (tmp_path / name).read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
