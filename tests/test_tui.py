"""Menu flow tests: scripted input, captured output, real scans on tmp folders."""

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

import fakes
from secrety.cli import app
from secrety.tui.banner import banner
from secrety.tui.flow import run
from secrety.tui.prompts import ask, choose


def _drive(answers: list[str]) -> tuple[str, list[str]]:
    """Run the menu with scripted answers; returns (all output, prompts left unanswered)."""
    feed: Iterator[str] = iter(answers)
    out: list[str] = []

    def fake_input(prompt: str) -> str:
        try:
            return next(feed)
        except StopIteration:
            raise EOFError from None

    run(input_fn=fake_input, print_fn=out.append)
    return "\n".join(out), list(feed)


def test_banner_shows_name_and_version() -> None:
    text = banner()
    assert "Made by Nakken" in text
    assert "|___/" in text


def test_choose_rejects_then_accepts() -> None:
    out: list[str] = []
    answers = iter(["x", "9", "2"])
    index = choose("T", ["a", "b"], input_fn=lambda _: next(answers), print_fn=out.append)
    assert index == 1
    assert sum("Invalid choice" in line for line in out) == 2


def test_choose_q_goes_back() -> None:
    assert choose("T", ["a"], input_fn=lambda _: "q", print_fn=lambda _: None) is None


def test_ask_default_and_required() -> None:
    answers = iter(["", "", "v"])
    assert ask("P", default=".", input_fn=lambda _: next(answers), print_fn=lambda _: None) == "."
    out: list[str] = []
    assert ask("P", optional=False, input_fn=lambda _: next(answers), print_fn=out.append) == "v"
    assert out == ["A value is required."]


def test_quit_immediately() -> None:
    output, left = _drive(["q"])
    assert "Scan mode" in output
    assert left == []


def test_info_then_quit() -> None:
    output, _ = _drive(["0", "q"])
    assert "About secrety" in output


def test_scan_folder_shows_masked_finding(tmp_path: Path) -> None:
    (tmp_path / "config.env").write_text(f"GH={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    output, _ = _drive(["1", str(tmp_path), "q", "q"])
    assert "config.env" in output
    assert "potential secret(s) found" in output
    assert fakes.GITHUB_TOKEN not in output


def test_scan_clean_folder(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hi')\n", encoding="utf-8")
    output, _ = _drive(["1", str(tmp_path), "q", "q"])
    assert "No secret found" in output


def test_missing_path_returns_to_menu() -> None:
    output, left = _drive(["1", "does-not-exist-xyz", "q"])
    assert "does not exist" in output
    assert left == []


def test_git_mode_rejects_bad_commit_count(tmp_path: Path) -> None:
    output, _ = _drive(["2", str(tmp_path), "zero", "q"])
    assert "whole number" in output


def test_save_json_report_is_masked_and_never_overwrites(tmp_path: Path) -> None:
    (tmp_path / "config.env").write_text(f"GH={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    report = tmp_path.parent / f"{tmp_path.name}-report.json"
    # scan, "What now?" -> save (1), format JSON (2), file, then save again to the same file.
    output, _ = _drive(
        ["1", str(tmp_path), "1", "2", str(report), "1", "2", str(report), "q", "q", "q"]
    )
    assert "saved to" in output
    assert "already exists" in output
    document = report.read_text(encoding="utf-8")
    assert fakes.GITHUB_TOKEN not in document
    json.loads(document)


def test_new_scan_in_same_mode(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    output, _ = _drive(["1", str(tmp_path), "2", str(tmp_path), "q", "q", "q"])
    assert output.count("No secret found") == 2


def test_cli_without_args_opens_menu(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _="": "q")
    result = CliRunner().invoke(app, [])
    assert result.exit_code == 0
    assert "Scan mode" in result.output
