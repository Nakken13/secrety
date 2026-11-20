import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

import fakes
from secrety import __version__
from secrety.cli import app

runner = CliRunner()


def test_version_flag_prints_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "scan" in result.output


def test_scan_clean_folder_exits_zero(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No secret found" in result.output


def test_scan_reports_findings_masked_and_exits_one(tmp_path: Path) -> None:
    (tmp_path / "config.env").write_text(f"GH={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "config.env:1:4" in result.output
    assert "github-token" in result.output
    assert fakes.GITHUB_TOKEN not in result.output
    assert fakes.GITHUB_TOKEN[:4] in result.output
    assert "1 potential secret" in result.output


def test_scan_with_custom_rules(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n  - {id: demo, description: Demo, regex: 'DEMO-[0-9]{4}'}\n", encoding="utf-8"
    )
    target = tmp_path / "src"
    target.mkdir()
    (target / "a.txt").write_text("id = DEMO-1234\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(target), "--rules", str(rules)])
    assert result.exit_code == 1
    assert "demo" in result.output


def test_scan_with_invalid_rules_exits_two(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules:\n  - {id: a, description: A, regex: '(oops'}\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--rules", str(rules)])
    assert result.exit_code == 2
    assert "invalid regex" in result.output


def test_scan_rejects_missing_path(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path / "missing")])
    assert result.exit_code != 0


def test_module_entry_point_runs() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "secrety", "--version"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0
    assert __version__ in result.stdout


def test_untrusted_paths_and_content_are_not_rich_markup(tmp_path: Path) -> None:
    hostile = tmp_path / "[bold]"
    hostile.mkdir()
    (hostile / "a.py").write_text(
        f'password = "[/b]{fakes.GENERIC_PASSWORD}"\nk = "{fakes.GITHUB_TOKEN}"\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1, result.output
    assert "[bold]/a.py:2" in result.output
    assert "2 potential secret" in result.output


def test_rule_error_message_is_not_rich_markup(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules:\n  - {id: '[/x]', description: A, regex: '(oops'}\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--rules", str(rules)])
    assert result.exit_code == 2
    assert "[/x]" in result.output
