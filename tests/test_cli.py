import subprocess
import sys
from pathlib import Path

import pytest
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


def test_summary_reports_unreadable_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "locked.txt").write_text("a", encoding="utf-8")
    real_open = Path.open

    def deny_locked(self: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        if self.name == "locked.txt":
            raise PermissionError("denied")
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "open", deny_locked)
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "1 path(s) could not be read" in result.output


def test_scan_runs_entropy_detection_by_default(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(f'k = "{fakes.HIGH_ENTROPY_BASE64}"\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "high-entropy-base64" in result.output
    assert fakes.HIGH_ENTROPY_BASE64 not in result.output


def test_scan_merges_regex_and_entropy_findings(tmp_path: Path) -> None:
    (tmp_path / "config.env").write_text(f"GH={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert "1 potential secret(s) found" in result.output
    assert "github-token" in result.output
    assert "also: high-entropy-base64" in result.output


def test_entropy_options_are_passed_to_the_detector(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(f'k = "{fakes.HIGH_ENTROPY_BASE64}"\n', encoding="utf-8")
    strict = ["--entropy-base64-threshold", "5.5", "--entropy-hex-threshold", "4"]
    assert runner.invoke(app, ["scan", str(tmp_path), *strict]).exit_code == 0
    long_only = ["--entropy-min-length", "60"]
    assert runner.invoke(app, ["scan", str(tmp_path), *long_only]).exit_code == 0


def test_entropy_hex_option_is_passed_to_the_detector(tmp_path: Path) -> None:
    digest = fakes.HIGH_ENTROPY_HEX[8:16] * 4  # "89abcdef" x4: entropy exactly 3.0
    (tmp_path / "app.py").write_text(f"digest = {digest}\n", encoding="utf-8")
    assert runner.invoke(app, ["scan", str(tmp_path)]).exit_code == 1
    option = ["--entropy-hex-threshold", "3.5"]
    assert runner.invoke(app, ["scan", str(tmp_path), *option]).exit_code == 0


@pytest.mark.parametrize(
    "option",
    [
        ["--entropy-base64-threshold", "7"],
        ["--entropy-hex-threshold", "0"],
        ["--entropy-min-length", "0"],
    ],
)
def test_out_of_range_entropy_option_is_rejected(tmp_path: Path, option: list[str]) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), *option])
    assert result.exit_code == 2
    assert "Error:" in result.output


def test_scan_flags_unquoted_secret_in_env_file(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(f"DB_PASSWORD={fakes.ENV_PASSWORD}\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "generic-password-unquoted" in result.output


def test_location_is_not_read_as_an_emoji_code(tmp_path: Path) -> None:
    # Rich turns ":100:" into an emoji: "a.env:100:4" must stay as is.
    text = "\n" * 99 + f"GH={fakes.GITHUB_TOKEN}\n"
    (tmp_path / "a.env").write_text(text, encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert "a.env:100:4" in result.output
