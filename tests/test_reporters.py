import json
from pathlib import Path

import pytest
from jsonschema import Draft4Validator
from typer.testing import CliRunner

import fakes
from secrety.cli import app
from secrety.models import DetectionMethod, Finding
from secrety.reporters import render_json, render_sarif, render_text, safe

runner = CliRunner()
SARIF_SCHEMA = json.loads(
    (Path(__file__).parent / "schemas" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8")
)


def make_finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "rule_id": "github-token",
        "description": "GitHub token",
        "path": "src/my app/a.py",
        "line": 3,
        "column": 7,
        "secret": fakes.GITHUB_TOKEN,
        "line_content": f"t = {fakes.GITHUB_TOKEN}",
        "method": DetectionMethod.REGEX,
        "confidence": 0.95,
    }
    fields.update(overrides)
    return Finding(**fields)  # type: ignore[arg-type]


def test_json_is_masked_and_stable() -> None:
    f = make_finding(also_matched=(("entropy", DetectionMethod.ENTROPY),))
    text = render_json([f])
    assert fakes.GITHUB_TOKEN not in text
    doc = json.loads(text)
    assert doc["schema_version"] == 1
    assert doc["tool"]["name"] == "secrety"
    item = doc["findings"][0]
    assert item["secret"] == f.masked()
    assert item["fingerprint"] == f.fingerprint
    assert item["also_matched"] == [{"rule_id": "entropy", "method": "entropy"}]
    assert item["commit"] is None


def test_json_empty() -> None:
    assert json.loads(render_json([]))["findings"] == []


def test_sarif_validates_against_official_schema() -> None:
    findings = [
        make_finding(),
        make_finding(rule_id="other", description="Other", confidence=0.3, path="b.txt"),
        make_finding(commit="a" * 40, author="A <a@b.c>", date="2024-01-01", removed_later=True),
    ]
    log = json.loads(render_sarif(findings))
    Draft4Validator(SARIF_SCHEMA).validate(log)
    run = log["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["github-token", "other"]
    assert [r["ruleIndex"] for r in run["results"]] == [0, 1, 0]
    assert [r["level"] for r in run["results"]] == ["error", "warning", "error"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "src/my%20app/a.py"
    )
    assert run["results"][2]["properties"]["removedLater"] is True


def test_sarif_empty_validates_and_never_leaks_secret() -> None:
    Draft4Validator(SARIF_SCHEMA).validate(json.loads(render_sarif([])))
    assert fakes.GITHUB_TOKEN not in render_sarif([make_finding()])


def test_safe_escapes_controls_and_markup() -> None:
    assert safe("\x1b[31m[bold]x") == "\\x1b[31m\\[bold]x"


def test_text_reporter_masks(capsys: pytest.CaptureFixture[str]) -> None:
    from rich.console import Console

    render_text(
        Console(highlight=False, emoji=False), [make_finding(author="Me", date="2024-05-06")]
    )
    out = capsys.readouterr().out
    assert fakes.GITHUB_TOKEN not in out
    assert "by Me on 2024-05-06" in out


@pytest.fixture
def secret_dir(tmp_path: Path) -> Path:
    d = tmp_path / "proj"
    d.mkdir()
    (d / "config.env").write_text(f"GH={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    return d


def test_cli_json_stdout_is_pure_json(secret_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(secret_dir), "--format", "json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["findings"][0]["rule_id"] == "github-token"
    assert fakes.GITHUB_TOKEN not in result.output


def test_cli_sarif_output_file(secret_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "r.sarif"
    result = runner.invoke(app, ["scan", str(secret_dir), "-f", "sarif", "-o", str(out)])
    assert result.exit_code == 1
    Draft4Validator(SARIF_SCHEMA).validate(json.loads(out.read_text(encoding="utf-8")))
    assert "potential secret" in result.output


def test_cli_text_output_file(secret_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "r.txt"
    result = runner.invoke(app, ["scan", str(secret_dir), "--output", str(out)])
    assert result.exit_code == 1
    content = out.read_text(encoding="utf-8")
    assert "github-token" in content
    assert fakes.GITHUB_TOKEN not in content
    assert "\x1b" not in content


def test_cli_clean_json_exit_zero(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["findings"] == []


def test_cli_unwritable_output_exits_two(secret_dir: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(secret_dir), "-f", "json", "-o", str(tmp_path / "no" / "x.json")]
    )
    assert result.exit_code == 2


def test_cli_text_unwritable_output_exits_two(secret_dir: Path, tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(secret_dir), "-o", str(tmp_path / "no" / "x.txt")])
    assert result.exit_code == 2


def test_cli_bad_format_rejected(secret_dir: Path) -> None:
    assert runner.invoke(app, ["scan", str(secret_dir), "--format", "xml"]).exit_code == 2


def test_cli_error_in_json_mode_keeps_stdout_empty(secret_dir: Path, tmp_path: Path) -> None:
    bad = tmp_path / "rules.yaml"
    bad.write_text("rules:\n  - {id: a, description: A, regex: '(oops'}\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["scan", str(secret_dir), "-f", "json", "--rules", str(bad)])
    assert result.exit_code == 2
    assert result.stdout == ""
