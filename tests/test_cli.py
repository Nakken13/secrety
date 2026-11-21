import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

import fakes
from conftest import GitRepo
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


def test_git_scan_finds_a_secret_deleted_later(git_repo: GitRepo) -> None:
    git_repo.commit("init", **{"README": "hello\n"})
    leak = git_repo.commit("leak", **{"app__settings.env": f"A=1\nGH={fakes.GITHUB_TOKEN}\n"})
    git_repo.commit("oops", **{"app__settings.env": "A=1\nGH=\n"})
    # A folder scan of the working tree sees nothing...
    assert runner.invoke(app, ["scan", str(git_repo.path)]).exit_code == 0
    # ...the history scan finds it, at the commit that added it.
    result = runner.invoke(app, ["scan", str(git_repo.path), "--git"])
    assert result.exit_code == 1
    assert f"{leak[:12]}:app/settings.env:2:4" in result.output
    assert "removed from HEAD" in result.output
    assert "Test Author <author@example.com>" in result.output
    assert fakes.GITHUB_TOKEN not in result.output
    assert "3 commit(s)" in result.output


def test_git_scan_options_are_passed_on(git_repo: GitRepo) -> None:
    git_repo.commit("leak", **{"a.env": f"GH={fakes.GITHUB_TOKEN}\n"})
    git_repo.commit("later", **{"b.txt": "x\n"})
    assert (
        runner.invoke(app, ["scan", str(git_repo.path), "--git", "--max-commits", "1"]).exit_code
        == 0
    )
    assert (
        runner.invoke(app, ["scan", str(git_repo.path), "--git", "--since", "2024-01-02"]).exit_code
        == 0
    )
    assert (
        runner.invoke(app, ["scan", str(git_repo.path), "--git", "--since", "2023-12-31"]).exit_code
        == 1
    )


def test_git_scan_of_a_folder_that_is_not_a_repository_exits_two(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--git"])
    assert result.exit_code == 2
    assert "not a Git repository" in result.output


def test_git_scan_of_an_empty_repository_exits_two(git_repo: GitRepo) -> None:
    result = runner.invoke(app, ["scan", str(git_repo.path), "--git"])
    assert result.exit_code == 2
    assert "no commits" in result.output


def test_git_scan_warns_about_shallow_clones(git_repo: GitRepo, tmp_path: Path) -> None:
    git_repo.commit("one", **{"a.txt": "1\n"})
    git_repo.commit("two", **{"a.txt": "1\n2\n"})
    clone = tmp_path / "clone"
    git_repo.git("clone", "--quiet", "--depth=1", git_repo.path.as_uri(), str(clone))
    result = runner.invoke(app, ["scan", str(clone), "--git"])
    assert "shallow clone" in result.output


def test_git_options_require_git(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--max-commits", "1"])
    assert result.exit_code == 2
    assert "--git" in result.output


def test_control_characters_from_the_repository_are_not_sent_to_the_terminal(
    git_repo: GitRepo,
) -> None:
    git_repo.commit("leak", **{"a.env": f"T={fakes.GITHUB_TOKEN}\n"})
    git_repo.git("commit", "--amend", "--quiet", "--no-edit", "--author=Evil\x1b[2J\x9b <e@x>")
    result = runner.invoke(app, ["scan", str(git_repo.path), "--git"])
    assert "\x1b" not in result.output
    assert "\x9b" not in result.output
    assert "Evil\\x1b[2J\\x9b" in result.output


def test_git_help_says_only_head_history_is_scanned() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert "reachable from HEAD" in " ".join(result.output.replace("\u2502", " ").split())


# --- allowlist and inline ignore -----------------------------------------


def test_findings_in_allowed_paths_are_suppressed_and_counted(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.env").write_text(f"GH={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "1 finding(s) suppressed by the path allowlist" in result.output


def test_inline_ignore_suppresses_a_finding(tmp_path: Path) -> None:
    (tmp_path / "app.env").write_text(
        f"GH={fakes.GITHUB_TOKEN}  # secrety:ignore[github-token, high-entropy-base64]\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "1 by inline secrety:ignore" in result.output


def test_config_file_can_turn_default_allowlist_off(tmp_path: Path) -> None:
    (tmp_path / ".secrety.toml").write_text("[allowlist]\nuse_defaults = false\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.env").write_text(f"GH={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "tests/fixture.env:1:4" in result.output
    assert "Config: " in result.output


def test_explicit_config_option(tmp_path: Path) -> None:
    config = tmp_path / "custom.toml"
    config.write_text('[allowlist]\npaths = ["vendor/**"]\n', encoding="utf-8")
    target = tmp_path / "repo"
    (target / "vendor").mkdir(parents=True)
    (target / "vendor" / "a.env").write_text(f"GH={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    assert runner.invoke(app, ["scan", str(target)]).exit_code == 1
    assert runner.invoke(app, ["scan", str(target), "--config", str(config)]).exit_code == 0


def test_invalid_config_exits_two(tmp_path: Path) -> None:
    (tmp_path / ".secrety.toml").write_text("[allowlist]\npath = []\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert "unknown key" in result.output


def test_git_scan_applies_the_allowlist(git_repo: GitRepo) -> None:
    git_repo.commit("add fixture", **{"tests__fixture.env": f"GH={fakes.GITHUB_TOKEN}\n"})
    result = runner.invoke(app, ["scan", str(git_repo.path), "--git"])
    assert result.exit_code == 0
    assert "1 finding(s) suppressed by the path allowlist" in result.output


# --- classifier -----------------------------------------------------------


def test_classifier_is_off_by_default(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text('api_key = "your-api-key-here-0000"\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "classifier" not in result.output


def test_classifier_drops_placeholders_and_rescores(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text('api_key = "your-api-key-here-0000"\n', encoding="utf-8")
    (tmp_path / "prod.env").write_text(f"GH={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--classifier"])
    assert result.exit_code == 1
    assert "prod.env:1:4" in result.output
    assert "README.md" not in result.output
    assert "1 finding(s) below the classifier threshold 0.50 dropped" in result.output
    assert "untrained stub" in result.output


def test_classifier_threshold_option(tmp_path: Path) -> None:
    (tmp_path / "prod.env").write_text(f"GH={fakes.GITHUB_TOKEN}\n", encoding="utf-8")
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--classifier", "--classifier-threshold", "1.0"]
    )
    assert result.exit_code == 0
    assert "threshold 1.00" in result.output


def test_classifier_threshold_out_of_range_exits_two(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--classifier", "--classifier-threshold", "1.5"]
    )
    assert result.exit_code == 2
    assert "threshold" in result.output


def test_classifier_threshold_needs_classifier(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--classifier-threshold", "0.2"])
    assert result.exit_code == 2
    assert "--classifier" in result.output


def test_custom_rules_with_unbounded_quantifier_warn(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n  - {id: greedy, description: G, regex: 'DEMO-[0-9]+'}\n", encoding="utf-8"
    )
    target = tmp_path / "src"
    target.mkdir()
    result = runner.invoke(app, ["scan", str(target), "--rules", str(rules)])
    assert result.exit_code == 0  # a warning, not an error
    assert "Warning: rule 'greedy': unbounded quantifier(s) +" in result.output


def test_bundled_rules_print_no_quantifier_warning(tmp_path: Path) -> None:
    assert "unbounded" not in runner.invoke(app, ["scan", str(tmp_path)]).output


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions are Windows-only")
def test_summary_reports_skipped_links(tmp_path: Path) -> None:
    (tmp_path / "outside").mkdir()
    root = tmp_path / "root"
    root.mkdir()
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(root / "j"), str(tmp_path / "outside")],
        check=True,
        capture_output=True,
    )
    result = runner.invoke(app, ["scan", str(root)])
    assert "1 link(s) not followed" in result.output


def test_summary_omits_links_when_none(tmp_path: Path) -> None:
    assert "link(s)" not in runner.invoke(app, ["scan", str(tmp_path)]).output
