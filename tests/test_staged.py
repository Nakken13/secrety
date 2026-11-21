import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

import fakes
from conftest import GitRepo
from secrety.cli import app
from secrety.sources.staged import StagedSource, repo_root

runner = CliRunner()
ROOT = Path(__file__).resolve().parent.parent
LEAK = f"GH={fakes.GITHUB_TOKEN}\n"


def staged(repo: GitRepo, **options: object) -> dict[str, str]:
    """``{path: text}`` of every file the source yields."""
    return {f.path: f.text for f in StagedSource(repo.path, **options)}  # type: ignore[arg-type]


def test_yields_the_index_content_not_the_worktree(git_repo: GitRepo) -> None:
    git_repo.commit("init", **{"README": "hi\n"})
    git_repo.write("a.env", LEAK)
    git_repo.git("add", "a.env")
    git_repo.write("a.env", "CLEAN=1\n")  # unstaged edit hides the leak on disk
    assert staged(git_repo) == {"a.env": LEAK}


def test_a_secret_only_in_the_worktree_is_ignored(git_repo: GitRepo) -> None:
    git_repo.commit("init", **{"a.env": "CLEAN=1\n"})
    git_repo.write("a.env", LEAK)  # modified, not staged
    assert staged(git_repo) == {}


def test_unmodified_committed_files_are_not_scanned(git_repo: GitRepo) -> None:
    git_repo.commit("init", **{"old.env": LEAK})
    git_repo.write("new.txt", "x\n")
    git_repo.git("add", "new.txt")
    assert list(staged(git_repo)) == ["new.txt"]


def test_paths_are_relative_to_the_repo_root_from_a_subfolder(git_repo: GitRepo) -> None:
    git_repo.write("src/app/a.env", LEAK)
    git_repo.git("add", "--all")
    assert list(staged(git_repo)) == ["src/app/a.env"]
    source = StagedSource(git_repo.path / "src" / "app")
    assert [f.path for f in source] == ["src/app/a.env"]


def test_deleted_files_and_binaries_and_large_files(git_repo: GitRepo) -> None:
    git_repo.commit("init", **{"gone.txt": "x\n"})
    git_repo.git("rm", "--quiet", "gone.txt")
    git_repo.write("bin.dat", b"\x00\x01" + LEAK.encode())
    git_repo.write("big.txt", "a" * 500)
    git_repo.write("ok.txt", "ok\n")
    git_repo.git("add", "--all")
    source = StagedSource(git_repo.path, max_file_size=200)
    assert [f.path for f in source] == ["ok.txt"]
    assert (source.stats.scanned, source.stats.skipped_binary, source.stats.skipped_large) == (
        1,
        1,
        1,
    )


def test_a_renamed_file_is_scanned_under_its_new_name(git_repo: GitRepo) -> None:
    git_repo.commit("init", **{"a.env": LEAK})
    git_repo.git("mv", "a.env", "b.env")
    assert list(staged(git_repo)) == ["b.env"]


def test_unusual_file_names_are_read(git_repo: GitRepo) -> None:
    git_repo.write("dir with space/é.env", LEAK)
    git_repo.git("add", "--all")
    assert list(staged(git_repo)) == ["dir with space/é.env"]


def test_not_a_repository_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a Git repository"):
        repo_root(tmp_path)


def test_cli_staged_finds_a_staged_secret(git_repo: GitRepo) -> None:
    git_repo.write("a.env", LEAK)
    git_repo.git("add", "a.env")
    git_repo.write("a.env", "CLEAN=1\n")
    result = runner.invoke(app, ["scan", str(git_repo.path), "--staged"])
    assert result.exit_code == 1
    assert "a.env:1" in result.output
    assert fakes.GITHUB_TOKEN not in result.output


def test_cli_staged_clean_index_exits_zero(git_repo: GitRepo) -> None:
    git_repo.commit("init", **{"a.env": LEAK})
    result = runner.invoke(app, ["scan", str(git_repo.path), "--staged"])
    assert result.exit_code == 0


def test_cli_staged_outside_a_repository_exits_two(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--staged"])
    assert result.exit_code == 2
    assert "not a Git repository" in result.output


def test_cli_staged_and_git_are_exclusive(git_repo: GitRepo) -> None:
    result = runner.invoke(app, ["scan", str(git_repo.path), "--staged", "--git"])
    assert result.exit_code == 2


def test_cli_staged_uses_repo_root_config_and_relative_paths(git_repo: GitRepo) -> None:
    git_repo.write(".secrety.toml", '[allowlist]\npaths = ["**/tests/**"]\n')
    git_repo.write("pkg/tests/t.env", LEAK)
    git_repo.git("add", "--all")
    # Scanned from a subfolder: the root config and the repo-relative path still apply.
    result = runner.invoke(app, ["scan", str(git_repo.path / "pkg"), "--staged"])
    assert result.exit_code == 0, result.output
    assert "suppressed by the path allowlist" in result.output


def test_exit_zero_overrides_findings_but_not_errors(git_repo: GitRepo, tmp_path: Path) -> None:
    git_repo.write("a.env", LEAK)
    git_repo.git("add", "a.env")
    result = runner.invoke(app, ["scan", str(git_repo.path), "--staged", "--exit-zero"])
    assert result.exit_code == 0
    assert "potential secret(s) found" in result.output
    err = runner.invoke(app, ["scan", str(tmp_path), "--staged", "--exit-zero"])
    assert err.exit_code == 2


def test_pre_commit_hook_definition_runs_the_staged_scan() -> None:
    hooks = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
    hook = next(h for h in hooks if h["id"] == "secrety")
    assert hook["language"] == "python"
    assert hook["pass_filenames"] is False
    assert hook["always_run"] is True
    assert hook["entry"].split() == ["secrety", "scan", "--staged"]


def test_pre_commit_flow_in_a_temp_repo(git_repo: GitRepo) -> None:
    """The hook's entry, run as pre-commit would (cwd = repo root), blocks a leak."""
    git_repo.write("a.env", LEAK)
    git_repo.git("add", "a.env")
    cmd = [sys.executable, "-m", "secrety", "scan", "--staged"]
    blocked = subprocess.run(cmd, cwd=git_repo.path, capture_output=True, text=True)
    assert blocked.returncode == 1
    git_repo.git("rm", "--cached", "--quiet", "a.env")
    ok = subprocess.run(cmd, cwd=git_repo.path, capture_output=True, text=True)
    assert ok.returncode == 0


def test_action_yml_is_a_composite_action_with_optional_sarif_upload() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"
    assert {"path", "config", "sarif", "exit-zero"} <= set(action["inputs"])
    uses = [s.get("uses", "") for s in action["runs"]["steps"]]
    assert any(u.startswith("github/codeql-action/upload-sarif@") for u in uses)


def test_a_temporary_index_from_git_commit_a_is_honoured(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``git commit <paths>`` runs hooks with GIT_INDEX_FILE on the index it will commit."""
    git_repo.commit("init", **{"a.txt": "x\n"})
    git_repo.write("a.env", LEAK)
    git_repo.git("add", "a.env")
    temp_index = git_repo.path / ".git" / "tmp-index"
    git_repo.git("read-tree", "HEAD")  # real index now lacks a.env
    monkeypatch.setenv("GIT_INDEX_FILE", str(temp_index))
    git_repo.git("read-tree", "HEAD")
    git_repo.git("add", "a.env")  # only the temporary index has it
    assert list(staged(git_repo)) == ["a.env"]


def test_cli_staged_reads_the_config_from_the_index_not_the_worktree(git_repo: GitRepo) -> None:
    git_repo.commit("init", **{".secrety.toml": "[allowlist]\npaths = []\n"})
    git_repo.write("a.env", LEAK)
    git_repo.git("add", "a.env")
    git_repo.write(".secrety.toml", '[allowlist]\npaths = ["**"]\n')  # unstaged, hides it
    result = runner.invoke(app, ["scan", str(git_repo.path), "--staged"])
    assert result.exit_code == 1, result.output


def test_cli_staged_invalid_staged_config_exits_two(git_repo: GitRepo) -> None:
    git_repo.write(".secrety.toml", "not = [valid")
    git_repo.write("a.txt", "x\n")
    git_repo.git("add", "--all")
    result = runner.invoke(app, ["scan", str(git_repo.path), "--staged"])
    assert result.exit_code == 2
