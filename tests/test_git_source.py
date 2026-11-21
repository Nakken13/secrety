import subprocess
from datetime import UTC, datetime
from pathlib import Path

import git
import pytest

import fakes
from conftest import GitRepo
from secrety.detectors import RegexDetector
from secrety.rules import load_rules
from secrety.scanner import scan
from secrety.sources.git import GitSource
from test_models import make_finding


def files_of(repo: GitRepo, **options: object) -> list[tuple[str, str, str]]:
    """``(short sha, path, text)`` of every excerpt the source yields."""
    return [(f.commit[:7], f.path, f.text) for f in GitSource(repo.path, **options)]  # type: ignore[index,arg-type]


def test_yields_only_the_lines_added_by_each_commit(git_repo: GitRepo) -> None:
    first = git_repo.commit("one", **{"a.txt": "alpha\nbeta\n"})
    second = git_repo.commit("two", **{"a.txt": "alpha\nNEW\nbeta\n"})
    assert (
        files_of(git_repo)
        == [
            (second[:7], "a.txt", "NEW"),  # newest first
            (first[:7], "a.txt", "alpha\nbeta"),
        ]
    )


def test_each_run_of_added_lines_is_one_excerpt_at_its_offset(git_repo: GitRepo) -> None:
    body = [f"line {n}" for n in range(1, 5001)]
    git_repo.commit("one", **{"big.txt": "\n".join(body) + "\n"})
    body[1] = "CHANGED 2"
    body[4998] = "CHANGED 4999"
    git_repo.commit("two", **{"big.txt": "\n".join(body) + "\n"})
    newest = [f for f in GitSource(git_repo.path) if f.text.startswith("CHANGED")]
    assert [(f.line_offset, f.text) for f in newest] == [(1, "CHANGED 2"), (4998, "CHANGED 4999")]


def test_a_nul_byte_far_down_does_not_hide_the_lines_above(git_repo: GitRepo) -> None:
    filler = "x" * 100 + "\n"
    content = f"T={fakes.GITHUB_TOKEN}\n" + filler * 100 + "bin\x00ary\n"
    git_repo.commit("one", **{"a.env": content})
    findings = scan(GitSource(git_repo.path), [RegexDetector(load_rules())]).findings
    assert [(f.path, f.line) for f in findings] == [("a.env", 1)]


def test_attaches_author_and_date(git_repo: GitRepo) -> None:
    git_repo.commit("one", **{"a.txt": "x\n"})
    (file,) = GitSource(git_repo.path)
    assert file.author == "Test Author <author@example.com>"
    assert datetime.fromisoformat(file.date) == datetime(2024, 1, 1, 12, tzinfo=UTC)  # type: ignore[arg-type]


def test_findings_point_at_the_line_of_the_file_in_that_commit(git_repo: GitRepo) -> None:
    git_repo.commit("one", **{"cfg.env": "A=1\nB=2\nC=3\n"})
    sha = git_repo.commit("leak", **{"cfg.env": f"A=1\nB=2\nTOKEN={fakes.GITHUB_TOKEN}\nC=3\n"})
    result = scan(GitSource(git_repo.path), [RegexDetector(load_rules())])
    (finding,) = result.findings
    assert (finding.commit, finding.path, finding.line) == (sha, "cfg.env", 3)
    assert finding.author == "Test Author <author@example.com>"
    assert datetime.fromisoformat(finding.date) == datetime(2024, 1, 2, 12, tzinfo=UTC)  # type: ignore[arg-type]
    shown = git_repo.git("show", f"{sha}:cfg.env").split("\n")
    assert fakes.GITHUB_TOKEN in shown[finding.line - 1]
    assert result.stats.commits == 2


def test_deleted_lines_and_deleted_files_yield_nothing(git_repo: GitRepo) -> None:
    git_repo.commit("one", **{"a.txt": "keep\ndrop\n", "b.txt": "gone\n"})
    git_repo.write("a.txt", "keep\n")
    (git_repo.path / "b.txt").unlink()
    git_repo.commit("two")
    assert [path for _, path, _ in files_of(git_repo)] == ["a.txt", "b.txt"]  # commit one only


def test_paths_in_subfolders_with_spaces_and_non_ascii(git_repo: GitRepo) -> None:
    git_repo.commit("one", **{"dir__my file é.txt": "x\n"})
    assert sorted(path for _, path, _ in files_of(git_repo)) == ["dir/my file é.txt"]


def test_rename_without_change_is_not_rescanned(git_repo: GitRepo) -> None:
    git_repo.commit("one", **{"a.txt": "content\n"})
    git_repo.git("mv", "a.txt", "b.txt")
    git_repo.commit("rename")
    assert [path for _, path, _ in files_of(git_repo)] == ["a.txt"]


def test_file_without_trailing_newline(git_repo: GitRepo) -> None:
    git_repo.commit("one", **{"a.txt": "no newline"})
    assert files_of(git_repo)[0][2] == "no newline"


def test_not_a_repository_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a Git repository"):
        list(GitSource(tmp_path))


def test_repository_without_commits_raises(git_repo: GitRepo) -> None:
    with pytest.raises(ValueError, match="no commits"):
        list(GitSource(git_repo.path))


def scan_history(repo: GitRepo) -> list:
    source = GitSource(repo.path)
    findings = scan(source, [RegexDetector(load_rules())]).findings
    return source.mark_removed(findings)


def test_secret_deleted_later_is_marked_removed(git_repo: GitRepo) -> None:
    leak = git_repo.commit("leak", **{"cfg.env": f"TOKEN={fakes.GITHUB_TOKEN}\n"})
    git_repo.commit("cleanup", **{"cfg.env": "TOKEN=\n"})
    (finding,) = scan_history(git_repo)
    assert (finding.commit, finding.removed_later) == (leak, True)


def test_secret_still_in_head_is_not_marked_removed(git_repo: GitRepo) -> None:
    git_repo.commit("leak", **{"cfg.env": f"TOKEN={fakes.GITHUB_TOKEN}\n"})
    git_repo.commit("other", **{"README": "hello\n"})
    (finding,) = scan_history(git_repo)
    assert finding.removed_later is False


def test_secret_moved_to_another_file_is_not_marked_removed(git_repo: GitRepo) -> None:
    git_repo.commit("leak", **{"a.env": f"TOKEN={fakes.GITHUB_TOKEN}\n"})
    (git_repo.path / "a.env").unlink()
    git_repo.commit("move", **{"b.env": f"KEY={fakes.GITHUB_TOKEN}\n"})
    assert [f.removed_later for f in scan_history(git_repo)] == [False, False]


def test_secret_inside_a_longer_secret_in_head_is_not_removed(git_repo: GitRepo) -> None:
    # git grep -o prints the longest match only, so "FAKEshort" is never printed.
    git_repo.commit("one", **{"a.env": "K=FAKEshortFAKElonger\n"})
    short = make_finding(commit="0" * 40, secret="FAKEshort", line_content="K=FAKEshort")
    long = make_finding(commit="0" * 40, secret="FAKEshortFAKElonger", line_content="K=")
    marked = GitSource(git_repo.path).mark_removed([short, long])
    assert [f.removed_later for f in marked] == [False, False]


def test_filesystem_findings_are_left_unchecked(git_repo: GitRepo) -> None:
    git_repo.commit("one", **{"a.txt": "x\n"})
    finding = make_finding()
    assert GitSource(git_repo.path).mark_removed([finding]) == [finding]


def test_clean_merge_reports_nothing_new(git_repo: GitRepo) -> None:
    git_repo.commit("base", **{"a.txt": "a\nb\n"})
    git_repo.git("checkout", "--quiet", "-b", "feature")
    branch = git_repo.commit("feature", **{"a.txt": f"a\nT={fakes.GITHUB_TOKEN}\nb\n"})
    git_repo.git("checkout", "--quiet", "main")
    git_repo.commit("main", **{"c.txt": "c\n"})
    git_repo.git("merge", "--quiet", "--no-edit", "feature")
    findings = scan(GitSource(git_repo.path), [RegexDetector(load_rules())]).findings
    assert [f.commit for f in findings] == [branch]


def test_lines_added_while_resolving_a_merge_are_reported(git_repo: GitRepo) -> None:
    git_repo.commit("base", **{"a.txt": "a\n"})
    git_repo.git("checkout", "--quiet", "-b", "feature")
    git_repo.commit("feature", **{"b.txt": "b\n"})
    git_repo.git("checkout", "--quiet", "main")
    git_repo.commit("main", **{"c.txt": "c\n"})
    git_repo.git("merge", "--quiet", "--no-commit", "feature")
    git_repo.write("b.txt", f"b\nT={fakes.GITHUB_TOKEN}\n")
    evil = git_repo.commit("evil merge")
    findings = scan(GitSource(git_repo.path), [RegexDetector(load_rules())]).findings
    assert [(f.commit, f.path, f.line) for f in findings] == [(evil, "b.txt", 2)]


def test_binary_files_are_skipped_and_counted(git_repo: GitRepo) -> None:
    git_repo.commit(
        "one", **{"blob.bin": b"\x00\x01" + fakes.GITHUB_TOKEN.encode(), "a.txt": "x\n"}
    )
    source = GitSource(git_repo.path)
    assert [f.path for f in source] == ["a.txt"]
    assert (source.stats.scanned, source.stats.skipped_binary) == (1, 1)


def test_file_versions_adding_more_than_max_size_are_skipped(git_repo: GitRepo) -> None:
    git_repo.commit("one", **{"big.txt": "x" * 50 + "\n", "small.txt": "y\n"})
    source = GitSource(git_repo.path, max_file_size=20)
    assert [f.path for f in source] == ["small.txt"]
    assert source.stats.skipped_large == 1


def test_shallow_clone_is_scanned_and_flagged(git_repo: GitRepo, tmp_path: Path) -> None:
    git_repo.commit("one", **{"a.txt": "old\n"})
    git_repo.commit("two", **{"a.txt": "old\nnew\n"})
    clone = tmp_path / "clone"
    git_repo.git("clone", "--quiet", "--depth=1", git_repo.path.as_uri(), str(clone))
    source = GitSource(clone)
    assert [f.text for f in source] == ["old\nnew"]  # the boundary commit adds everything
    assert source.is_shallow()
    assert not GitSource(git_repo.path).is_shallow()


def test_max_commits_keeps_the_newest(git_repo: GitRepo) -> None:
    git_repo.commit("one", **{"a.txt": "1\n"})
    git_repo.commit("two", **{"b.txt": "2\n"})
    newest = git_repo.commit("three", **{"c.txt": "3\n"})
    source = GitSource(git_repo.path, max_commits=1)
    assert [f.commit for f in source] == [newest]
    assert source.stats.commits == 1


def test_since_skips_older_commits(git_repo: GitRepo) -> None:
    git_repo.commit("day 1", **{"a.txt": "1\n"})
    git_repo.commit("day 2", **{"b.txt": "2\n"})
    git_repo.commit("day 3", **{"c.txt": "3\n"})
    since = datetime(2024, 1, 2, tzinfo=UTC)
    assert [f.path for f in GitSource(git_repo.path, since=since)] == ["c.txt", "b.txt"]


def test_subfolder_limits_history_to_it(git_repo: GitRepo) -> None:
    git_repo.commit("one", **{"src__a.txt": "a\n", "doc__b.txt": "b\n"})
    assert [f.path for f in GitSource(git_repo.path / "src")] == ["src/a.txt"]


# --- Hardening against repository content and config (review findings) ---


def test_subfolder_scan_follows_merged_side_branches(git_repo: GitRepo) -> None:
    git_repo.commit("base", **{"sub__f.txt": "a\n", "other.txt": "o\n"})
    git_repo.git("checkout", "--quiet", "-b", "side")
    leak = git_repo.commit("leak", **{"sub__f.txt": f"a\nT={fakes.GITHUB_TOKEN}\n"})
    git_repo.commit("unleak", **{"sub__f.txt": "a\n"})
    git_repo.git("checkout", "--quiet", "main")
    git_repo.commit("main", **{"other.txt": "o\n2\n"})
    git_repo.git("merge", "--quiet", "--no-edit", "side")
    findings = scan(GitSource(git_repo.path / "sub"), [RegexDetector(load_rules())]).findings
    assert [f.commit for f in findings] == [leak]


def test_log_output_encoding_config_is_ignored(git_repo: GitRepo) -> None:
    git_repo.commit("leak", **{"a.env": f"T={fakes.GITHUB_TOKEN}\n"})
    git_repo.git("config", "i18n.logOutputEncoding", "UTF-16")
    findings = scan(GitSource(git_repo.path), [RegexDetector(load_rules())]).findings
    assert len(findings) == 1


def test_root_commit_is_scanned_even_with_show_root_off(git_repo: GitRepo) -> None:
    git_repo.commit("leak", **{"a.env": f"T={fakes.GITHUB_TOKEN}\n"})
    git_repo.git("config", "log.showRoot", "false")
    assert [f.path for f in GitSource(git_repo.path)] == ["a.env"]


def test_gitattributes_cannot_hide_text_files(git_repo: GitRepo) -> None:
    git_repo.commit("leak", **{".gitattributes": "* -diff\n", "a.env": f"T={fakes.GITHUB_TOKEN}\n"})
    source = GitSource(git_repo.path)
    findings = source.mark_removed(scan(source, [RegexDetector(load_rules())]).findings)
    assert [(f.path, f.removed_later) for f in findings] == [("a.env", False)]
    assert source.stats.skipped_binary == 0


def test_crlf_lines_keep_their_content_and_line(git_repo: GitRepo) -> None:
    git_repo.commit("one", **{"a.env": f"A=1\r\nT={fakes.GITHUB_TOKEN}\r\n"})
    (finding,) = scan(GitSource(git_repo.path), [RegexDetector(load_rules())]).findings
    assert (finding.line, finding.secret) == (2, fakes.GITHUB_TOKEN)


def test_octopus_merge_reports_only_lines_new_to_every_parent(git_repo: GitRepo) -> None:
    git_repo.commit("base", **{"a.txt": "a\n"})
    for branch in ("b1", "b2"):
        git_repo.git("checkout", "--quiet", "-b", branch, "main")
        git_repo.commit(branch, **{f"{branch}.txt": f"{branch}\n"})
    git_repo.git("checkout", "--quiet", "main")
    git_repo.git("merge", "--quiet", "--no-commit", "b1", "b2")
    git_repo.write("a.txt", f"a\nT={fakes.GITHUB_TOKEN}\n")
    evil = git_repo.commit("octopus")
    findings = scan(GitSource(git_repo.path), [RegexDetector(load_rules())]).findings
    assert [(f.commit, f.path, f.line) for f in findings] == [(evil, "a.txt", 2)]


def test_stopping_early_does_not_raise(git_repo: GitRepo) -> None:
    for day in range(3):
        git_repo.commit(f"c{day}", **{f"f{day}.txt": "x\n" * 2000})
    iterator = iter(GitSource(git_repo.path))
    next(iterator)
    iterator.close()  # type: ignore[attr-defined]


def test_secrets_are_not_passed_on_the_command_line(
    git_repo: GitRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    git_repo.commit("leak", **{"a.env": f"T={fakes.GITHUB_TOKEN}\n"})
    source = GitSource(git_repo.path)
    findings = scan(source, [RegexDetector(load_rules())]).findings
    commands: list[str] = []
    real_popen = git.cmd.Popen

    def spy(cmd: object, *args: object, **kwargs: object) -> subprocess.Popen:  # type: ignore[type-arg]
        commands.append(str(cmd))
        return real_popen(cmd, *args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(git.cmd, "Popen", spy)
    source.mark_removed(findings)
    assert commands
    assert not any(fakes.GITHUB_TOKEN in c for c in commands)


def test_overlapping_secrets_both_found_in_head(git_repo: GitRepo) -> None:
    git_repo.commit("one", **{"a.env": "K=abcFAKEXYZdef\n"})
    first = make_finding(commit="0" * 40, secret="abcFAKEXYZ", line_content="K=")
    second = make_finding(commit="0" * 40, secret="FAKEXYZdef", line_content="K=")
    marked = GitSource(git_repo.path).mark_removed([first, second])
    assert [f.removed_later for f in marked] == [False, False]
