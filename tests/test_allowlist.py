import pytest

from secrety.allowlist import (
    DEFAULT_ALLOWED_PATHS,
    Allowlist,
    glob_matches,
    inline_ignored,
)
from secrety.models import DetectionMethod, Finding


def make_finding(
    path: str = "src/app.py",
    line_content: str = 'password = "FAKE-value-EXAMPLE"',
    rule_id: str = "generic-password-assignment",
    also_matched: tuple[tuple[str, DetectionMethod], ...] = (),
) -> Finding:
    return Finding(
        rule_id=rule_id,
        description="test rule",
        path=path,
        line=1,
        column=13,
        secret="FAKE-value-EXAMPLE",
        line_content=line_content,
        method=DetectionMethod.REGEX,
        confidence=0.4,
        also_matched=also_matched,
    )


# --- glob semantics -------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "path"),
    [
        ("tests/**", "tests/test_cli.py"),
        ("tests/**", "tests/unit/deep/x.py"),
        ("**/tests/**", "tests/x.py"),  # ** matches zero folders
        ("**/tests/**", "pkg/sub/tests/x.py"),
        ("*.lock", "Cargo.lock"),  # no "/" in the pattern: any depth
        ("*.lock", "a/b/poetry.lock"),
        ("package-lock.json", "web/package-lock.json"),
        ("src/*.py", "src/app.py"),
        ("docs/?.md", "docs/a.md"),
    ],
)
def test_glob_matches(pattern: str, path: str) -> None:
    assert glob_matches(pattern, path)


@pytest.mark.parametrize(
    ("pattern", "path"),
    [
        ("src/*.py", "src/sub/app.py"),  # "*" never crosses "/"
        ("tests/**", "src/tests_helper.py"),
        ("tests/**", "mytests/x.py"),  # anchored at the root
        ("*.lock", "Cargo.lock.bak"),
        ("docs/?.md", "docs/ab.md"),
        ("**/tests/**", "contests/x.py"),  # whole folder names only
    ],
)
def test_glob_does_not_match(pattern: str, path: str) -> None:
    assert not glob_matches(pattern, path)


def test_glob_escapes_regex_characters() -> None:
    assert glob_matches("a+b.txt", "a+b.txt")
    assert not glob_matches("a+b.txt", "aab.txt")


def test_glob_is_case_insensitive() -> None:
    # Windows and macOS file systems are case-insensitive.
    assert glob_matches("tests/**", "Tests/x.py")


# --- path allowlist -------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "tests/fakes.py",
        "pkg/tests/test_x.py",
        "test/x.js",
        "src/__tests__/a.test.ts",
        "test_app.py",
        "app_test.go",
        "web/app.spec.ts",
        "package-lock.json",
        "yarn.lock",
        "poetry.lock",
        "uv.lock",
        "go.sum",
        "examples/demo.py",
        ".env.example",
        "config.sample",
    ],
)
def test_default_allowlist_covers_tests_lockfiles_and_examples(path: str) -> None:
    assert Allowlist().allows_path(path)


@pytest.mark.parametrize("path", ["src/app.py", ".env", "config/prod.yaml", "latest/x.py"])
def test_default_allowlist_keeps_real_code(path: str) -> None:
    assert not Allowlist().allows_path(path)


def test_extra_paths_add_to_defaults() -> None:
    allowlist = Allowlist(paths=("crew/**",))
    assert allowlist.allows_path("crew/notes.md")
    assert allowlist.allows_path("tests/x.py")


def test_defaults_can_be_turned_off() -> None:
    allowlist = Allowlist(paths=("crew/**",), use_defaults=False)
    assert not allowlist.allows_path("tests/x.py")
    assert allowlist.allows_path("crew/notes.md")
    assert allowlist.patterns == ("crew/**",)


def test_defaults_are_listed_first() -> None:
    assert Allowlist(paths=("x/**",)).patterns == (*DEFAULT_ALLOWED_PATHS, "x/**")


# --- inline ignore --------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        'password = "FAKE-value-EXAMPLE"  # secrety:ignore',
        'password = "FAKE-value-EXAMPLE"  // secrety:ignore',
        'password = "FAKE-value-EXAMPLE"  /* secrety:ignore */',
        'password = "FAKE-value-EXAMPLE"  <!-- secrety:ignore -->',
        'password = "FAKE-value-EXAMPLE"  -- secrety:ignore',
        "password: FAKE-value-EXAMPLE  ; SECRETY:IGNORE",
        'password = "FAKE-value-EXAMPLE"  # secrety:ignore[generic-password-assignment]',
        'x = "FAKE-value-EXAMPLE"  # secrety:ignore[other, generic-password-assignment]',
    ],
)
def test_inline_ignore_any_comment_style(line: str) -> None:
    assert inline_ignored(make_finding(line_content=line))


@pytest.mark.parametrize(
    "line",
    [
        'password = "FAKE-value-EXAMPLE"',
        'password = "FAKE-value-EXAMPLE"  # secrety:ignore[aws-access-key-id]',
        'password = "FAKE-value-EXAMPLE"  # secrety:ignored',
        'password = "FAKE-value-EXAMPLE"  # notsecrety:ignore',
        'password = "FAKE-value-EXAMPLE"  # secrety:ignore[]',
    ],
)
def test_inline_ignore_not_triggered(line: str) -> None:
    assert not inline_ignored(make_finding(line_content=line))


def test_inline_ignore_with_ids_follows_the_reported_rule() -> None:
    # Provider tokens nearly always trip entropy too, and the merged finding is
    # reported under the regex rule: naming that rule must be enough.
    merged = (("high-entropy-base64", DetectionMethod.ENTROPY),)
    reported = make_finding(
        line_content='p = "FAKE-value-EXAMPLE"  # secrety:ignore[generic-password-assignment]',
        also_matched=merged,
    )
    # Naming only a merged rule does not hide what the reported rule found.
    merged_only = make_finding(
        line_content='p = "FAKE-value-EXAMPLE"  # secrety:ignore[high-entropy-base64]',
        also_matched=merged,
    )
    bare = make_finding(line_content='p = "FAKE"  # secrety:ignore', also_matched=merged)
    assert inline_ignored(reported)
    assert not inline_ignored(merged_only)
    assert inline_ignored(bare)


# --- filtering ------------------------------------------------------------


def test_apply_splits_kept_and_suppressed() -> None:
    kept = make_finding(path="src/app.py")
    by_path = make_finding(path="tests/x.py")
    by_comment = make_finding(line_content='p = "FAKE-value-EXAMPLE"  # secrety:ignore')
    result = Allowlist().apply([kept, by_path, by_comment])
    assert result.kept == [kept]
    assert result.suppressed_by_path == 1
    assert result.suppressed_inline == 1


def test_apply_path_wins_over_inline_count() -> None:
    both = make_finding(path="tests/x.py", line_content='p = "FAKE"  # secrety:ignore')
    result = Allowlist().apply([both])
    assert (result.suppressed_by_path, result.suppressed_inline) == (1, 0)
