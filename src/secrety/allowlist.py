"""Drop findings the user has declared harmless: allowed paths and inline ignores.

Filtering runs after detection, on findings, so it works the same for a
folder scan and a Git history scan, and no detector needs to know about it.
Every suppressed finding is counted: nothing is hidden silently.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache

from secrety.models import Finding

# Test code, dependency lockfiles (integrity hashes look random) and example
# files are the usual sources of fake or public values. A real secret
# committed there is still possible: ``use_defaults=False`` scans them too.
DEFAULT_ALLOWED_PATHS: tuple[str, ...] = (
    # test folders and files
    "**/tests/**",
    "**/test/**",
    "**/__tests__/**",
    "test_*.py",
    "*_test.py",
    "*_test.go",
    "*.test.js",
    "*.test.ts",
    "*.spec.js",
    "*.spec.ts",
    # lockfiles
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
    "go.sum",
    # examples and templates
    "**/examples/**",
    "**/example/**",
    "*.example",
    "*.sample",
)

# "secrety:ignore" or "secrety:ignore[rule-a, rule-b]", anywhere on the line,
# so it works after any comment marker (#, //, /* */, <!-- -->, --, ;).
_IGNORE = re.compile(r"(?<![\w-])secrety:ignore(?![\w-])(?:\[([^\]]*)\])?", re.IGNORECASE)


def _glob_to_regex(pattern: str) -> str:
    """Translate a glob into a regex matching a whole ``/``-separated path.

    ``*`` and ``?`` stay inside one path segment; ``**`` spans folders
    (``**/`` matches zero or more of them). A pattern without ``/`` matches
    the file name at any depth, as in ``.gitignore``.
    """
    if "/" not in pattern:
        pattern = "**/" + pattern
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:[^/]*/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return "".join(out)


@lru_cache(maxsize=256)
def _compile(pattern: str) -> re.Pattern[str]:
    """Compile ``pattern`` once; allowlists are small and reused for every finding."""
    return re.compile(_glob_to_regex(pattern), re.IGNORECASE)


def glob_matches(pattern: str, path: str) -> bool:
    """Return True if ``path`` (relative, ``/`` separators) matches ``pattern``.

    Matching ignores case: Windows and macOS file systems do.
    """
    return _compile(pattern).fullmatch(path) is not None


def inline_ignored(finding: Finding) -> bool:
    """Return True if the finding's line carries a ``secrety:ignore`` marker.

    A bare marker ignores every finding on the line. With rule ids
    (``secrety:ignore[rule-a,rule-b]``) the finding is ignored when the ids
    include the rule it is *reported* under. Rules merged into it
    (:attr:`~secrety.models.Finding.also_matched`) flagged the same span, so
    they are covered too; naming only a merged rule (typically the entropy
    one) does not hide what the reported rule, a known format, found.
    """
    reported = finding.rule_id.lower()
    for match in _IGNORE.finditer(finding.line_content):
        listed = match.group(1)
        if listed is None:
            return True
        if reported in {part.strip().lower() for part in listed.split(",")}:
            return True
    return False


@dataclass(frozen=True, slots=True)
class FilterResult:
    """Findings left after filtering, and how many each filter removed."""

    kept: list[Finding]
    suppressed_by_path: int = 0
    suppressed_inline: int = 0


@dataclass(frozen=True, slots=True)
class Allowlist:
    """Paths whose findings are dropped, on top of inline ``secrety:ignore`` markers.

    Attributes:
        paths: Extra globs (see :func:`glob_matches`), added to the defaults.
        use_defaults: Include :data:`DEFAULT_ALLOWED_PATHS`.
    """

    paths: tuple[str, ...] = ()
    use_defaults: bool = True
    patterns: tuple[str, ...] = field(init=False)

    def __post_init__(self) -> None:
        """Freeze the effective pattern list, defaults first."""
        defaults = DEFAULT_ALLOWED_PATHS if self.use_defaults else ()
        object.__setattr__(self, "patterns", (*defaults, *self.paths))

    def allows_path(self, path: str) -> bool:
        """Return True if findings in ``path`` are dropped."""
        return any(glob_matches(pattern, path) for pattern in self.patterns)

    def apply(self, findings: Iterable[Finding]) -> FilterResult:
        """Split ``findings`` into kept ones and counts of suppressed ones.

        The path is checked first: a finding in an allowed file counts as a
        path suppression even if its line also has a marker.
        """
        kept: list[Finding] = []
        by_path = inline = 0
        for finding in findings:
            if self.allows_path(finding.path):
                by_path += 1
            elif inline_ignored(finding):
                inline += 1
            else:
                kept.append(finding)
        return FilterResult(kept=kept, suppressed_by_path=by_path, suppressed_inline=inline)
