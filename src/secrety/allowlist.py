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

from secrety.models import DetectionMethod, Finding

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
# so it works after any comment marker (#, //, /* */, <!-- -->, --, ;). Group
# 1 is "[" when ids follow, group 2 the ids, group 3 the closing "]".
_IGNORE = re.compile(r"(?<![\w-])secrety:ignore(?![\w-])(?:\s*(\[)([^\]\n]*)(\])?)?", re.IGNORECASE)


def _segment_matches(pattern: str, name: str) -> bool:
    """Match one path segment against ``*`` / ``?`` wildcards, without backtracking.

    The classic two-pointer algorithm: on a mismatch, only the last ``*`` is
    retried, one character further. Cost is at most ``len(pattern) *
    len(name)``, so a pattern from an untrusted ``.secrety.toml`` such as
    ``*a*a*a*a*b`` cannot stall the scan (a translated regex backtracks
    exponentially on it).
    """
    p = n = 0
    star = -1
    resume = 0
    while n < len(name):
        if p < len(pattern) and pattern[p] in ("?", name[n]):
            p += 1
            n += 1
        elif p < len(pattern) and pattern[p] == "*":
            star, resume = p, n
            p += 1
        elif star != -1:
            resume += 1
            p, n = star + 1, resume
        else:
            return False
    return pattern[p:].strip("*") == ""


@lru_cache(maxsize=256)
def _segments(pattern: str) -> tuple[str, ...]:
    r"""Normalise a glob into lowercase path segments, ``.gitignore`` style.

    ``\`` becomes ``/``; a leading ``/`` anchors at the root; a pattern with
    no other ``/`` matches at any depth (``**/`` is prepended); a trailing
    ``/`` is dropped (matching a folder already covers its content); runs of
    ``**`` collapse into one.
    """
    pattern = pattern.replace("\\", "/").lower()
    if pattern.startswith("/"):
        pattern = pattern.lstrip("/")
    elif "/" not in pattern.rstrip("/"):
        pattern = "**/" + pattern
    segments: list[str] = []
    for segment in pattern.split("/"):
        if segment and not (segment == "**" and segments and segments[-1] == "**"):
            segments.append(segment)
    return tuple(segments)


def glob_matches(pattern: str, path: str) -> bool:
    """Return True if ``path`` (relative, ``/`` separators) matches ``pattern``.

    ``*`` and ``?`` stay inside one segment, ``**`` spans folders (zero or
    more). As in ``.gitignore``, a pattern that matches a folder matches
    everything inside it (``vendor`` matches ``vendor/a.py``). Matching
    ignores case: Windows and macOS file systems do.
    """
    parts = path.lower().split("/")
    # Indices into ``parts`` reachable after matching the segments so far.
    states = {0}
    for segment in _segments(pattern):
        if segment == "**":
            states = set(range(min(states), len(parts) + 1))
        else:
            states = {
                i + 1 for i in states if i < len(parts) and _segment_matches(segment, parts[i])
            }
        if not states:
            return False
    # Matched the whole path (a file) or a prefix of it (a folder holding it).
    return max(states) >= 1


@lru_cache(maxsize=4096)
def _allowed(patterns: tuple[str, ...], path: str) -> bool:
    """Cached :meth:`Allowlist.allows_path`: a file often has several findings."""
    return any(glob_matches(pattern, path) for pattern in patterns)


def inline_ignored(finding: Finding) -> bool:
    """Return True if the finding's line carries a ``secrety:ignore`` marker.

    A bare marker ignores every finding on the line. With rule ids
    (``secrety:ignore[rule-a,rule-b]``) the finding is ignored when the ids
    include the rule it is reported under and every other *regex* rule
    merged into it (:attr:`~secrety.models.Finding.also_matched`). Merged
    entropy findings flag the same value and need not be named; another
    known format overlapping it must be. A malformed marker (``[`` never
    closed) ignores nothing: a typo must not widen the suppression.
    """
    needed = {finding.rule_id.lower()} | {
        rule_id.lower()
        for rule_id, method in finding.also_matched
        if method is DetectionMethod.REGEX
    }
    for match in _IGNORE.finditer(finding.line_content):
        opened, listed, closed = match.groups()
        if opened is None:
            return True
        if closed is not None and needed <= {part.strip().lower() for part in listed.split(",")}:
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
        inline_ignore: Honour ``secrety:ignore`` markers. Turn it off to scan
            code you do not trust: its markers would hide its own findings.
    """

    paths: tuple[str, ...] = ()
    use_defaults: bool = True
    inline_ignore: bool = True
    patterns: tuple[str, ...] = field(init=False)

    def __post_init__(self) -> None:
        """Freeze the effective pattern list, defaults first."""
        defaults = DEFAULT_ALLOWED_PATHS if self.use_defaults else ()
        object.__setattr__(self, "patterns", (*defaults, *self.paths))

    def allows_path(self, path: str) -> bool:
        """Return True if findings in ``path`` are dropped."""
        return _allowed(self.patterns, path)

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
            elif self.inline_ignore and inline_ignored(finding):
                inline += 1
            else:
                kept.append(finding)
        return FilterResult(kept=kept, suppressed_by_path=by_path, suppressed_inline=inline)
