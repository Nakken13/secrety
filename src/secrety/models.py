"""Core data model shared by every detector, source and reporter."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

_MAX_VISIBLE_EDGE = 4
_MIN_LENGTH_TO_SHOW_EDGES = 20
_MAX_MASK_STARS = 120
_SHORT_SHA = 12


class DetectionMethod(StrEnum):
    """How a finding was produced."""

    REGEX = "regex"
    ENTROPY = "entropy"


@dataclass(frozen=True, slots=True)
class Finding:
    """A potential secret found in a file (or in a file at a given commit).

    Attributes:
        rule_id: Identifier of the rule that matched (e.g. ``aws-access-key-id``).
        description: Human-readable name of the rule.
        path: File path, relative to the scan root, with ``/`` separators.
        line: 1-based line number.
        column: 1-based column where the secret starts.
        secret: The raw secret value. Never print it directly: use :meth:`masked`.
        line_content: The full line, for context.
        method: Detection method that produced this finding.
        confidence: Score in ``[0, 1]``; higher means more likely a real secret.
        commit: Commit SHA when the finding comes from Git history, else ``None``.
        author: ``Name <email>`` of the commit author (Git history only).
        date: Author date of the commit, ISO 8601 (Git history only).
        removed_later: For Git history, ``True`` when the secret no longer
            appears anywhere in ``HEAD`` (it lives only in history), ``False``
            when it is still there; ``None`` when not checked.
        also_matched: ``(rule_id, method)`` of the other findings merged into
            this one because they flagged the same place (see
            :func:`secrety.scanner.merge_duplicates`).
    """

    rule_id: str
    description: str
    path: str
    line: int
    column: int
    secret: str = field(repr=False)
    line_content: str = field(repr=False)
    method: DetectionMethod
    confidence: float
    commit: str | None = None
    author: str | None = None
    date: str | None = None
    removed_later: bool | None = None
    also_matched: tuple[tuple[str, DetectionMethod], ...] = ()

    def __post_init__(self) -> None:
        """Validate invariants that every consumer relies on."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")

    def masked(self) -> str:
        """Return the secret with at most a quarter of it visible.

        Secrets shorter than 20 characters (typically passwords) are fully
        hidden. Longer ones keep up to 4 characters at each edge, never more
        than ``length // 8`` per edge, so at most 25 % is shown. The visible
        prefix is usually a public marker such as ``ghp_`` or ``AKIA``, which
        is what a reader needs to recognise the key type. At most 120
        asterisks are printed, so a huge token (an embedded data URI) does not
        flood the terminal.
        """
        n = len(self.secret)
        if n < _MIN_LENGTH_TO_SHOW_EDGES:
            return "*" * n
        edge = min(_MAX_VISIBLE_EDGE, n // 8)
        return (
            f"{self.secret[:edge]}{'*' * min(n - 2 * edge, _MAX_MASK_STARS)}{self.secret[-edge:]}"
        )

    @property
    def methods(self) -> tuple[DetectionMethod, ...]:
        """Every method that flagged this place, the reported one first."""
        return tuple(dict.fromkeys([self.method, *(m for _, m in self.also_matched)]))

    @property
    def location(self) -> str:
        """``[sha:]path:line:column``, the format used by most linters."""
        prefix = f"{self.commit[:_SHORT_SHA]}:" if self.commit else ""
        return f"{prefix}{self.path}:{self.line}:{self.column}"

    @property
    def fingerprint(self) -> str:
        """Stable identifier usable for deduplication and baselines.

        Built from the rule, path, commit and the line with the secret cut
        out. Two properties follow:

        * the secret itself is never hashed, so a fingerprint published in a
          JSON/SARIF report cannot be brute-forced back into a short password;
        * line and column numbers are left out, so the fingerprint survives
          code being added above the secret.
        """
        context = self.line_content.replace(self.secret, "").strip()
        raw = f"{self.rule_id}|{self.path}|{self.commit or ''}|{context}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
