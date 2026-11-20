"""Core data model shared by every detector, source and reporter."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

_MAX_VISIBLE_EDGE = 4
_MIN_LENGTH_TO_SHOW_EDGES = 20
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
        is what a reader needs to recognise the key type.
        """
        n = len(self.secret)
        if n < _MIN_LENGTH_TO_SHOW_EDGES:
            return "*" * n
        edge = min(_MAX_VISIBLE_EDGE, n // 8)
        return f"{self.secret[:edge]}{'*' * (n - 2 * edge)}{self.secret[-edge:]}"

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
