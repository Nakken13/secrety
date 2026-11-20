"""Core data model shared by every detector, source and reporter."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum

_VISIBLE_EDGE = 4
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
    secret: str
    line_content: str
    method: DetectionMethod
    confidence: float
    commit: str | None = None

    def __post_init__(self) -> None:
        """Validate invariants that every consumer relies on."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")

    def masked(self) -> str:
        """Return the secret with only its first and last 4 characters visible.

        Secrets of 8 characters or fewer are fully hidden, since showing 8 of
        them would reveal everything.
        """
        n = len(self.secret)
        if n <= 2 * _VISIBLE_EDGE:
            return "*" * n
        hidden = "*" * (n - 2 * _VISIBLE_EDGE)
        return f"{self.secret[:_VISIBLE_EDGE]}{hidden}{self.secret[-_VISIBLE_EDGE:]}"

    @property
    def location(self) -> str:
        """``[sha:]path:line:column``, the format used by most linters."""
        prefix = f"{self.commit[:_SHORT_SHA]}:" if self.commit else ""
        return f"{prefix}{self.path}:{self.line}:{self.column}"

    @property
    def fingerprint(self) -> str:
        """Stable identifier usable for deduplication and baselines.

        It hashes the secret together with its location, so it never exposes
        the secret itself.
        """
        raw = f"{self.rule_id}|{self.path}|{self.line}|{self.column}|{self.secret}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
