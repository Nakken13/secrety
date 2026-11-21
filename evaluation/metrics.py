"""Score detections against the corpus ground truth.

A detection is a ``(path, line)`` location, whatever span a tool reports, so
secrety, gitleaks and trufflehog are scored the same way. Candidates never
share a line (see :mod:`evaluation.corpus`), so a location belongs to at most
one of them.

* **TP**: a secret candidate with at least one flagged line in its span.
* **FN**: a secret candidate with none.
* **FP**: a flagged location outside every secret span (a decoy, filler or
  anything else): precision is therefore measured over everything the tool
  says, not only over the decoys that were planted.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from evaluation.corpus import Candidate
from secrety.models import Finding

Location = tuple[str, int]


@dataclass(frozen=True)
class Scores:
    """Counts and the derived precision, recall and F1."""

    tp: int
    fp: int
    fn: int

    @property
    def precision(self) -> float:
        """Share of what the tool flagged that was a real secret."""
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        """Share of the planted secrets the tool found."""
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall."""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


def _spans(truth: Iterable[Candidate], label: str) -> dict[Location, Candidate]:
    return {
        (c.path, n): c for c in truth if c.label == label for n in range(c.line, c.end_line + 1)
    }


def score_locations(locations: Iterable[Location], truth: Sequence[Candidate]) -> Scores:
    """Score a set of flagged ``(path, line)`` locations."""
    secret_lines = _spans(truth, "secret")
    found = set(locations)
    hit = {id(secret_lines[loc]) for loc in found if loc in secret_lines}
    total = sum(1 for c in truth if c.label == "secret")
    fp = sum(1 for loc in found if loc not in secret_lines)
    return Scores(tp=len(hit), fp=fp, fn=total - len(hit))


def score(findings: Iterable[Finding], truth: Sequence[Candidate]) -> Scores:
    """Score secrety findings; findings on the same line count once."""
    return score_locations({(f.path, f.line) for f in findings}, truth)


def label_findings(findings: Sequence[Finding], truth: Sequence[Candidate]) -> list[int]:
    """Return 1 for each finding that sits on a secret, else 0 (training labels)."""
    secret_lines = _spans(truth, "secret")
    return [int((f.path, f.line) in secret_lines) for f in findings]


def family_report(
    findings: Iterable[Finding], truth: Sequence[Candidate]
) -> dict[str, tuple[int, int]]:
    """Return ``family -> (hits, total)``.

    For a secret family a hit is a secret found (recall); for a decoy family
    it is a decoy wrongly flagged (false-positive rate).
    """
    flagged = {(f.path, f.line) for f in findings}
    hits: dict[str, int] = defaultdict(int)
    totals: dict[str, int] = defaultdict(int)
    for c in truth:
        totals[c.family] += 1
        if any((c.path, n) in flagged for n in range(c.line, c.end_line + 1)):
            hits[c.family] += 1
    return {family: (hits[family], total) for family, total in sorted(totals.items())}


@dataclass(frozen=True)
class Row:
    """One compared configuration and its scores."""

    name: str
    scores: Scores
