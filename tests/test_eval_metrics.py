"""Scoring findings against the corpus ground truth."""

from __future__ import annotations

import pytest
from evaluation.corpus import Candidate
from evaluation.metrics import (
    family_report,
    label_findings,
    score,
    score_locations,
)

from secrety.models import DetectionMethod, Finding


def cand(path: str, line: int, label: str, family: str = "f", end: int | None = None) -> Candidate:
    return Candidate(path, line, end or line, label, family, "v")


def finding(path: str, line: int) -> Finding:
    return Finding(
        rule_id="r",
        description="d",
        path=path,
        line=line,
        column=1,
        secret="s",
        line_content="s",
        method=DetectionMethod.REGEX,
        confidence=0.5,
    )


TRUTH = [cand("a.py", 2, "secret"), cand("a.py", 5, "decoy"), cand("b.py", 3, "secret")]


def test_perfect_detection() -> None:
    s = score_locations({("a.py", 2), ("b.py", 3)}, TRUTH)
    assert (s.tp, s.fp, s.fn) == (2, 0, 0)
    assert s.precision == s.recall == s.f1 == 1.0


def test_decoy_and_stray_hits_are_false_positives() -> None:
    s = score_locations({("a.py", 2), ("a.py", 5), ("a.py", 9)}, TRUTH)
    assert (s.tp, s.fp, s.fn) == (1, 2, 1)
    assert s.precision == pytest.approx(1 / 3)
    assert s.recall == pytest.approx(1 / 2)
    assert s.f1 == pytest.approx(0.4)


def test_nothing_found_scores_zero_without_dividing_by_zero() -> None:
    s = score_locations(set(), TRUTH)
    assert (s.tp, s.fp, s.fn) == (0, 0, 2)
    assert s.precision == 0.0
    assert s.recall == 0.0
    assert s.f1 == 0.0


def test_duplicate_findings_on_one_location_count_once() -> None:
    s = score([finding("a.py", 2), finding("a.py", 2), finding("a.py", 2)], TRUTH)
    assert (s.tp, s.fp) == (1, 0)


def test_block_candidate_matches_on_any_of_its_lines() -> None:
    truth = [cand("k.pem", 1, "secret", end=6)]
    s = score_locations({("k.pem", 4)}, truth)
    assert (s.tp, s.fp, s.fn) == (1, 0, 0)


def test_two_hits_in_one_block_are_one_true_positive() -> None:
    truth = [cand("k.pem", 1, "secret", end=6)]
    s = score_locations({("k.pem", 1), ("k.pem", 2), ("k.pem", 3)}, truth)
    assert (s.tp, s.fp, s.fn) == (1, 0, 0)


def test_label_findings_marks_those_on_a_secret() -> None:
    found = [finding("a.py", 2), finding("a.py", 5), finding("z.py", 1)]
    assert label_findings(found, TRUTH) == [1, 0, 0]


def test_family_report_shows_recall_and_decoy_hits() -> None:
    truth = [
        cand("a.py", 1, "secret", "token"),
        cand("a.py", 2, "secret", "token"),
        cand("a.py", 3, "decoy", "sha"),
        cand("a.py", 4, "decoy", "uuid"),
    ]
    report = family_report([finding("a.py", 1), finding("a.py", 3)], truth)
    assert report["token"] == (1, 2)  # secrets found, secrets total
    assert report["sha"] == (1, 1)  # decoys flagged, decoys total
    assert report["uuid"] == (0, 1)
