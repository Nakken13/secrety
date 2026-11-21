"""Running secrety's own detectors on a generated corpus."""

from __future__ import annotations

from pathlib import Path

import pytest
from evaluation.corpus import FILES_DIR, generate_corpus
from evaluation.detect import VARIANTS, run_variant

from secrety.classifier import load_classifier
from secrety.models import DetectionMethod


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("corpus")
    generate_corpus(root, seed=1, split="train", n_files=30)
    return root / FILES_DIR


def locations(findings: list) -> set[tuple[str, int]]:
    return {(f.path, f.line) for f in findings}


def test_variants_are_the_four_compared_configurations() -> None:
    assert VARIANTS == ("regex", "entropy", "combined", "combined+classifier")


def test_regex_variant_only_reports_regex_findings(corpus: Path) -> None:
    findings = run_variant(corpus, "regex")
    assert findings
    assert {f.method for f in findings} == {DetectionMethod.REGEX}


def test_entropy_variant_only_reports_entropy_findings(corpus: Path) -> None:
    findings = run_variant(corpus, "entropy")
    assert findings
    assert {f.method for f in findings} == {DetectionMethod.ENTROPY}


def test_combined_covers_both_methods(corpus: Path) -> None:
    combined = locations(run_variant(corpus, "combined"))
    assert locations(run_variant(corpus, "regex")) <= combined
    assert locations(run_variant(corpus, "entropy")) <= combined


def test_the_path_allowlist_does_not_hide_corpus_files(corpus: Path) -> None:
    # corpus folders are named tests/, docs/...: the default path allowlist would drop them
    paths = {f.path.split("/")[0] for f in run_variant(corpus, "combined")}
    assert "tests" in paths


def test_classifier_variant_never_adds_findings(corpus: Path) -> None:
    combined = locations(run_variant(corpus, "combined"))
    rescored = locations(run_variant(corpus, "combined+classifier", load_classifier()))
    assert rescored <= combined


def test_classifier_variant_needs_a_model(corpus: Path) -> None:
    with pytest.raises(ValueError, match="classifier"):
        run_variant(corpus, "combined+classifier")


def test_unknown_variant_is_rejected(corpus: Path) -> None:
    with pytest.raises(ValueError, match="variant"):
        run_variant(corpus, "magic")
