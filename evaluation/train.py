"""Train the false-positive classifier on the synthetic corpus.

Reproducible command (from the repository root)::

    python -m evaluation.train --output evaluation/results/classifier.json

Rows are secrety's own merged findings on the train corpus, labelled by the
ground truth, with features from :func:`secrety.features.extract`: the model
sees at training time exactly what it sees when scanning. The threshold is
chosen on a separate validation corpus (another seed, same families); the test
corpus is never touched here.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from evaluation.corpus import (
    DEFAULT_FILES,
    FILES_DIR,
    TRAIN_SEED,
    Candidate,
    generate_corpus,
    load_ground_truth,
)
from evaluation.detect import run_variant
from evaluation.export_model import export_model
from evaluation.metrics import Scores, label_findings, score
from secrety.classifier import Classifier
from secrety.features import extract
from secrety.models import Finding

VALIDATION_SEED = 3
THRESHOLD_GRID = tuple(round(0.05 * i, 2) for i in range(1, 20))


def build_training_set(
    corpus_dir: Path,
) -> tuple[list[Finding], list[tuple[float, ...]], list[int]]:
    """Return the findings of ``corpus_dir``, their feature rows and their 0/1 labels."""
    findings = run_variant(corpus_dir / FILES_DIR, "combined")
    labels = label_findings(findings, load_ground_truth(corpus_dir))
    return findings, [extract(f) for f in findings], labels


def train(x: list[tuple[float, ...]], y: list[int]) -> tuple[StandardScaler, LogisticRegression]:
    """Fit the scaler and the logistic regression (deterministic: lbfgs, no sampling)."""
    scaler = StandardScaler().fit(np.array(x))
    model = LogisticRegression(max_iter=1000).fit(scaler.transform(np.array(x)), y)
    return scaler, model


def to_classifier(scaler: Any, model: Any, threshold: float) -> Classifier:
    """Build the runtime classifier from fitted sklearn objects, without a file round trip."""
    return Classifier(
        mean=tuple(float(v) for v in scaler.mean_),
        scale=tuple(float(v) for v in scaler.scale_),
        coef=tuple(float(v) for v in model.coef_[0]),
        intercept=float(model.intercept_[0]),
        threshold=threshold,
    )


def choose_threshold(
    scaler: Any, model: Any, findings: list[Finding], truth: list[Candidate]
) -> tuple[float, Scores]:
    """Return the grid threshold that maximises end-to-end F1 on ``findings``, with its scores."""
    best, best_scores = THRESHOLD_GRID[0], Scores(0, 0, 0)
    for threshold in THRESHOLD_GRID:
        kept = to_classifier(scaler, model, threshold).rescore(findings).kept
        scores = score(kept, truth)
        if scores.f1 > best_scores.f1 or best_scores == Scores(0, 0, 0):
            best, best_scores = threshold, scores
    return best, best_scores


def main(argv: list[str] | None = None) -> None:
    """Generate the train and validation corpora, train, and write the model."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--files", type=int, default=DEFAULT_FILES)
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as tmp:
        train_dir, val_dir = Path(tmp) / "train", Path(tmp) / "validation"
        generate_corpus(train_dir, TRAIN_SEED, "train", args.files)
        val_truth = generate_corpus(val_dir, VALIDATION_SEED, "train", args.files)
        _, x, y = build_training_set(train_dir)
        scaler, model = train(x, y)
        val_findings = run_variant(val_dir / FILES_DIR, "combined")
        threshold, val = choose_threshold(scaler, model, val_findings, val_truth)
    export_model(
        scaler,
        model,
        threshold,
        args.output,
        dataset=(
            f"synthetic seed {TRAIN_SEED}, {args.files} files; validation seed {VALIDATION_SEED}"
        ),
        n_samples=len(y),
        metrics={
            "validation_precision": round(val.precision, 4),
            "validation_recall": round(val.recall, 4),
            "validation_f1": round(val.f1, 4),
        },
    )
    print(f"wrote {args.output} (threshold {threshold}, validation F1 {val.f1:.3f})")


if __name__ == "__main__":
    main()
