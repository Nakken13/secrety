"""Training the classifier on the corpus and exporting it to the runtime format."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("sklearn")

from evaluation.corpus import FILES_DIR, generate_corpus, load_ground_truth
from evaluation.detect import run_variant
from evaluation.export_model import export_model
from evaluation.train import (
    build_training_set,
    choose_threshold,
    to_classifier,
    train,
)

from secrety.classifier import load_classifier
from secrety.features import FEATURE_NAMES


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("train-corpus")
    generate_corpus(root, seed=1, split="train", n_files=60)
    return root


def test_training_set_uses_the_runtime_features(corpus: Path) -> None:
    findings, x, y = build_training_set(corpus)
    assert len(findings) == len(x) == len(y)
    assert all(len(row) == len(FEATURE_NAMES) for row in x)
    assert set(y) == {0, 1}


def test_training_is_reproducible(corpus: Path) -> None:
    _, x, y = build_training_set(corpus)
    a_scaler, a_model = train(x, y)
    b_scaler, b_model = train(x, y)
    assert list(a_model.coef_[0]) == list(b_model.coef_[0])
    assert list(a_scaler.mean_) == list(b_scaler.mean_)


def test_pure_python_probability_matches_sklearn(corpus: Path, tmp_path: Path) -> None:
    findings, x, y = build_training_set(corpus)
    scaler, model = train(x, y)
    path = tmp_path / "classifier.json"
    export_model(scaler, model, 0.5, path, dataset="unit", n_samples=len(y), metrics={})
    loaded = load_classifier(path)
    expected = model.predict_proba(scaler.transform(x))[:, 1]
    for finding, p in zip(findings, expected, strict=True):
        assert loaded.probability(finding) == pytest.approx(p, abs=1e-9)


def test_export_writes_a_trained_model_record(corpus: Path, tmp_path: Path) -> None:
    _, x, y = build_training_set(corpus)
    scaler, model = train(x, y)
    path = tmp_path / "classifier.json"
    export_model(scaler, model, 0.4, path, dataset="unit", n_samples=len(y), metrics={"f1": 0.9})
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["feature_names"] == list(FEATURE_NAMES)
    assert data["threshold"] == 0.4
    assert data["training"]["stub"] is False
    assert data["training"]["dataset"] == "unit"
    assert data["training"]["n_samples"] == len(y)
    assert data["training"]["metrics"] == {"f1": 0.9}
    assert data["training"]["sklearn_version"]
    assert not load_classifier(path).stub


def test_threshold_is_chosen_on_the_grid_and_in_range(corpus: Path) -> None:
    _, x, y = build_training_set(corpus)
    scaler, model = train(x, y)
    truth = load_ground_truth(corpus)
    findings = run_variant(corpus / FILES_DIR, "combined")
    threshold, scores = choose_threshold(scaler, model, findings, truth)
    assert scores.f1 > 0
    assert 0.05 <= threshold <= 0.95
    assert to_classifier(scaler, model, threshold).threshold == threshold
