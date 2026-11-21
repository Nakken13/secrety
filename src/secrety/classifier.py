"""Rescore findings with the packaged logistic-regression model.

The model is plain JSON (``data/classifier.json``): a standard scaler and
logistic-regression coefficients, evaluated here in pure Python. No pickle is
ever loaded and scikit-learn is not a runtime dependency. The format and the
checks below are recorded in ``docs/decisions/0001-classifier-format.md``.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from importlib.resources import files
from pathlib import Path
from typing import Any

from secrety.features import FEATURE_NAMES, extract
from secrety.models import Finding

SUPPORTED_SCHEMA_VERSIONS = frozenset({1})
MODEL_TYPE = "logistic_regression"
_PACKAGED_MODEL = "data/classifier.json"
_Fail = Callable[[str], "ClassifierError"]
_KEYS = frozenset(
    {
        "schema_version",
        "model_type",
        "feature_names",
        "scaler",
        "coef",
        "intercept",
        "threshold",
        "training",
    }
)


class ClassifierError(ValueError):
    """Raised when a model file is unreadable or does not match the schema."""


@dataclass(frozen=True, slots=True)
class RescoreResult:
    """Findings at or above the threshold, rescored, and how many were dropped."""

    kept: list[Finding]
    dropped: int


@dataclass(frozen=True, slots=True)
class Classifier:
    """A validated logistic-regression model over :data:`~secrety.features.FEATURE_NAMES`.

    Attributes:
        mean: Scaler mean, one value per feature.
        scale: Scaler standard deviation, one value per feature (all > 0).
        coef: Logistic-regression weights, one per feature.
        intercept: Logistic-regression bias.
        threshold: Probability at or above which a finding is kept.
        stub: ``True`` for the hand-set placeholder model shipped before training.
    """

    mean: tuple[float, ...]
    scale: tuple[float, ...]
    coef: tuple[float, ...]
    intercept: float
    threshold: float
    stub: bool = False

    def probability(self, finding: Finding) -> float:
        """Return the model's probability that ``finding`` is a real secret."""
        z = self.intercept + sum(
            c * (x - m) / s
            for c, x, m, s in zip(self.coef, extract(finding), self.mean, self.scale, strict=True)
        )
        # Numerically stable sigmoid: exp() of a large positive number overflows.
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        e = math.exp(z)
        return e / (1.0 + e)

    def rescore(self, findings: Iterable[Finding]) -> RescoreResult:
        """Replace each confidence by the model probability; drop those below threshold."""
        kept: list[Finding] = []
        dropped = 0
        for finding in findings:
            p = self.probability(finding)
            if p >= self.threshold:
                kept.append(replace(finding, confidence=p))
            else:
                dropped += 1
        return RescoreResult(kept=kept, dropped=dropped)


def load_classifier(path: Path | None = None, threshold: float | None = None) -> Classifier:
    """Load and validate a model: ``path``, or the one packaged with secrety.

    Args:
        path: Model file; ``None`` loads ``secrety/data/classifier.json``.
        threshold: Overrides the threshold stored in the model.

    Raises:
        ClassifierError: Unreadable file, invalid JSON, or any schema check failing.
    """
    name = str(path) if path is not None else f"secrety/{_PACKAGED_MODEL}"
    try:
        if path is None:
            text = files("secrety").joinpath(_PACKAGED_MODEL).read_text(encoding="utf-8")
        else:
            text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ClassifierError(f"{name}: cannot be read: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ClassifierError(f"{name}: not valid JSON: {exc}") from exc
    return _parse(data, name, threshold)


def _parse(data: Any, name: str, threshold: float | None) -> Classifier:
    """Check every field of the decoded JSON (see the decision record)."""

    def fail(message: str) -> ClassifierError:
        return ClassifierError(f"{name}: {message}")

    if not isinstance(data, dict):
        raise fail("the model must be a JSON object")
    missing = sorted(_KEYS - data.keys())
    if missing:
        raise fail(f"missing key(s) {missing}")
    unknown = sorted(data.keys() - _KEYS)
    if unknown:
        raise fail(f"unknown key(s) {unknown}")
    version = data["schema_version"]
    if isinstance(version, bool) or version not in SUPPORTED_SCHEMA_VERSIONS:
        raise fail(
            f"schema_version {version!r} is not supported "
            f"(supported: {sorted(SUPPORTED_SCHEMA_VERSIONS)})"
        )
    if data["model_type"] != MODEL_TYPE:
        raise fail(f"model_type must be {MODEL_TYPE!r}, got {data['model_type']!r}")
    if data["feature_names"] != list(FEATURE_NAMES):
        raise fail(
            "feature_names differ from secrety.features.FEATURE_NAMES: "
            "the model was trained on other features and must be re-exported"
        )
    scaler = data["scaler"]
    if not isinstance(scaler, dict) or set(scaler) != {"mean", "scale"}:
        raise fail("scaler must be an object with exactly 'mean' and 'scale'")
    mean = _vector(scaler["mean"], "scaler.mean", fail)
    scale = _vector(scaler["scale"], "scaler.scale", fail)
    if any(s <= 0 for s in scale):
        raise fail("scaler.scale values must all be > 0")
    coef = _vector(data["coef"], "coef", fail)
    intercept = _number(data["intercept"], "intercept", fail)
    stored = _number(data["threshold"], "threshold", fail)
    chosen = stored if threshold is None else _number(threshold, "threshold", fail)
    if not 0.0 <= chosen <= 1.0:
        raise fail(f"threshold must be in [0, 1], got {chosen}")
    training = data["training"]
    if not isinstance(training, dict):
        raise fail("training must be an object")
    return Classifier(
        mean=mean,
        scale=scale,
        coef=coef,
        intercept=intercept,
        threshold=chosen,
        stub=training.get("stub") is True,
    )


def _number(value: Any, field: str, fail: _Fail) -> float:
    """Return ``value`` as a finite float; booleans and strings are rejected."""
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        raise fail(f"{field} must be a finite number, got {value!r}")
    return float(value)


def _vector(values: Any, field: str, fail: _Fail) -> tuple[float, ...]:
    """Return one finite float per feature, or raise."""
    if not isinstance(values, Sequence) or isinstance(values, str):
        raise fail(f"{field} must be a list of numbers")
    if len(values) != len(FEATURE_NAMES):
        raise fail(f"{field} has {len(values)} values, expected {len(FEATURE_NAMES)}")
    return tuple(_number(v, f"{field}[{i}]", fail) for i, v in enumerate(values))
