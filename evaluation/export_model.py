"""Write a trained scaler + logistic regression to secrety's JSON model format.

The schema is fixed by ``docs/decisions/0001-classifier-format.md``; the
loader refuses a file whose feature list differs from
:data:`secrety.features.FEATURE_NAMES`, which this module writes from the same
constant so the two cannot drift.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import sklearn

from secrety.features import FEATURE_NAMES

SCHEMA_VERSION = 1


def export_model(
    scaler: Any,
    model: Any,
    threshold: float,
    path: Path,
    *,
    dataset: str,
    n_samples: int,
    metrics: dict[str, float],
    trained_at: str | None = None,
) -> None:
    """Write a fitted ``StandardScaler`` and ``LogisticRegression`` to ``path``."""
    record = {
        "schema_version": SCHEMA_VERSION,
        "model_type": "logistic_regression",
        "feature_names": list(FEATURE_NAMES),
        "scaler": {
            "mean": [float(v) for v in scaler.mean_],
            "scale": [float(v) for v in scaler.scale_],
        },
        "coef": [float(v) for v in model.coef_[0]],
        "intercept": float(model.intercept_[0]),
        "threshold": float(threshold),
        "training": {
            "stub": False,
            "trained_at": trained_at or datetime.now(UTC).date().isoformat(),
            "sklearn_version": sklearn.__version__,
            "dataset": dataset,
            "n_samples": n_samples,
            "metrics": metrics,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
