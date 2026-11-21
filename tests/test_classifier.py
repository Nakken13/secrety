import json
import math
from pathlib import Path
from typing import Any

import pytest

from secrety.classifier import (
    SUPPORTED_SCHEMA_VERSIONS,
    Classifier,
    ClassifierError,
    load_classifier,
)
from secrety.features import FEATURE_NAMES, extract
from secrety.models import DetectionMethod, Finding

N = len(FEATURE_NAMES)


def model_dict(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "schema_version": 1,
        "model_type": "logistic_regression",
        "feature_names": list(FEATURE_NAMES),
        "scaler": {"mean": [0.0] * N, "scale": [1.0] * N},
        "coef": [0.0] * N,
        "intercept": 0.0,
        "threshold": 0.5,
        "training": {"stub": True},
    }
    data.update(overrides)
    return data


def write_model(tmp_path: Path, data: dict[str, Any] | str) -> Path:
    path = tmp_path / "model.json"
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


def make_finding(secret: str = "FAKEaB3dE5gH7jK9mN1pQ2rS4", path: str = "src/app.py") -> Finding:
    line = f'api_key = "{secret}"'
    return Finding(
        rule_id="r",
        description="d",
        path=path,
        line=1,
        column=line.index(secret) + 1,
        secret=secret,
        line_content=line,
        method=DetectionMethod.REGEX,
        confidence=0.4,
    )


# --- inference ------------------------------------------------------------


def test_zero_model_scores_one_half(tmp_path: Path) -> None:
    model = load_classifier(write_model(tmp_path, model_dict()))
    assert model.probability(make_finding()) == pytest.approx(0.5)


def test_probability_is_scaled_logistic_regression(tmp_path: Path) -> None:
    # Golden value: p = sigmoid(sum(coef * (x - mean) / scale) + intercept).
    mean = [0.5] * N
    scale = [2.0] * N
    coef = [0.1 * (i + 1) * (-1) ** i for i in range(N)]
    model = load_classifier(
        write_model(
            tmp_path, model_dict(scaler={"mean": mean, "scale": scale}, coef=coef, intercept=-0.3)
        )
    )
    finding = make_finding()
    x = extract(finding)
    z = sum(c * (v - m) / s for c, v, m, s in zip(coef, x, mean, scale, strict=True)) - 0.3
    assert model.probability(finding) == pytest.approx(1 / (1 + math.exp(-z)), abs=1e-12)


def test_extreme_scores_do_not_overflow(tmp_path: Path) -> None:
    for intercept in (-1000.0, 1000.0):
        model = load_classifier(write_model(tmp_path, model_dict(intercept=intercept)))
        p = model.probability(make_finding())
        assert 0.0 <= p <= 1.0


def test_rescore_replaces_confidence_and_drops_below_threshold(tmp_path: Path) -> None:
    coef = [0.0] * N
    coef[FEATURE_NAMES.index("ext_doc")] = -10.0
    model = load_classifier(write_model(tmp_path, model_dict(coef=coef, intercept=1.0)))
    code = make_finding(path="src/app.py")
    doc = make_finding(path="README.md")
    result = model.rescore([code, doc])
    assert [f.path for f in result.kept] == ["src/app.py"]
    assert result.kept[0].confidence == pytest.approx(1 / (1 + math.exp(-1.0)))
    assert result.dropped == 1


def test_threshold_override(tmp_path: Path) -> None:
    model = load_classifier(write_model(tmp_path, model_dict()), threshold=0.6)
    assert model.threshold == 0.6
    assert model.rescore([make_finding()]).kept == []  # p = 0.5 < 0.6


def test_threshold_is_inclusive(tmp_path: Path) -> None:
    model = load_classifier(write_model(tmp_path, model_dict(threshold=0.5)))
    assert len(model.rescore([make_finding()]).kept) == 1


@pytest.mark.parametrize("threshold", [-0.1, 1.5, math.nan])
def test_threshold_override_out_of_range(tmp_path: Path, threshold: float) -> None:
    with pytest.raises(ClassifierError, match="threshold"):
        load_classifier(write_model(tmp_path, model_dict()), threshold=threshold)


# --- packaged model -------------------------------------------------------


def test_packaged_model_loads_and_is_a_stub() -> None:
    model = load_classifier()
    assert isinstance(model, Classifier)
    assert model.stub
    assert 0.0 <= model.probability(make_finding()) <= 1.0


def test_packaged_stub_ranks_obvious_cases() -> None:
    model = load_classifier()
    real = make_finding(secret="aB3dE5gH7jK9mN1pQ2rS4tUv", path="deploy/.env")
    placeholder = make_finding(secret="your-api-key-here-0000", path="README.md")
    assert model.probability(real) > model.probability(placeholder)


# --- validation on load ---------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"schema_version": 99}, "schema_version"),
        ({"schema_version": True}, "schema_version"),
        ({"model_type": "gbdt"}, "model_type"),
        ({"feature_names": list(reversed(FEATURE_NAMES))}, "feature_names"),
        ({"feature_names": list(FEATURE_NAMES[:-1])}, "feature_names"),
        ({"coef": [0.0] * (N - 1)}, "coef"),
        ({"coef": [True] + [0.0] * (N - 1)}, "coef"),
        ({"coef": ["1"] + [0.0] * (N - 1)}, "coef"),
        ({"scaler": {"mean": [0.0] * N}}, "scaler"),
        ({"scaler": {"mean": [0.0] * N, "scale": [0.0] * N}}, "scale"),
        ({"scaler": {"mean": [0.0] * N, "scale": [-1.0] * N}}, "scale"),
        ({"scaler": [1, 2]}, "scaler"),
        ({"intercept": None}, "intercept"),
        ({"threshold": 2.0}, "threshold"),
        ({"training": "x"}, "training"),
    ],
)
def test_invalid_model_is_rejected(tmp_path: Path, overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ClassifierError, match=message):
        load_classifier(write_model(tmp_path, model_dict(**overrides)))


def test_missing_key_is_rejected(tmp_path: Path) -> None:
    data = model_dict()
    del data["coef"]
    with pytest.raises(ClassifierError, match="coef"):
        load_classifier(write_model(tmp_path, data))


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ClassifierError, match="unknown"):
        load_classifier(write_model(tmp_path, model_dict(coeff=[])))


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_numbers_are_rejected(tmp_path: Path, token: str) -> None:
    # json.loads accepts these non-standard tokens: the loader must not.
    text = json.dumps(model_dict()).replace('"intercept": 0.0', f'"intercept": {token}')
    with pytest.raises(ClassifierError, match="intercept"):
        load_classifier(write_model(tmp_path, text))


def test_integers_are_accepted(tmp_path: Path) -> None:
    load_classifier(write_model(tmp_path, model_dict(intercept=1, coef=[0] * N)))


@pytest.mark.parametrize("text", ["{not json", "[]", ""])
def test_malformed_file_is_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(ClassifierError):
        load_classifier(write_model(tmp_path, text))


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ClassifierError, match="cannot be read"):
        load_classifier(tmp_path / "absent.json")


def test_error_names_the_file(tmp_path: Path) -> None:
    path = write_model(tmp_path, model_dict(model_type="x"))
    with pytest.raises(ClassifierError, match=r"model.json"):
        load_classifier(path)


def test_classifier_error_is_a_value_error() -> None:
    assert issubclass(ClassifierError, ValueError)
    assert 1 in SUPPORTED_SCHEMA_VERSIONS


def test_huge_integer_is_rejected_not_crashing(tmp_path: Path) -> None:
    text = json.dumps(model_dict()).replace('"intercept": 0.0', f'"intercept": {10**400}')
    with pytest.raises(ClassifierError, match="intercept"):
        load_classifier(write_model(tmp_path, text))


def test_non_finite_score_keeps_the_finding(tmp_path: Path) -> None:
    # A tiny scale times a huge weight overflows to inf - inf = NaN: never
    # drop a finding on a score that is not a number.
    coef = [1e308, -1e308] + [0.0] * (N - 2)
    scale = [1e-300] * N
    model = load_classifier(
        write_model(tmp_path, model_dict(coef=coef, scaler={"mean": [0.0] * N, "scale": scale}))
    )
    assert model.probability(make_finding()) == 1.0
