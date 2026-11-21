# 0001 — Classifier model format: versioned JSON, pure-Python inference

- Status: accepted
- Date: 2026-11-21
- Task: 04 (false-positive reduction), consumed by 07 (training)

## Context

secrety rescores each finding with a classifier trained in task 07 on a
labelled corpus (scikit-learn, evaluation only). The trained model has to ship
inside the package and be loaded by the CLI, the pre-commit hook and the
GitHub Action. Runtime dependencies today are gitpython, pyyaml, typer and
rich.

## Options

| Option | Runtime deps | Load safety | Version coupling |
| --- | --- | --- | --- |
| A. pickled sklearn `.joblib` | + scikit-learn, numpy, scipy (~100 MB) | unpickling runs arbitrary code | must match the training sklearn version |
| B. JSON: scaler + logistic regression coefficients | none | plain data | none (versioned schema) |
| C. ONNX | + onnxruntime (10-50 MB) | safe | runtime version |
| D. gradient-boosted trees in JSON | none | safe | needs a tree walker, bigger schema |

## Decision

**B.** The model is `src/secrety/data/classifier.json`, a standard scaler
followed by a logistic regression, evaluated in pure Python:

```text
z = (x - mean) / scale
p = 1 / (1 + exp(-(coef · z + intercept)))
```

Schema (version 1):

```json
{
  "schema_version": 1,
  "model_type": "logistic_regression",
  "feature_names": ["..."],
  "scaler": {"mean": [], "scale": []},
  "coef": [],
  "intercept": 0.0,
  "threshold": 0.5,
  "training": {"stub": true, "trained_at": null, "sklearn_version": null,
               "dataset": null, "n_samples": 0, "metrics": {}}
}
```

Checks on load, each failure a `ClassifierError` (a `ValueError`, exit code 2
like a bad rules file):

0. The top level is an object with exactly the keys above: a missing or
   unknown key (a typo such as `coeff`) fails.
1. `schema_version` is supported; an unknown version fails, it is never guessed.
2. `model_type` is `logistic_regression`.
3. `feature_names` equals `secrety.features.FEATURE_NAMES` exactly (same order),
   so a renamed or reordered feature cannot silently swap columns.
4. `scaler.mean`, `scaler.scale` and `coef` have one value per feature.
5. Every number is a finite float (booleans rejected); every `scale` is > 0.
6. `threshold` is in `[0, 1]`; `--classifier-threshold` overrides it.

No `jsonschema` dependency: the validator is hand-written.

## Consequences

- No new runtime dependency, no unsafe load, no sklearn version lock: a
  security tool must not ship a pickle.
- Inference is a dozen lines, easy to test with golden values.
- The model has to stay linear. Feature crosses are computed in
  `features.py`; a non-linear model means a new `model_type` or
  `schema_version: 2` (option D stays open if task 07 shows a real gain).
- Task 04 ships a hand-set stub (`"stub": true`). Task 07 adds
  `evaluation/export_model.py`, which imports `FEATURE_NAMES` and checks that
  the pure-Python scores match sklearn's `predict_proba` to 1e-9.
- Any change to `FEATURE_NAMES` requires retraining and re-exporting; check 3
  enforces it.
