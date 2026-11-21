# 07 Evaluation and benchmark

Depends on 01-06 (all methods + classifier inference). Largest phase; consider splitting when started (corpus+metrics / training / benchmark+plots).
Zone : `evaluation/`, `src/secrety/data/`, `docs/results/`, `tests/test_eval_*.py`

- [ ] Synthetic corpus generator: generated at runtime, fixed seed, never committed (gitignored), fake values only
- [ ] Marker design: FAKE/EXAMPLE markers must not leak the label. Put markers in surrounding context or equally across positives and decoys. Verify how gitleaks and trufflehog allowlists/stopwords treat marked values and document findings
- [ ] `ground_truth.json` written alongside the corpus
- [ ] Metrics: precision/recall/F1 for regex, entropy, combined, combined+classifier
- [ ] Separate train/test seeds; held-out decoy families present only in test
- [ ] Classifier training script (writes the artifact format chosen in task 04), reproducible command
- [ ] Benchmark vs gitleaks and trufflehog (`--no-verification`), pinned versions, timing, same corpus
- [ ] matplotlib plots + markdown results table in `docs/results/`
- [ ] Tests for generator determinism and metrics; coverage >= 80%

Carried over from 04:
- [ ] Settle the marker conflict: `features.value_placeholder` fires on `fake`/`example`, the markers AGENTS.md requires on fake values. Either drop those words from the feature (and retrain) or keep them out of the runtime corpus; decide before training
- [ ] `evaluation/export_model.py` imports `secrety.features.FEATURE_NAMES` and writes `src/secrety/data/classifier.json` (schema in `docs/decisions/0001-classifier-format.md`, `training.stub: false`); a test checks pure-Python `Classifier.probability` matches sklearn `predict_proba` to 1e-9
- [ ] Train through `secrety.features.extract` only (same features at scan and training time); report metrics with and without `--classifier`
