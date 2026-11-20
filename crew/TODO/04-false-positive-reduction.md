# 04 False-positive reduction and classifier

Allowlists, inline ignore, features, classifier inference. Depends on 01 and 02.
Zone : `src/secrety/allowlist.py`, `src/secrety/features.py`, `src/secrety/classifier.py`, `src/secrety/data/`, `src/secrety/cli.py`, `docs/decisions/`, `tests/`

- [ ] OPEN DECISION (architect persona, do first; record in `docs/decisions/0001-classifier-format.md`): pickled sklearn `.joblib` (fragile across sklearn versions, unsafe to load) vs exporting logistic regression coefficients + scaler to JSON (pure-Python inference, versioned schema). Recommendation to evaluate: JSON
- [ ] Path allowlist globs (tests, lockfiles, examples) as defaults, overridable via config
- [ ] Inline `# secrety:ignore` (and `secrety:ignore[rule-id]`) honored for any comment style
- [ ] Feature extraction: entropy, length, charset class, variable name tokens, file extension + tests
- [ ] Classifier inference module per the decision; loads the packaged model; scores each Finding; threshold configurable
- [ ] Stub model usable in tests until task 07 training; classifier wired into pipeline behind `--classifier` flag
- [ ] Coverage >= 80%
