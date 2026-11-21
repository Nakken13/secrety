# 04 False-positive reduction and classifier

Allowlists, inline ignore, features, classifier inference. Depends on 01 and 02.
Zone : `src/secrety/allowlist.py`, `src/secrety/features.py`, `src/secrety/classifier.py`, `src/secrety/data/`, `src/secrety/cli.py`, `docs/decisions/`, `tests/`

- [x] OPEN DECISION (architect persona, do first; record in `docs/decisions/0001-classifier-format.md`): pickled sklearn `.joblib` (fragile across sklearn versions, unsafe to load) vs exporting logistic regression coefficients + scaler to JSON (pure-Python inference, versioned schema). Recommendation to evaluate: JSON
- [x] Path allowlist globs (tests, lockfiles, examples) as defaults, overridable via config
- [x] Inline `# secrety:ignore` (and `secrety:ignore[rule-id]`) honored for any comment style
- [x] Feature extraction: entropy, length, charset class, variable name tokens, file extension + tests
- [x] Classifier inference module per the decision; loads the packaged model; scores each Finding; threshold configurable
- [x] Stub model usable in tests until task 07 training; classifier wired into pipeline behind `--classifier` flag
- [x] Coverage >= 80%

Carried over from 01 (review / self-scan):
- [x] Self-scan of this repo is clean: allowlist `tests/` (fakes.py, test_cli.py hostile-markup case), `# secrety:ignore` on the url-credentials regex line of default_rules.yaml (matches itself), and the pyproject `secrety = "secrety.cli:app"` hit (keyword inside the tool's own name) handled by the classifier or an allowlist
- [x] Lint custom `--rules` files for unbounded quantifiers (`+`, `*`, `{n,}`) and warn (ReDoS guarantee currently holds for bundled rules only)
- [x] Count links/junctions skipped by the filesystem walk in ScanStats; check whether `_is_link` should test `st_reparse_tag` (symlink / mount point) instead of every reparse point

Close in progress (2026-11-21): deep review done, items 1-9 fixed in the last commit (marker typo no longer widens, `allowlist.inline_ignore` off switch, gitignore-style non-backtracking globs, overflow/NaN guards, empty-secret charset). Item 10 (`re._parser` private) declined: present 3.11-3.14, tests catch a move.
Resume with `/crew-close-task`: still to do — docs for `inline_ignore` + gitignore globs in `docs/methodology.md`, widen 06 carry-over (scan root != repo root; inline markers now switchable), AGENTS.md map (`filtering/` -> top-level modules), `simplify` pass, then history/tests/merge.
