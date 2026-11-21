# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Interactive numbered menu, opened by `secrety` with no arguments: banner, scan modes
  (folder, Git history, staged), findings as cards per file, report saving.

## [0.1.0] - 2026-11-21

First release.

### Added

- `secrety scan` for a folder, with a confidence score per finding and masked
  secrets in every output.
- Regex rules for AWS, GitHub, Stripe, Google, Slack, JWT, private keys, URL
  credentials and password assignments; custom rules with `--rules`.
- Shannon-entropy detector with separate base64 and hex thresholds.
- Merging of findings reported by several rules for the same value.
- Git history scan (`--git`, `--max-commits`, `--since`).
- Staged-content scan (`--staged`) for pre-commit use, `--exit-zero`, a
  pre-commit hook and a GitHub Action.
- `.secrety.toml` allowlist (tests, lockfiles and examples skipped by default)
  and inline `secrety:ignore`.
- Text, JSON and SARIF reports.
- Optional classifier (`--classifier`): logistic regression stored as JSON,
  evaluated without pickle or scikit-learn.
- Evaluation: synthetic corpus, metrics and a benchmark against gitleaks and
  trufflehog, in `evaluation/` and `docs/results/`.

[0.1.0]: https://github.com/Nakken13/secrety/releases/tag/v0.1.0
