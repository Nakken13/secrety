# 07 Evaluation — DEV checks

Generator, metrics, training/export parity and report formatting are covered by automated tests (568 pytest, 93 % coverage). The numbers in `docs/results/` come from one run on a Windows machine; these checks need another environment.

- [ ] 🖱️ GitHub CI: the `test` matrix (ubuntu 3.11/3.12/3.13, windows 3.11) passes with `pip install -e ".[dev,eval]"` (scikit-learn and matplotlib wheels install and the eval tests run, not skipped)
- [ ] 🖱️ On Linux or macOS with the gitleaks v8.30.1 and trufflehog v3.100.0 binaries under `evaluation/tools/`: `python -m evaluation.report --out /tmp/results` runs to the end and gives the same precision/recall as `docs/results/results.md` (timings may differ)
