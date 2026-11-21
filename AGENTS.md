# AGENTS.md — secrety

Invariants guide + repo map for any agent (Claude Code or other) working on
this project.

## Stack

Declared in `pyproject.toml` (deps added phase by phase): Python 3.11+, `src/` layout, packaging via `pyproject.toml` (hatchling),
CLI with typer + rich, GitPython, PyYAML, scikit-learn, pytest + pytest-cov,
ruff, matplotlib (evaluation only), GitHub Actions CI.

## Repository map

```text
src/secrety/         # package: cli, scanner, config, models, allowlist, features, classifier (+ data/), detectors/, sources/, rules/ (reporters/ planned, task 05)
tests/               # pytest unit + integration (temporary git repos via tmp_path)
evaluation/          # synthetic corpus generator, metrics, benchmark vs gitleaks/trufflehog, plots
docs/                # methodology, architecture, images for the README
.github/workflows/   # CI (ruff + pytest + coverage)
crew/                # task tracking (crew-mates scaffold)
```

## Verified commands

```bash
python -m venv .venv && .venv/Scripts/python -m pip install -e ".[dev]"   # install (Windows; bin/ on Linux)
secrety --version && secrety scan .                                         # run
.venv/Scripts/python -m pytest                                              # tests + coverage gate 80 %
.venv/Scripts/ruff check . && .venv/Scripts/ruff format --check .           # lint
pipx install .                                                              # end-user install
```

## Code rules

- Full type hints, docstrings on every public function/class.
- Conventional Commits, small atomic commits.
- Coverage must stay > 80 % (`pytest --cov`).
- No `print` for output: go through the reporters (rich / JSON / SARIF).
- Detection rules live in `src/secrety/rules/default_rules.yaml`, not in code.

## Secrets and boundaries

- **Never a real secret anywhere in the repo**, including tests and evaluation.
  Fake values only, visibly marked (`FAKE`, `EXAMPLE`, `TEST`) whenever the
  format allows it.
- The evaluation corpus is **generated at runtime** (fixed seed) and is never
  committed, to avoid tripping GitHub push protection / secret scanning.
- The scanner never prints a full secret value in logs: findings are masked in
  terminal output.
- See `SECURITY.md`.

## Documentation routing

- Product vision / scope: `PRODUCT.md`.
- Contribution conventions: `CONTRIBUTING.md`.
- Security limits: `SECURITY.md`.
- Global context guide: `crew/CLAUDE_CONTEXT/AGENTS.md`.
