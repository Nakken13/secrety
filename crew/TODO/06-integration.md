# 06 Integration: pre-commit, staged mode, GitHub Action

Depends on 05 (formats, for SARIF upload) and 01.
Zone : `.pre-commit-hooks.yaml`, `action.yml`, `src/secrety/sources/staged.py`, `src/secrety/cli.py`, `tests/test_staged.py`, `docs/integration.md`

- [ ] `--staged` mode scanning only the git index content (not the worktree)
- [ ] Non-zero exit code on findings (0 clean, 1 findings, 2 error); `--exit-zero` override
- [ ] `.pre-commit-hooks.yaml` hook definition + test with a temp repo
- [ ] Reusable composite GitHub Action `action.yml` (install, scan, optional SARIF upload)
- [ ] `docs/integration.md` usage snippets
- [ ] Coverage >= 80%
