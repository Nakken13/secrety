# 06 Integration: pre-commit, staged mode, GitHub Action

Depends on 05 (formats, for SARIF upload) and 01.
Zone : `.pre-commit-hooks.yaml`, `action.yml`, `src/secrety/sources/staged.py`, `src/secrety/cli.py`, `tests/test_staged.py`, `docs/integration.md`

- [ ] `--staged` mode scanning only the git index content (not the worktree)
- [ ] Non-zero exit code on findings (0 clean, 1 findings, 2 error); `--exit-zero` override
- [ ] `.pre-commit-hooks.yaml` hook definition + test with a temp repo
- [ ] Reusable composite GitHub Action `action.yml` (install, scan, optional SARIF upload)
- [ ] `docs/integration.md` usage snippets
- [ ] Coverage >= 80%

Carried over from 04:
- [ ] Single-file scans (pre-commit passes files) report the basename only, so `**/tests/**` allowlist globs cannot match and `.secrety.toml` is looked up beside the file, not at the repo root: pass repo-relative paths and the repo-root config to the filters in staged / pre-commit mode
- [ ] `secrety scan . --git` on this repo still reports 2 hits from commits before the inline markers (`pyproject.toml` entry point, `default_rules.yaml` url-credentials description): needs a baseline / fingerprint allowlist (or accept and document) before a `--git` CI gate on this repo
- [ ] Action / CI on untrusted code: the scanned repo's `.secrety.toml` and `secrety:ignore` markers can silence findings; document passing an explicit `--config` (and `use_defaults = false` if wanted)
