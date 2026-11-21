# 03 Git history scan

Find secrets that were deleted in later commits. Depends on 01 (02 optional). Loosely coupled to reporters, but shares `cli.py`.
Zone : `src/secrety/sources/git.py`, `src/secrety/sources/base.py`, `src/secrety/models.py`, `src/secrety/scanner.py`, `src/secrety/cli.py`, `pyproject.toml`, `tests/test_git_source.py`, `tests/test_cli.py`, `tests/conftest.py`

- [x] Git source with GitPython: iterate commits, scan added lines of each diff (not the full tree per commit); attach commit sha, author, date to Finding
- [x] Mark findings as "removed later" when the secret is absent from HEAD
- [x] Handle merge commits, binary diffs, large diffs, shallow clones
- [x] `--git` option on `secrety scan` (+ `--max-commits`, `--since`)
- [x] Integration test: temp repo fixture where a secret is committed then deleted; assert it is detected with the correct commit
- [x] Coverage >= 80% (98 %)
