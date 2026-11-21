# Integration

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Nothing found (or `--exit-zero`) |
| 1 | Secrets found |
| 2 | Error (bad option, not a Git repository, unreadable config...) |

`--exit-zero` turns code 1 into 0 so a report-only job never blocks; errors
still exit 2.

## Staged mode

```bash
secrety scan --staged
```

Scans only what is **staged in the Git index**, not the worktree: an unstaged
edit that hides a secret on disk does not hide it from this check. Added and
modified files are scanned (deleted files, symlinks and submodules are not;
renames are scanned under the new name).

Paths are reported relative to the **repository root**, and the root
`.secrety.toml` applies, wherever you run it from. The config is read from the
**index** too, so an unstaged edit cannot silence a finding. So an allowlist glob such
as `**/tests/**` behaves the same in a pre-commit run and in a full scan.
`--staged` cannot be combined with `--git`.

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Nakken13/secrety
    rev: v0.1.0
    hooks:
      - id: secrety
```

The hook runs `secrety scan --staged` with `pass_filenames: false`: it reads
the index itself instead of the file names pre-commit hands over (which would
lose the repository-relative paths the allowlist needs).

## GitHub Action

```yaml
# .github/workflows/secrets.yml
name: secrets
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # only for sarif: "true"
jobs:
  secrety:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Nakken13/secrety@v0.1.0
        with:
          sarif: "true"
```

| Input | Default | Meaning |
|-------|---------|---------|
| `path` | `.` | File or folder to scan |
| `config` | empty | Settings file (see the warning below) |
| `version` | action's own tag | PyPI specifier, e.g. `==0.1.0`; empty installs the code of the tag you use |
| `sarif` | `false` | Upload findings to GitHub code scanning |
| `exit-zero` | `false` | Do not fail the job on findings |

The `exit-code` output holds secrety's exit code (0, 1, 2).

### Scanning untrusted code (pull requests from forks)

The scanned repository's own `.secrety.toml` and `secrety:ignore` markers can
silence findings, so a malicious pull request could hide a secret. When the
code is not trusted, check out a trusted config and pass it explicitly:

```yaml
- uses: Nakken13/secrety@v0.1.0
  with:
    config: .github/secrety-trusted.toml   # taken from the base branch
```

with, in that file, `[allowlist]` / `use_defaults = false` and
`inline_ignore = false` if you want every path and every line scanned.

## Scanning history (`--git`) in CI

`secrety scan . --git` reports every secret ever added, including ones fixed
long ago. On a repository with old findings that are accepted or already
rotated, a `--git` gate fails forever. There is no baseline file yet: mark
accepted lines with an inline `secrety:ignore[rule-id]` marker (it applies to
the commit that added the line) or scan only recent history with
`--since` / `--max-commits`. A fingerprint baseline is planned.
