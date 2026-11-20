# CONTRIBUTING.md — secrety

## Branches

`main` is always green. Work branches: `feat/<slug>`, `fix/<slug>`,
`docs/<slug>`, `chore/<slug>`.

## Commits

Conventional Commits (`feat(scope): ...`, `fix: ...`, `test: ...`,
`docs: ...`, `ci: ...`, `chore: ...`). Small and atomic: one logical change
per commit.

## Pull requests

CI must pass before merge: `ruff check`, `ruff format --check`, `pytest` with
coverage > 80 %. Never commit a real secret, even in a test.
