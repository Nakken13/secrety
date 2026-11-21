# Batching — parallel workstreams

One batch = one Claude. See § Batching in `crew/CLAUDE_CONTEXT/LIFECYCLE.md` for the rules
(impact zone, disjointness invariant between active batches).

## Unsorted

## Batch A

Zone: `src/secrety/`, `tests/`, `docs/`, `evaluation/`, `.github/`, `README.md`, `CHANGELOG.md`, `.pre-commit-hooks.yaml`, `action.yml`

Sequential: 01 -> 02 -> 03 -> 04 -> 05 -> 06 -> 07 -> 08. (03 and 05 are loosely coupled and could be parallelized in a separate batch only if `cli.py` edits are merged carefully; not worth it.)

- ~~`01-regex-detection.md`~~
- ~~`02-entropy-detection.md`~~
- ~~`03-git-history-scan.md`~~
- `04-false-positive-reduction.md`
- `05-outputs.md`
- `06-integration.md`
- `07-evaluation.md`
- `08-docs-release.md`
