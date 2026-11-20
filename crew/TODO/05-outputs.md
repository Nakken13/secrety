# 05 Output formats

Terminal, JSON, SARIF. Depends on 01 (Finding model). Could run parallel to 03/04 apart from `cli.py` (`--format` option); kept sequential to avoid conflicts.
Zone : `src/secrety/reporters/`, `src/secrety/cli.py`, `tests/test_reporters.py`, `tests/schemas/`

- [ ] Rich terminal reporter with masked values (e.g. first 4 chars + `****`); secrets never printed in clear by default
- [ ] JSON reporter (stable schema, masked by default)
- [ ] SARIF 2.1.0 reporter; validated in tests against the official schema vendored in `tests/schemas/` (jsonschema as dev dep)
- [ ] `--format {text,json,sarif}` and `--output FILE`
- [ ] Tests, coverage >= 80%
