# 01 Regex detection and filesystem scan

Core scanner: Finding model, YAML rules, regex detector, filesystem source, `secrety scan PATH`. Depends on phase 0 (skeleton, done outside crew). Everything after depends on this.
Zone : `src/secrety/models.py`, `src/secrety/rules/`, `src/secrety/detectors/regex.py`, `src/secrety/sources/filesystem.py`, `src/secrety/cli.py`, `tests/`

- [ ] `models.Finding` dataclass (rule_id, path, line, column, match, secret, commit?, method, score?) + tests
- [ ] YAML rule loader with validation (bad regex, missing fields, duplicate ids -> clear error) + tests
- [ ] `src/secrety/rules/default_rules.yaml`: AWS, GitHub, Stripe, Slack, Google, JWT, PEM private keys, URLs with credentials; each rule has a positive and a negative test (fake values only)
- [ ] Regex detector yielding Findings with line/column
- [ ] Filesystem source: recursive walk, skip binaries (NUL sniff) and files above a size limit, configurable
- [ ] `secrety scan PATH` wired to source + detector (plain output for now)
- [ ] pytest passes, coverage >= 80%; small atomic Conventional Commits
