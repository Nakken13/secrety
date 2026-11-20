# History of completed tasks

One entry per finished task (code complete): what, when, key files/commits.
Project context memory — do not summarize, keep the details that would help a
future session understand why a decision was made.

<!-- Example:
## <task slug> — YYYY-MM-DD
What: ...
Key files/commits: ...
-->

## 01-regex-detection — 2026-11-20
What: core scanner. `Finding` model (masking: <20 chars fully hidden, <=25 % shown; fingerprint = rule|path|commit|line-without-secret, never the secret nor line/column so it survives code shifts and cannot be brute-forced from a published report). YAML rule loader with strict validation (bool/str/version checks, I/O errors -> RuleError -> exit 2). 13 default rules (AWS id/secret incl. JSON + Terraform forms, GitHub classic + fine-grained, Stripe, Slack token/xoxe/xapp + webhook, Google, JWT, PEM incl. DH, PuTTY, URL credentials, generic quoted password incl. DB_PASSWORD/client_secret/SECRET_KEY/`:=`). `Detector` protocol + line-based `RegexDetector` (newline-only line numbers, two-level keyword pre-filter on one lowercase copy). `FilesystemSource` (one lstat per file, 8 KiB head sniff, UTF-16 BOM, NTFS junctions and symlinks never followed, unreadable paths counted). `scanner.scan` -> `ScanResult(findings, stats)`. CLI `secrety scan PATH [--rules] [--max-file-size]`, exit 0/1/2, Rich-escaped output.
Why some decisions: ReDoS found by automated security review (url-credentials 2.4 s, jwt 3+ s on 40k-char lines) -> every quantifier bounded + lookbehinds, worst-case lines kept as tests; with linear rules long lines are no longer dropped. Test fakes are assembled at runtime (tests/fakes.py) so the repo holds no literal secret-shaped string (self-scan + GitHub push protection). Unquoted .env/YAML values deliberately left to entropy (02) + classifier (04): a regex on them flags function calls.
Deferred: dedupe when generic and specific rules hit the same value (02); self-scan FPs to silence in 04 (tests/fakes.py, tests/test_cli.py, url regex matching itself in default_rules.yaml, pyproject `secrety = "secrety.cli:app"`); bounded-quantifier lint for custom `--rules` files; Rich reporters package (05).
Reviews: deep code review (14 items, all applied or deferred above) + simplify (4 angles, 5 refactor commits; runtime_checkable kept, used by tests).
Key commits: d601dfd..53160b7 on crew/batch-a (models, rules, detectors, sources, cli, ReDoS fix a51838c, review fixes 7c5fa9d..a2af177, refactors 61cddbe..53160b7).
Tests: none — detection logic is a risky zone but fully covered by automated tests (144 pytest, 97.7 % coverage, positive+negative case per rule, ReDoS regression lines, Windows junction test).
