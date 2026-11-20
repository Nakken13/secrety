# 02 Entropy detection

Shannon entropy over base64/hex candidate tokens. Depends on 01.
Zone : `src/secrety/detectors/entropy.py`, `src/secrety/config.py`, `src/secrety/cli.py`, `docs/methodology.md`, `tests/`

- [ ] Tokenizer extracting base64 and hex candidates (min length)
- [ ] Shannon entropy function; per-charset thresholds (starting points base64 4.5, hex 3.0, tuned in task 07) + tests with known values
- [ ] Thresholds and min length configurable (config + CLI options)
- [ ] Entropy detector emits Findings (method="entropy"); dedupe against regex findings on the same span
- [ ] `docs/methodology.md`: formula H = -sum p_i log2 p_i, why per-charset thresholds, known weaknesses
- [ ] Tests, coverage >= 80%

Carried over from 01 (review):
- [ ] Dedupe findings when several detectors/rules report the same value at the same place (e.g. generic-password-assignment + aws-secret-access-key on `secret_key = "..."`): keep one, highest confidence, record all methods
- [ ] Cover unquoted secret values (`.env` `PASSWORD=...`, YAML `password: ...`), deliberately left out of the regex rules because a regex flags function calls there
