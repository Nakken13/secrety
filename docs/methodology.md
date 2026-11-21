# Detection methodology

secrety runs two detectors on every file, then merges what they report.

| Detector | Finds | Method | Confidence |
|---|---|---|---|
| Regex rules (`rules/default_rules.yaml`) | known formats (AWS, GitHub, Stripe, JWT, private keys...) and generic password assignments | `regex` | per rule, 0.4 to 0.95 |
| Entropy | random-looking tokens with no known format | `entropy` | 0.3 to 0.6 |

## Shannon entropy

For a string `s` of length `n`, where character `i` appears with frequency
`p_i = count_i / n`:

```
H(s) = - sum_i  p_i * log2(p_i)        (bits per character)
```

`H` measures how unpredictable each character is. `aaaa` gives 0, `aabb`
gives 1, `abcd` gives 2. A random string over an alphabet of `k` symbols
approaches `log2(k)`: 6 bits for base64 (64 symbols), 4 bits for hex (16).
English words and identifiers repeat letters, so they stay lower (about 3.3 to
3.8 for `src/secrety/detectors/entropy` or a long snake_case name).

Two upper bounds limit what can be flagged:

- **Alphabet:** `H <= log2(k)`. A hex token never exceeds 4.
- **Length:** `H <= log2(n)`. A string can only use `n` distinct characters,
  so a 20-character token never exceeds 4.32 bits. With the default base64
  threshold (4.5), no base64 token shorter than 23 characters can be flagged,
  whatever its content.

## Candidate tokens

Each line is cut into maximal runs of base64 characters `[A-Za-z0-9+/_-]`,
optionally followed by `=` padding. The URL-safe characters `-` and `_` are
included so that URL-safe keys and JWT segments stay in one piece. Any other
character ends a token: quotes, spaces, `:`, `.`, and `=` past the first two
(which are taken as padding, so in `KEY=value` the token is `KEY=`). A token is
kept when:

- it is at least `min_length` characters long (default 20);
- it is not made only of decimal digits (timestamps, IDs, phone numbers).

A token made only of hex digits is classified **hex**. Any other token is
classified **base64**.

## Why per-charset thresholds

A hex token cannot go above 4 bits per character, so a single threshold cannot
work for both charsets. At 4.5 no hex secret would ever be found. At 3.0
base64 would flag most long identifiers. Each charset therefore gets a
threshold proportionate to its maximum:

| Charset | Maximum | Default threshold | Option |
|---|---|---|---|
| base64 | 6.0 | 4.5 | `--entropy-base64-threshold` |
| hex | 4.0 | 3.0 | `--entropy-hex-threshold` |

`--entropy-min-length` sets the shortest token. The defaults are the usual
starting points (TruffleHog, detect-secrets). Task 07 tunes them on a
labelled corpus. Confidence grows linearly from 0.3 at the threshold to 0.6 at
the charset maximum, so entropy findings stay below most regex rules.

This confidence is not comparable across charsets. Hex reaches its 4-bit
ceiling easily, so a random hex digest scores 0.4-0.55. A random base64 token
of 24-40 characters scores only 0.3-0.35, because the length bound keeps it far
from 6 bits. Calibrated scores come from the classifier (task 04).

## Unquoted assignments in config files

The `generic-password-assignment` regex rule only accepts quoted values. In
code, an unquoted value is an identifier or a call (`password =
get_password()`). In config files (`.env*`, `.yml`/`.yaml`, `.ini`, `.cfg`,
`.conf`, `.properties`), values are plain text. The
`generic-password-unquoted` rule flags `KEY=value` and `key: value` lines
there. It is an ordinary YAML rule: the optional `paths` field (globs on the
file name) limits it to those files, so a custom `--rules` file can tune or
drop it. It matches when:

- the line starts with the key (after indentation, an optional YAML list
  marker `- ` and an optional `export`);
- the key contains `password`, `passwd`, `pwd`, `secret`, `api_key`,
  `access_token` or `auth_token`, with `_`, `-` or nothing in the middle
  (`x-api-key`, `apikey`);
- the value has at least 8 non-space characters; only the first 256 are
  reported;
- the value does not start with `$ < { %`, which mark references and templates
  (`${VAR}`, `<your-password>`, `{{ var }}`, `%(var)s`).

Entropy cannot gate these values. A 10-character password has at most
`log2(10) = 3.3` bits, the same as an ordinary word.

## Merging duplicates

Several detectors often flag the same secret. For example, `secret_key =
"..."` matches both `generic-password-assignment` and `aws-secret-access-key`,
and the value is also a high-entropy token. Within a file, findings on the same
line whose spans overlap are grouped. Overlap is transitive: one JWT regex
match overlaps three entropy tokens, because `.` splits them. Each group keeps
one finding:

1. a regex finding, if the group has one, whatever its confidence;
2. then the highest confidence;
3. then the earliest column.

Regex comes first for two reasons. A known format is stronger evidence than
randomness. And letting confidence decide would make the result depend on the
entropy threshold: `password = "<hex>"` would be reported as
`high-entropy-hex` at one threshold and `generic-password-assignment` at
another. The fingerprint hashes the rule id, so it would flip too. Regex also
wins when the entropy token is only a fragment of the value: `!` and `@` are
not base64, so they cut the value into several tokens.

The other findings are recorded in `Finding.also_matched`, listed as `also:`
in the terminal output. `Finding.methods` lists every method that fired.

## Reducing false positives

Filtering runs on findings, after detection, so a folder scan and a `--git`
scan are filtered the same way. Every filter counts what it removes and the
summary prints the counts: nothing is hidden silently.

1. **Path allowlist.** Findings in test code (`tests/`, `test_*.py`,
   `*.spec.ts`...), dependency lockfiles (integrity hashes look random) and
   examples (`examples/`, `*.example`) are dropped by default. Globs follow
   `.gitignore` conventions: `*` stays inside one folder, `**` spans folders,
   a pattern without `/` matches the file name at any depth, case is ignored.
   A `.secrety.toml` at the scanned folder (or `--config FILE`) adds patterns
   or turns the defaults off:

   ```toml
   [allowlist]
   paths = ["vendor/**", "docs/*.md"]
   use_defaults = false   # also scan tests, lockfiles and examples
   ```

   Unknown keys are errors, so a typo (`path` for `paths`) cannot silently
   disable the file.
2. **Inline ignore.** A line containing `secrety:ignore` is skipped, whatever
   the comment syntax (`#`, `//`, `<!-- -->`...). `secrety:ignore[rule-a,
   rule-b]` only ignores findings reported under those rules. Rules merged
   into a finding (`also:`) flagged the same value, so naming the reported
   rule is enough; naming only a merged rule (usually `high-entropy-*`) does
   not hide what a known-format rule found.
3. **Classifier** (opt-in, `--classifier`). A logistic regression rescores
   each remaining finding from features of the value (entropy, length,
   charset, placeholder words such as `example` or `changeme`), of the name
   it is assigned to (`password`, `mock_token`) and of the file type. The
   confidence becomes the model probability, and findings below the
   threshold (`--classifier-threshold`, default from the model) are dropped.
   The model is versioned JSON evaluated in pure Python: no pickle is loaded
   and scikit-learn is not needed at runtime (see
   `docs/decisions/0001-classifier-format.md`). Until the evaluation trains
   it, the packaged model is a hand-set stub and the CLI says so.

Custom rules (`--rules`) are checked for unbounded quantifiers (`+`, `*`,
`{n,}`), which can backtrack for a long time on a long line. The bundled
rules bound every repetition, and a test keeps it that way.

## Known weaknesses

- **Short secrets are invisible to entropy.** See the length bound above.
  Passwords are left to the regex rules, quoted and unquoted.
- **Public base64 data.** Certificate bundles (`cacert.pem`), embedded images
  and lock-file integrity hashes are high entropy and not secret. Scanning
  pip's own package gives about 2,550 findings from `cacert.pem` alone.
  Lockfiles are allowlisted by default; certificate bundles are not (a `.pem`
  can hold a private key), so add them to `.secrety.toml` when needed.
- **Hex hashes.** Git SHAs, checksums and SHA-256 digests (about 3.7 bits)
  exceed the hex threshold (3.0). Outside lockfiles, only the trained
  classifier (task 07) can tell them apart.
- **Allowlisted paths are trusted.** A real secret committed under `tests/`
  or in an allowlisted folder is not reported, only counted. `.secrety.toml`
  is read from the scanned repository, so whoever controls the repository
  controls what is skipped: a CI scan of untrusted code should pass its own
  `--config` (which replaces the repository's file).
- **The stub classifier is not evidence.** Its weights are hand-set: use
  `--classifier` for triage, not as a gate, until task 07 publishes metrics.
  Its `value_placeholder` feature fires on `FAKE` and `EXAMPLE`, the very
  markers the repository's fake values must carry: task 07 has to settle that
  conflict (drop those words from the feature, or keep them out of the
  runtime-generated corpus) before training.
- **Alphabet literals and URL paths.** `"ABC...xyz0123456789"` or
  `github.com/python/cpython/blob/<sha>` look random to the formula.
- **Character frequency only.** `H` ignores order, so `abcdabcd...` scores like
  a random string of the same letters.
- **No upper length.** A one-line data URI or an embedded notebook image is a
  single huge token, so it gives one finding. The masked value is capped at 120
  asterisks, so it does not flood the terminal.
- **Fragments.** With no regex finding to take over, an entropy finding on a
  value cut by `!` or `.` reports only one piece. The other pieces stay in the
  line context that the fingerprint hashes. Short pieces could in principle be
  brute-forced from a published fingerprint.
- **Fingerprint collisions.** Two different tokens with the same surrounding
  text in one file (`k = "<token>"`) get the same fingerprint, because the
  fingerprint leaves the secret and the line number out on purpose. This
  matters for baselines.
- **Line by line.** A secret split across lines (a multi-line PEM body, a
  string concatenation) is seen in pieces, or missed.
- **Unquoted detection depends on file names.** A config file with an unusual
  extension is not checked. A long non-secret value under a secret-like key
  (`secret_name: my-service-prod`) is flagged.
