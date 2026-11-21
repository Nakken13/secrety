# Detection methodology

secrety runs three detectors on every file, then merges what they report.

| Detector | Finds | Method | Confidence |
|---|---|---|---|
| Regex rules (`rules/default_rules.yaml`) | known formats: AWS, GitHub, Stripe, JWT, private keys... | `regex` | per rule, 0.4 to 0.95 |
| Unquoted assignments | `DB_PASSWORD=...`, `password: ...` in config files | `regex` | 0.4 |
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
included so that URL-safe keys and JWT segments stay in one piece. Every other
character ends a token: quotes, spaces, `=`, `:` and `.`. A token is kept when:

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
the charset maximum, so entropy findings stay below most regex rules. A known
format is stronger evidence than randomness.

## Unquoted assignments in config files

The `generic-password-assignment` regex rule only accepts quoted values. In
code, an unquoted value is an identifier or a call (`password =
get_password()`). In config files (`.env*`, `.yml`/`.yaml`, `.ini`, `.cfg`,
`.conf`, `.properties`), values are plain text. A dedicated detector flags
`KEY=value` and `key: value` lines there when:

- the key contains `password`, `passwd`, `pwd`, `secret`, `api_key`,
  `access_token` or `auth_token`;
- the value is 8 to 256 non-space characters;
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

1. the highest confidence;
2. on a tie, a regex finding over an entropy one;
3. then the earliest column.

The other findings are recorded in `Finding.also_matched`, and
`Finding.methods` lists every method that fired.

## Known weaknesses

- **Short secrets are invisible to entropy.** See the length bound above.
  Passwords are left to regex rules and to the unquoted-assignment detector.
- **Public base64 data.** Certificate bundles (`cacert.pem`), embedded images
  and lock-file integrity hashes are high entropy and not secret. Scanning
  pip's own package gives about 2,550 findings from `cacert.pem` alone. Task 04
  handles this (path and context filters, classifier).
- **Hex hashes.** Git SHAs, checksums and SHA-256 digests (about 3.7 bits)
  exceed the hex threshold (3.0). Task 04 handles them too.
- **Alphabet literals and URL paths.** `"ABC...xyz0123456789"` or
  `github.com/python/cpython/blob/<sha>` look random to the formula.
- **Character frequency only.** `H` ignores order, so `abcdabcd...` scores like
  a random string of the same letters.
- **Line by line.** A secret split across lines (a multi-line PEM body, a
  string concatenation) is seen in pieces, or missed.
- **Unquoted detection depends on file names.** A config file with an unusual
  extension is not checked. A long non-secret value under a secret-like key
  (`secret_name: my-service-prod`) is flagged.
