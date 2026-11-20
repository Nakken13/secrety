# SECURITY.md — secrety

## Secrets

This project handles secret-*shaped* strings by design. Rules:

- Never commit a real secret. Tests and the evaluation corpus use fake values
  only, visibly marked (`FAKE`, `EXAMPLE`, `TEST`) whenever the format allows.
- The evaluation corpus is generated at runtime and git-ignored.
- No `.env` committed; the tool itself needs no credentials.

## Auth boundaries

No authentication: secrety is a local CLI. It makes **no network calls**
(no secret verification against provider APIs).

## Sensitive data / PII

Findings may contain real secrets from the scanned code: terminal output masks
the value; JSON/SARIF reports contain a masked snippet by default and must be
treated as sensitive if a `--show-secrets` option is added.

## Pre-production checklist

- `gitleaks`/`secrety` self-scan of this repo is clean (only allowlisted fakes).
- No test fixture matches a real provider's live-key format without a fake marker.
- Reporting a vulnerability: open a private GitHub security advisory.
