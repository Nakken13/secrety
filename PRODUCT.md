# PRODUCT.md — secrety

## Vision

A command-line scanner that finds secrets (API keys, tokens, passwords,
private keys) exposed in source code and Git history, with a confidence score
and a rigorously measured precision/recall.

## Target user

Developers and small teams who want to block secret leaks before a push
(pre-commit hook, GitHub Action) or audit an existing repository. Also a
portfolio project for engineering-school applications: methodology and
honest evaluation matter as much as features.

## Current scope

Nothing shipped yet. Planned: regex rules (YAML), Shannon entropy, Git history
scan, false-positive reduction (allowlist, inline ignore, ML classifier),
terminal/JSON/SARIF outputs, pre-commit hook, GitHub Action, benchmark vs
Gitleaks and TruffleHog.

## Out of scope (explicitly)

- Live verification of found secrets against provider APIs (network calls,
  ethical and legal concerns).
- Automatic secret revocation or history rewriting.
- Scanning remote services (Slack, S3, Docker images…): local folders and Git
  repositories only.
