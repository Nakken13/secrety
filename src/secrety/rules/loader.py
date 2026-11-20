r"""Load and validate detection rules from YAML.

A rules file looks like::

    version: 1
    rules:
      - id: github-pat
        description: GitHub personal access token
        regex: '\b(ghp_[A-Za-z0-9]{36})\b'
        secret_group: 1      # capture group holding the secret (0 = whole match)
        confidence: 0.95     # prior probability that a match is a real secret
        keywords: [ghp_]     # cheap pre-filter: skip lines without any keyword

Every problem is reported as a :class:`RuleError` naming the file and the
rule, so that a typo in a custom rule never fails silently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

DEFAULT_RULES_RESOURCE = "default_rules.yaml"
DEFAULT_CONFIDENCE = 0.5
_REQUIRED = ("id", "description", "regex")
_OPTIONAL = ("secret_group", "confidence", "keywords")


class RuleError(ValueError):
    """Raised when a rules file is malformed."""


@dataclass(frozen=True, slots=True)
class Rule:
    """A compiled detection rule.

    Attributes:
        id: Unique, stable identifier (used in reports and allowlists).
        description: Human-readable name.
        pattern: Compiled regular expression.
        secret_group: Index of the capture group holding the secret.
        confidence: Prior confidence in ``[0, 1]`` attached to every match.
        keywords: Lowercase substrings; a line containing none is skipped.
    """

    id: str
    description: str
    pattern: re.Pattern[str]
    secret_group: int = 0
    confidence: float = DEFAULT_CONFIDENCE
    keywords: tuple[str, ...] = ()


def _build_rule(raw: Any, index: int, source: str) -> Rule:
    """Validate one raw YAML mapping and turn it into a :class:`Rule`."""
    where = f"{source}: rule #{index}"
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: expected a mapping, got {type(raw).__name__}")

    for field in _REQUIRED:
        if not raw.get(field):
            raise RuleError(f"{where}: missing required field '{field}'")
    unknown = set(raw) - set(_REQUIRED) - set(_OPTIONAL)
    if unknown:
        raise RuleError(f"{where} ({raw['id']}): unknown field(s) {sorted(unknown)}")

    rule_id = str(raw["id"])
    where = f"{where} ({rule_id})"
    try:
        pattern = re.compile(str(raw["regex"]))
    except re.error as exc:
        raise RuleError(f"{where}: invalid regex: {exc}") from exc

    secret_group = raw.get("secret_group", 0)
    if not isinstance(secret_group, int) or not 0 <= secret_group <= pattern.groups:
        raise RuleError(
            f"{where}: secret_group={secret_group!r} but the regex has {pattern.groups} group(s)"
        )

    confidence = raw.get("confidence", DEFAULT_CONFIDENCE)
    if not isinstance(confidence, int | float) or not 0.0 <= confidence <= 1.0:
        raise RuleError(f"{where}: confidence must be a number in [0, 1], got {confidence!r}")

    keywords = raw.get("keywords") or []
    if not isinstance(keywords, list):
        raise RuleError(f"{where}: keywords must be a list")

    return Rule(
        id=rule_id,
        description=str(raw["description"]),
        pattern=pattern,
        secret_group=secret_group,
        confidence=float(confidence),
        keywords=tuple(str(k).lower() for k in keywords),
    )


def parse_rules(text: str, source: str = "<string>") -> list[Rule]:
    """Parse and validate rules from YAML text.

    Args:
        text: YAML document with a top-level ``rules`` list.
        source: Name used in error messages (usually the file path).

    Returns:
        The compiled rules, in file order.

    Raises:
        RuleError: If the YAML is invalid or any rule is malformed.
    """
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleError(f"{source}: invalid YAML: {exc}") from exc

    if not isinstance(document, dict) or "rules" not in document:
        raise RuleError(f"{source}: expected a top-level 'rules' key")
    raw_rules = document["rules"]
    if not isinstance(raw_rules, list):
        raise RuleError(f"{source}: 'rules' must be a list")

    rules: list[Rule] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_rules, start=1):
        rule = _build_rule(raw, index, source)
        if rule.id in seen:
            raise RuleError(f"{source}: rule #{index}: duplicate id '{rule.id}'")
        seen.add(rule.id)
        rules.append(rule)
    return rules


def load_rules(path: Path | None = None) -> list[Rule]:
    """Load rules from ``path``, or the bundled default rules when ``None``."""
    if path is None:
        resource = files("secrety.rules").joinpath(DEFAULT_RULES_RESOURCE)
        return parse_rules(resource.read_text(encoding="utf-8"), source=DEFAULT_RULES_RESOURCE)
    return parse_rules(path.read_text(encoding="utf-8"), source=str(path))
