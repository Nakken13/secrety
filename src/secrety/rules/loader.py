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
        paths: ['*.env']     # optional: only files whose name matches a glob

Every problem is reported as a :class:`RuleError` naming the file and the
rule, so that a typo in a custom rule never fails silently.
"""

from __future__ import annotations

import re
import re._parser as _sre_parser  # the parser behind re.compile (3.11+)
from collections.abc import Iterable
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

DEFAULT_RULES_RESOURCE = "default_rules.yaml"
DEFAULT_CONFIDENCE = 0.5
# Greedy, lazy and possessive (a++, Python 3.11+) repetitions.
_REPEATS = frozenset(
    {_sre_parser.MAX_REPEAT, _sre_parser.MIN_REPEAT, _sre_parser.POSSESSIVE_REPEAT}
)
SUPPORTED_VERSION = 1
_REQUIRED = ("id", "description", "regex")
_OPTIONAL = ("secret_group", "confidence", "keywords", "paths")


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
        paths: Lowercase globs on the file name (``*.env``); empty = every file.
    """

    id: str
    description: str
    pattern: re.Pattern[str]
    secret_group: int = 0
    confidence: float = DEFAULT_CONFIDENCE
    keywords: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()


def _is_number(value: Any, *, integer: bool = False) -> bool:
    """True for YAML ints/floats, rejecting booleans (``bool`` is an ``int`` in Python)."""
    kinds: type | tuple[type, ...] = int if integer else (int, float)
    return isinstance(value, kinds) and not isinstance(value, bool)


def _lowercase_strings(raw: dict[str, Any], key: str, where: str) -> tuple[str, ...]:
    """Validate the optional list-of-strings field ``key`` and lowercase it."""
    values = raw.get(key) or []
    if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values):
        raise RuleError(f"{where}: {key} must be a list of non-empty strings")
    return tuple(v.lower() for v in values)


def _build_rule(raw: Any, index: int, source: str) -> Rule:
    """Validate one raw YAML mapping and turn it into a :class:`Rule`."""
    where = f"{source}: rule #{index}"
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: expected a mapping, got {type(raw).__name__}")

    for name in _REQUIRED:
        if not raw.get(name):
            raise RuleError(f"{where}: missing required field '{name}'")
        if not isinstance(raw[name], str):
            raise RuleError(f"{where}: field '{name}' must be a string, got {raw[name]!r}")
    unknown = set(raw) - set(_REQUIRED) - set(_OPTIONAL)
    if unknown:
        raise RuleError(f"{where} ({raw['id']}): unknown field(s) {sorted(unknown)}")

    where = f"{where} ({raw['id']})"
    try:
        pattern = re.compile(raw["regex"])
    except re.error as exc:
        raise RuleError(f"{where}: invalid regex: {exc}") from exc

    secret_group = raw.get("secret_group", 0)
    if not _is_number(secret_group, integer=True) or not 0 <= secret_group <= pattern.groups:
        raise RuleError(
            f"{where}: secret_group={secret_group!r} but the regex has {pattern.groups} group(s)"
        )

    confidence = raw.get("confidence", DEFAULT_CONFIDENCE)
    if not _is_number(confidence) or not 0.0 <= confidence <= 1.0:
        raise RuleError(f"{where}: confidence must be a number in [0, 1], got {confidence!r}")

    keywords = _lowercase_strings(raw, "keywords", where)
    paths = _lowercase_strings(raw, "paths", where)
    if any("/" in p for p in paths):
        raise RuleError(f"{where}: paths are matched on the file name only, '/' cannot match")

    return Rule(
        id=raw["id"],
        description=raw["description"],
        pattern=pattern,
        secret_group=secret_group,
        confidence=float(confidence),
        keywords=keywords,
        paths=paths,
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
    version = document.get("version", SUPPORTED_VERSION)
    if version != SUPPORTED_VERSION:
        raise RuleError(f"{source}: unsupported version {version!r} (expected {SUPPORTED_VERSION})")
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
    """Load rules from ``path``, or the bundled default rules when ``None``.

    Raises:
        RuleError: If the file cannot be read or decoded, or is malformed.
    """
    if path is None:
        resource = files("secrety.rules").joinpath(DEFAULT_RULES_RESOURCE)
        return parse_rules(resource.read_text(encoding="utf-8"), source=DEFAULT_RULES_RESOURCE)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuleError(f"{path}: cannot read rules file: {exc}") from exc
    return parse_rules(text, source=str(path))


def unbounded_quantifiers(pattern: str) -> list[str]:
    r"""Return the unbounded repetitions (``+``, ``*``, ``{n,}``, lazy too) in ``pattern``.

    The regex is parsed by the standard library's own parser, so escaped
    characters (``\+``) and character classes (``[+*]``) are not mistaken for
    quantifiers. An unbounded repetition followed by more pattern can backtrack
    for a long time on a long line (ReDoS); the bundled rules bound every one.
    """
    found: list[str] = []
    _collect_unbounded(_sre_parser.parse(pattern), found)
    return found


def _collect_unbounded(node: Any, found: list[str]) -> None:
    """Walk a parsed regex, appending a label for each unbounded repetition."""
    for op, av in node:
        if op in _REPEATS:
            low, high, _ = av
            if high == _sre_parser.MAXREPEAT:
                found.append({0: "*", 1: "+"}.get(low, f"{{{low},}}"))
        _collect_in(av, found)


def _collect_in(value: Any, found: list[str]) -> None:
    """Recurse into every sub-pattern nested in an opcode argument."""
    if isinstance(value, _sre_parser.SubPattern):
        _collect_unbounded(value, found)
    elif isinstance(value, tuple | list):
        for item in value:
            _collect_in(item, found)


def unbounded_rule_warnings(rules: Iterable[Rule]) -> list[str]:
    """Return one warning per rule whose regex has an unbounded repetition."""
    warnings = []
    for rule in rules:
        if quantifiers := unbounded_quantifiers(rule.pattern.pattern):
            warnings.append(
                f"rule {rule.id!r}: unbounded quantifier(s) {' '.join(quantifiers)} "
                "can make a scan very slow on long lines (ReDoS); bound them, e.g. {1,256}."
            )
    return warnings
