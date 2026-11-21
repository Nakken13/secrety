from pathlib import Path

import pytest

from secrety.rules import (
    Rule,
    RuleError,
    load_rules,
    parse_rules,
    unbounded_quantifiers,
    unbounded_rule_warnings,
)

VALID = r"""
version: 1
rules:
  - id: demo-token
    description: Demo token
    regex: '\b(demo_[a-z0-9]{8})\b'
    secret_group: 1
    confidence: 0.8
    keywords: [demo_]
"""


def test_parse_valid_rule() -> None:
    (rule,) = parse_rules(VALID)
    assert isinstance(rule, Rule)
    assert rule.id == "demo-token"
    assert rule.secret_group == 1
    assert rule.confidence == 0.8
    assert rule.keywords == ("demo_",)
    assert rule.pattern.search("x = demo_abcd1234")


def test_defaults_when_optional_fields_missing() -> None:
    (rule,) = parse_rules("rules:\n  - id: a\n    description: A\n    regex: 'abc'\n")
    assert rule.secret_group == 0
    assert rule.confidence == 0.5
    assert rule.keywords == ()


def test_load_rules_from_file(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text(VALID, encoding="utf-8")
    assert [r.id for r in load_rules(path)] == ["demo-token"]


@pytest.mark.parametrize(
    ("yaml_text", "message"),
    [
        ("rules:\n  - id: a\n    description: A\n    regex: '(unclosed'\n", "invalid regex"),
        ("rules:\n  - id: a\n    regex: 'x'\n", "description"),
        ("rules:\n  - description: A\n    regex: 'x'\n", "id"),
        (
            "rules:\n"
            "  - {id: a, description: A, regex: x}\n"
            "  - {id: a, description: B, regex: y}\n",
            "duplicate",
        ),
        ("rules:\n  - {id: a, description: A, regex: x, confidence: 2}\n", "confidence"),
        ("rules:\n  - {id: a, description: A, regex: 'x', secret_group: 3}\n", "secret_group"),
        ("rules:\n  - {id: a, description: A, regex: x, colour: red}\n", "unknown"),
        ("rules: {}\n", "list"),
        ("- just a list\n", "rules"),
        ("rules: [\n", "YAML"),
    ],
)
def test_invalid_rules_raise_clear_error(yaml_text: str, message: str) -> None:
    with pytest.raises(RuleError, match=message):
        parse_rules(yaml_text, source="test.yaml")


def test_error_names_source_and_rule() -> None:
    with pytest.raises(RuleError, match=r"test\.yaml.*rule #1"):
        parse_rules("rules:\n  - id: a\n    regex: 'x'\n", source="test.yaml")


@pytest.mark.parametrize(
    ("yaml_text", "message"),
    [
        ("rules:\n  - {id: a, description: A, regex: '(x)', secret_group: true}\n", "secret_group"),
        ("rules:\n  - {id: a, description: A, regex: x, confidence: true}\n", "confidence"),
        ("rules:\n  - {id: a, description: A, regex: x, keywords: [null]}\n", "keywords"),
        ("rules:\n  - {id: a, description: A, regex: x, keywords: [3]}\n", "keywords"),
        ("version: 2\nrules: []\n", "version"),
    ],
)
def test_loader_rejects_odd_yaml_values(yaml_text: str, message: str) -> None:
    with pytest.raises(RuleError, match=message):
        parse_rules(yaml_text)


def test_version_is_optional() -> None:
    assert parse_rules("rules: []\n") == []


def test_non_utf8_rules_file_raises_rule_error(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_bytes(b"rules: []\n# \xff\xfe\n")
    with pytest.raises(RuleError, match="cannot read"):
        load_rules(path)


def test_unreadable_rules_file_raises_rule_error(tmp_path: Path) -> None:
    with pytest.raises(RuleError, match="cannot read"):
        load_rules(tmp_path)  # a directory cannot be read as a file


@pytest.mark.parametrize("field", ["id", "description", "regex"])
def test_required_fields_must_be_strings(field: str) -> None:
    raw = {"id": "a", "description": "A", "regex": "x"}
    raw[field] = 123  # type: ignore[assignment]
    yaml_text = "rules:\n  - {" + ", ".join(f"{k}: {v}" for k, v in raw.items()) + "}\n"
    with pytest.raises(RuleError, match=field):
        parse_rules(yaml_text)


def test_paths_are_parsed_lowercase() -> None:
    text = "rules:\n  - {id: a, description: A, regex: 'abc', paths: ['*.ENV', '.env*']}\n"
    (rule,) = parse_rules(text)
    assert rule.paths == ("*.env", ".env*")


def test_paths_default_to_every_file() -> None:
    (rule,) = parse_rules("rules:\n  - {id: a, description: A, regex: 'abc'}\n")
    assert rule.paths == ()


@pytest.mark.parametrize("paths", ["'*.env'", "[1]", "['']", "['config/*.yml']"])
def test_invalid_paths_are_rejected(paths: str) -> None:
    with pytest.raises(RuleError, match="paths"):
        parse_rules(f"rules:\n  - {{id: a, description: A, regex: 'abc', paths: {paths}}}\n")


# --- unbounded quantifier lint -------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "count"),
    [
        (r"a+", 1),
        (r"a*", 1),
        (r"a{3,}", 1),
        (r"a+?", 1),  # lazy is still unbounded
        (r"a++", 1),  # possessive too
        (r"(?:a|b*)c+", 2),  # inside groups and alternations
        (r"(?=x+)y", 1),  # inside lookarounds
        (r"a{1,64}", 0),
        (r"a?b{2}c{0,5}?", 0),
        (r"\+\*", 0),  # escaped characters are literals
        (r"[+*]{1,3}", 0),  # inside a character class
        (r"\{3,\}", 0),
    ],
)
def test_unbounded_quantifiers(pattern: str, count: int) -> None:
    assert len(unbounded_quantifiers(pattern)) == count


def test_bundled_rules_have_no_unbounded_quantifier() -> None:
    assert unbounded_rule_warnings(load_rules()) == []


def test_warnings_name_the_rule(tmp_path: Path) -> None:
    rules = parse_rules(
        "version: 1\nrules:\n  - id: greedy\n    description: d\n    regex: 'key=(\\w+)'\n"
    )
    warnings = unbounded_rule_warnings(rules)
    assert len(warnings) == 1
    assert "greedy" in warnings[0]
    assert "unbounded" in warnings[0]
