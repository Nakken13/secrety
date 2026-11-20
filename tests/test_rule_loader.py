from pathlib import Path

import pytest

from secrety.rules import Rule, RuleError, load_rules, parse_rules

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
