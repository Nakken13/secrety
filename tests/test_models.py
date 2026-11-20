import pytest

from secrety.models import DetectionMethod, Finding


def make_finding(**overrides: object) -> Finding:
    data: dict[str, object] = {
        "rule_id": "aws-access-key-id",
        "description": "AWS access key ID",
        "path": "config/settings.py",
        "line": 12,
        "column": 9,
        "secret": "AKIAFAKEEXAMPLE23456",
        "line_content": 'KEY = "AKIAFAKEEXAMPLE23456"',
        "method": DetectionMethod.REGEX,
        "confidence": 0.9,
    }
    data.update(overrides)
    return Finding(**data)  # type: ignore[arg-type]


def test_masked_keeps_only_edges() -> None:
    finding = make_finding()
    assert finding.masked() == "AKIA************3456"
    assert "FAKEEXAMPLE" not in finding.masked()


def test_masked_short_secret_is_fully_hidden() -> None:
    assert make_finding(secret="abc12345").masked() == "********"


def test_location_without_commit() -> None:
    assert make_finding().location == "config/settings.py:12:9"


def test_location_with_commit_uses_short_sha() -> None:
    finding = make_finding(commit="0123456789abcdef0123")
    assert finding.location == "0123456789ab:config/settings.py:12:9"


def test_fingerprint_is_stable_and_hides_secret() -> None:
    a, b = make_finding(), make_finding()
    assert a.fingerprint == b.fingerprint
    assert "AKIA" not in a.fingerprint
    assert make_finding(line=13).fingerprint != a.fingerprint


@pytest.mark.parametrize("value", [-0.1, 1.5])
def test_confidence_must_be_a_probability(value: float) -> None:
    with pytest.raises(ValueError, match="confidence"):
        make_finding(confidence=value)


def test_finding_is_immutable() -> None:
    finding = make_finding()
    with pytest.raises(AttributeError):
        finding.line = 3  # type: ignore[misc]
