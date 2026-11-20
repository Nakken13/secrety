import pytest

import fakes
from secrety.models import DetectionMethod, Finding


def make_finding(**overrides: object) -> Finding:
    data: dict[str, object] = {
        "rule_id": "aws-access-key-id",
        "description": "AWS access key ID",
        "path": "config/settings.py",
        "line": 12,
        "column": 9,
        "secret": fakes.AWS_ACCESS_KEY_ID,
        "line_content": f'KEY = "{fakes.AWS_ACCESS_KEY_ID}"',
        "method": DetectionMethod.REGEX,
        "confidence": 0.9,
    }
    data.update(overrides)
    return Finding(**data)  # type: ignore[arg-type]


def test_masked_long_secret_shows_at_most_four_chars_per_edge() -> None:
    secret = "A" * 4 + "x" * 32 + "B" * 4  # 40 chars
    assert make_finding(secret=secret).masked() == "AAAA" + "*" * 32 + "BBBB"


@pytest.mark.parametrize("length", [20, 24, 33, 40, 64, 100])
def test_masked_never_reveals_more_than_a_quarter(length: int) -> None:
    masked = make_finding(secret="s" * length).masked()
    assert len(masked) == length
    assert masked.count("s") <= length // 4


@pytest.mark.parametrize("length", [1, 8, 9, 12, 19])
def test_masked_short_secret_is_fully_hidden(length: int) -> None:
    # Short values are typically passwords: even 8 visible chars of a 12-char
    # password would leak most of it.
    assert make_finding(secret="p" * length).masked() == "*" * length


def test_repr_never_contains_the_secret() -> None:
    finding = make_finding()
    assert fakes.AWS_ACCESS_KEY_ID not in repr(finding)


def test_location_without_commit() -> None:
    assert make_finding().location == "config/settings.py:12:9"


def test_location_with_commit_uses_short_sha() -> None:
    finding = make_finding(commit="0123456789abcdef0123")
    assert finding.location == "0123456789ab:config/settings.py:12:9"


def test_fingerprint_is_stable_and_never_depends_on_the_secret() -> None:
    a = make_finding()
    assert a.fingerprint == make_finding().fingerprint
    # The secret is not hashed at all, so a published fingerprint cannot be
    # brute-forced back into a short password.
    other = make_finding(secret="other", line_content='KEY = "other"')
    assert other.fingerprint == a.fingerprint


def test_fingerprint_survives_line_shifts_but_not_file_or_commit_changes() -> None:
    a = make_finding()
    assert make_finding(line=40, column=1).fingerprint == a.fingerprint
    assert make_finding(path="other.py").fingerprint != a.fingerprint
    assert make_finding(commit="abc").fingerprint != a.fingerprint
    assert make_finding(rule_id="jwt").fingerprint != a.fingerprint


@pytest.mark.parametrize("value", [-0.1, 1.5])
def test_confidence_must_be_a_probability(value: float) -> None:
    with pytest.raises(ValueError, match="confidence"):
        make_finding(confidence=value)


def test_finding_is_immutable() -> None:
    finding = make_finding()
    with pytest.raises(AttributeError):
        finding.line = 3  # type: ignore[misc]
