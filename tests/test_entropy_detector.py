import math
import string

import pytest

import fakes
from secrety.config import EntropyConfig
from secrety.detectors.entropy import Charset, EntropyDetector, iter_candidates, shannon_entropy
from secrety.models import DetectionMethod, Finding

# --- Shannon entropy -------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", 0.0),
        ("aaaa", 0.0),
        ("aabb", 1.0),
        ("abcd", 2.0),
        ("0123456789abcdef", 4.0),
        (string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/", 6.0),
    ],
)
def test_shannon_entropy_known_values(value: str, expected: float) -> None:
    assert shannon_entropy(value) == pytest.approx(expected)


def test_entropy_is_capped_by_length() -> None:
    # n distinct characters give exactly log2(n): the maximum for that length.
    value = string.ascii_letters[:20]
    assert shannon_entropy(value) == pytest.approx(math.log2(20))


# --- Tokenizer -------------------------------------------------------------


def test_candidate_hex_token_is_classified_hex() -> None:
    line = "digest = 0123456789abcdef0123456789abcdef"
    [(column, token, charset)] = iter_candidates(line, min_length=20)
    assert token == "0123456789abcdef0123456789abcdef"
    assert column == line.index(token)
    assert charset is Charset.HEX


def test_candidate_base64_token_keeps_padding() -> None:
    line = 'key: "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo+/w=="'
    [(_, token, charset)] = iter_candidates(line, min_length=20)
    assert token == "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo+/w=="
    assert charset is Charset.BASE64


def test_candidate_shorter_than_min_length_is_ignored() -> None:
    assert list(iter_candidates("x = abcdef0123", min_length=20)) == []


def test_pure_digit_tokens_are_ignored() -> None:
    # Timestamps, IDs and phone numbers are hex-looking but never secrets.
    assert list(iter_candidates("id = 123456789012345678901234", min_length=20)) == []


def test_several_candidates_on_one_line() -> None:
    a, b = "A" * 10 + "b" * 10, "0123456789abcdef" * 2
    tokens = [token for _, token, _ in iter_candidates(f"{a}.{b}", min_length=20)]
    assert tokens == [a, b]


# --- Detector --------------------------------------------------------------


def _scan(text: str, path: str = "app.py", config: EntropyConfig | None = None) -> list[Finding]:
    return list(EntropyDetector(config or EntropyConfig()).scan(text, path))


def test_detector_flags_high_entropy_base64() -> None:
    line = f'token = "{fakes.HIGH_ENTROPY_BASE64}"'
    [finding] = _scan(f"x = 1\n{line}\n")
    assert finding.rule_id == "high-entropy-base64"
    assert finding.method is DetectionMethod.ENTROPY
    assert finding.secret == fakes.HIGH_ENTROPY_BASE64
    assert (finding.line, finding.column) == (2, line.index(fakes.HIGH_ENTROPY_BASE64) + 1)
    assert finding.line_content == line
    assert 0.3 <= finding.confidence <= 0.6


def test_detector_flags_high_entropy_hex() -> None:
    [finding] = _scan(f"digest = {fakes.HIGH_ENTROPY_HEX}\n")
    assert finding.rule_id == "high-entropy-hex"


@pytest.mark.parametrize(
    "line",
    [
        "def test_scan_reports_findings_masked_and_exits_one() -> None:",
        "from src/secrety/detectors/entropy import x",
        "id = 550e8400-e29b-41d4-a716-446655440000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ],
)
def test_detector_ignores_low_entropy_tokens(line: str) -> None:
    assert _scan(line) == []


def test_thresholds_are_configurable() -> None:
    text = f"digest = {fakes.HIGH_ENTROPY_HEX}\n"  # entropy exactly 4.0
    assert _scan(text, config=EntropyConfig(hex_threshold=4.0)) != []  # threshold inclusive
    assert _scan(text, config=EntropyConfig(min_length=33)) == []  # token is 32 long
    assert (
        _scan(f"x = {fakes.HIGH_ENTROPY_BASE64}", config=EntropyConfig(base64_threshold=5.5)) == []
    )


def test_confidence_grows_with_entropy() -> None:
    low = EntropyConfig(base64_threshold=3.0)
    [weak] = _scan("x = " + "ab" * 6 + "cdefgh" * 2 + "ijkl", config=low)
    [strong] = _scan(f"x = {fakes.HIGH_ENTROPY_BASE64}", config=low)
    assert weak.confidence < strong.confidence
