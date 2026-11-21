import math

import pytest

from secrety.features import FEATURE_NAMES, extract, name_before, name_tokens
from secrety.models import DetectionMethod, Finding


def make_finding(
    secret: str = "FAKEaB3dE5gH7jK9mN1pQ2rS4",
    line_content: str | None = None,
    path: str = "src/app.py",
    method: DetectionMethod = DetectionMethod.REGEX,
    confidence: float = 0.4,
) -> Finding:
    if line_content is None:
        line_content = f'api_key = "{secret}"'
    return Finding(
        rule_id="r",
        description="d",
        path=path,
        line=1,
        column=line_content.index(secret) + 1,
        secret=secret,
        line_content=line_content,
        method=method,
        confidence=confidence,
    )


def features(finding: Finding) -> dict[str, float]:
    return dict(zip(FEATURE_NAMES, extract(finding), strict=True))


def test_one_value_per_feature_name() -> None:
    assert len(extract(make_finding())) == len(FEATURE_NAMES)
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


def test_every_value_is_a_finite_float() -> None:
    values = extract(make_finding())
    assert all(isinstance(v, float) and math.isfinite(v) for v in values)


def test_entropy_and_length() -> None:
    f = features(make_finding(secret="aaaaaaaabbbbbbbb"))
    assert f["entropy"] == pytest.approx(1.0)
    assert f["log_length"] == pytest.approx(math.log(16))


def test_prior_confidence_and_method() -> None:
    f = features(make_finding(method=DetectionMethod.ENTROPY, confidence=0.55))
    assert f["prior_confidence"] == pytest.approx(0.55)
    assert f["method_regex"] == 0.0


@pytest.mark.parametrize(
    ("secret", "expected"),
    [
        ("0123456789abcdef0123", "charset_hex"),
        ("FAKEaB3dE5gH7jK9mN1p", "charset_alnum"),
        ("FAKEaB3dE5gH7jK9+/==", "charset_base64"),
        ("FAKE!pa55-EXAMPLE#", "charset_other"),
    ],
)
def test_charset_class_is_one_hot(secret: str, expected: str) -> None:
    f = features(make_finding(secret=secret))
    classes = {k: v for k, v in f.items() if k.startswith("charset_")}
    assert classes == {k: float(k == expected) for k in classes}


def test_digit_and_case_mix() -> None:
    f = features(make_finding(secret="abcdABCD12"))
    assert f["digit_ratio"] == pytest.approx(0.2)
    assert f["mixed_case"] == 1.0
    assert features(make_finding(secret="abcdefgh12"))["mixed_case"] == 0.0


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('api_key = "VALUE"', "api_key"),
        ('DB_PASSWORD="VALUE"', "DB_PASSWORD"),
        ("password: VALUE", "password"),
        ('"client_secret": "VALUE"', "client_secret"),
        ("export AUTH_TOKEN=VALUE", "AUTH_TOKEN"),
        ("self.secret := 'VALUE'", "self.secret"),
        ('{"token" => "VALUE"}', "token"),
        ("VALUE", ""),
        ('call("VALUE")', ""),
    ],
)
def test_name_before(line: str, expected: str) -> None:
    assert name_before(line, line.index("VALUE")) == expected


@pytest.mark.parametrize(
    ("name", "tokens"),
    [
        ("DB_PASSWORD", ("db", "password")),
        ("clientSecret", ("client", "secret")),
        ("self.api-key", ("self", "api", "key")),
        ("HTTPToken", ("http", "token")),
        ("", ()),
    ],
)
def test_name_tokens(name: str, tokens: tuple[str, ...]) -> None:
    assert name_tokens(name) == tokens


def test_name_features() -> None:
    f = features(make_finding(line_content='DB_PASSWORD = "FAKEaB3dE5gH7jK9mN1pQ2rS4"'))
    assert f["name_secret_word"] == 1.0
    assert f["name_test_word"] == 0.0
    assert f["has_name"] == 1.0
    g = features(make_finding(line_content='mock_token = "FAKEaB3dE5gH7jK9mN1pQ2rS4"'))
    assert g["name_test_word"] == 1.0
    h = features(make_finding(line_content='"FAKEaB3dE5gH7jK9mN1pQ2rS4"'))
    assert (h["has_name"], h["name_secret_word"]) == (0.0, 0.0)


@pytest.mark.parametrize(
    ("secret", "expected"),
    [
        ("your-api-key-here-0000", 1.0),
        ("changeme-changeme-123", 1.0),
        ("xxxxxxxxxxxxxxxxxxxx", 1.0),
        ("FAKEaB3dE5gH7jK9mN1pQ2rS4", 1.0),  # test values are marked FAKE
        ("aB3dE5gH7jK9mN1pQ2rS4tU", 0.0),
    ],
)
def test_placeholder_value(secret: str, expected: float) -> None:
    assert features(make_finding(secret=secret))["value_placeholder"] == expected


def test_value_with_template_or_module_shape() -> None:
    assert features(make_finding(secret="secrety.cli:app"))["value_dotted_name"] == 1.0
    assert features(make_finding(secret="aB3dE5gH7jK9mN1pQ2rS4"))["value_dotted_name"] == 0.0


@pytest.mark.parametrize(
    ("path", "column"),
    [
        ("deploy/.env", "ext_config"),
        ("prod.env", "ext_config"),
        ("config/app.yaml", "ext_config"),
        ("settings.toml", "ext_config"),
        ("src/app.py", "ext_code"),
        ("web/main.ts", "ext_code"),
        ("README.md", "ext_doc"),
        ("notes.txt", "ext_doc"),
    ],
)
def test_file_extension_columns(path: str, column: str) -> None:
    f = features(make_finding(path=path))
    exts = {k: v for k, v in f.items() if k.startswith("ext_")}
    assert exts == {k: float(k == column) for k in exts}


def test_unknown_extension_maps_to_zeros() -> None:
    f = features(make_finding(path="data/blob.xyz"))
    assert all(v == 0.0 for k, v in f.items() if k.startswith("ext_"))


def test_extract_is_deterministic() -> None:
    finding = make_finding()
    assert extract(finding) == extract(finding)
