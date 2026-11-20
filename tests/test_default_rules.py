"""Each default rule must catch its format and ignore look-alikes.

Positive cases: (line of code, expected secret). Negative cases: lines that a
naive rule would flag but this one must not.
"""

import re._constants as _constants
import re._parser as _parser

import pytest

import fakes
from secrety.detectors import RegexDetector
from secrety.rules import Rule, load_rules

RULES: dict[str, Rule] = {rule.id: rule for rule in load_rules()}

POSITIVE: dict[str, list[tuple[str, str]]] = {
    "aws-access-key-id": [(f'key = "{fakes.AWS_ACCESS_KEY_ID}"', fakes.AWS_ACCESS_KEY_ID)],
    "aws-secret-access-key": [
        (f"aws_secret_access_key = {fakes.AWS_SECRET_ACCESS_KEY}", fakes.AWS_SECRET_ACCESS_KEY),
        (f'AWS_SECRET_KEY: "{fakes.AWS_SECRET_ACCESS_KEY}"', fakes.AWS_SECRET_ACCESS_KEY),
        # AWS CLI / STS JSON output
        (f'"SecretAccessKey": "{fakes.AWS_SECRET_ACCESS_KEY}",', fakes.AWS_SECRET_ACCESS_KEY),
        # Terraform provider block
        (f'  secret_key = "{fakes.AWS_SECRET_ACCESS_KEY}"', fakes.AWS_SECRET_ACCESS_KEY),
    ],
    "github-token": [(f"token={fakes.GITHUB_TOKEN}", fakes.GITHUB_TOKEN)],
    "github-fine-grained-pat": [
        (f"GH_TOKEN={fakes.GITHUB_FINE_GRAINED_PAT}", fakes.GITHUB_FINE_GRAINED_PAT)
    ],
    "stripe-secret-key": [
        (f"stripe.api_key = '{fakes.STRIPE_SECRET_KEY}'", fakes.STRIPE_SECRET_KEY),
        (f"key: {fakes.STRIPE_RESTRICTED_KEY}", fakes.STRIPE_RESTRICTED_KEY),
        (f"key: {fakes.STRIPE_LONG_SECRET_KEY}", fakes.STRIPE_LONG_SECRET_KEY),
    ],
    "slack-token": [
        (f"SLACK_BOT_TOKEN={fakes.SLACK_TOKEN}", fakes.SLACK_TOKEN),
        (f"SLACK_APP_TOKEN={fakes.SLACK_APP_TOKEN}", fakes.SLACK_APP_TOKEN),
        (f"refresh: {fakes.SLACK_ROTATING_TOKEN}", fakes.SLACK_ROTATING_TOKEN),
    ],
    "slack-webhook": [(f'url = "{fakes.SLACK_WEBHOOK}"', fakes.SLACK_WEBHOOK)],
    "google-api-key": [(f"const key = '{fakes.GOOGLE_API_KEY}';", fakes.GOOGLE_API_KEY)],
    "jwt": [(f"Authorization: Bearer {fakes.JWT}", fakes.JWT)],
    "private-key": [
        (fakes.PRIVATE_KEY_HEADER, fakes.PRIVATE_KEY_HEADER),
        (fakes.DH_PRIVATE_KEY_HEADER, fakes.DH_PRIVATE_KEY_HEADER),
    ],
    "putty-private-key": [(fakes.PUTTY_KEY_HEADER, fakes.PUTTY_KEY_HEADER)],
    "url-credentials": [(f'DATABASE_URL="{fakes.URL_WITH_CREDENTIALS}"', fakes.URL_PASSWORD)],
    "generic-password-assignment": [
        (f'password = "{fakes.GENERIC_PASSWORD}"', fakes.GENERIC_PASSWORD),
        (f"'api_key': '{fakes.GENERIC_PASSWORD}'", fakes.GENERIC_PASSWORD),
        # Keyword inside a longer identifier ("_" is a word character, so the
        # old leading \b missed all of these).
        (f'DB_PASSWORD = "{fakes.GENERIC_PASSWORD}"', fakes.GENERIC_PASSWORD),
        (f'db_password: "{fakes.GENERIC_PASSWORD}"', fakes.GENERIC_PASSWORD),
        (f'client_secret = "{fakes.GENERIC_PASSWORD}"', fakes.GENERIC_PASSWORD),
        (f"SECRET_KEY = '{fakes.GENERIC_PASSWORD}'", fakes.GENERIC_PASSWORD),
        (f'password := "{fakes.GENERIC_PASSWORD}"', fakes.GENERIC_PASSWORD),  # Go
    ],
}

NEGATIVE: dict[str, list[str]] = {
    "aws-access-key-id": ["AKIA" + "fake", "MY" + fakes.AWS_ACCESS_KEY_ID],
    "aws-secret-access-key": [
        f"checksum = {fakes.AWS_SECRET_ACCESS_KEY}",  # 40 chars but no AWS context
        "aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']",
    ],
    "github-token": ["ghp" + "_tooShort123"],
    "github-fine-grained-pat": ["github" + "_pat_" + "short"],
    "stripe-secret-key": ["pk" + "_live_" + fakes.pad("FAKEpublishable", 24)],  # public key
    "slack-token": ["xox" + "z-not-a-real-prefix-0000"],
    "slack-webhook": ["https://hooks.slack.com/services/"],
    "google-api-key": ["AI" + "zaTooShort"],
    "jwt": ["eyJ" + "hbGciOiJIUzI1NiJ9.only-two-parts"],
    "private-key": ["-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----"],
    "putty-private-key": ["PuTTY is a free SSH client"],
    "url-credentials": [
        "https://example.com/path",
        "ssh://git@github.com/org/repo.git",
        "postgres://user:${DB_PASSWORD}@db:5432/app",
        "redis://user:<password>@localhost",
    ],
    "generic-password-assignment": [
        'password = ""',
        "password = os.environ['PASSWORD']",
        'password = "short"',
        'password = "${PASSWORD}"',
        "pwd = os.getcwd()",
        "password_hint = None",
    ],
}


def first_secret(rule: Rule, line: str) -> str | None:
    """Return the secret the real detector reports for ``rule`` on ``line``."""
    finding = next(iter(RegexDetector([rule]).scan(line, "case.txt")), None)
    return finding.secret if finding else None


def test_every_rule_has_positive_and_negative_cases() -> None:
    assert set(POSITIVE) == set(RULES)
    assert set(NEGATIVE) == set(RULES)


def test_default_rules_have_keywords() -> None:
    for rule in RULES.values():
        assert rule.keywords, f"{rule.id} has no pre-filter keyword"


def test_keywords_appear_in_positive_cases() -> None:
    """The pre-filter must never hide a true positive."""
    for rule_id, cases in POSITIVE.items():
        for line, _ in cases:
            lowered = line.lower()
            assert any(k in lowered for k in RULES[rule_id].keywords), (rule_id, line)


@pytest.mark.parametrize(
    ("rule_id", "line", "expected"),
    [(rid, line, secret) for rid, cases in POSITIVE.items() for line, secret in cases],
)
def test_rule_detects_fake_secret(rule_id: str, line: str, expected: str) -> None:
    assert first_secret(RULES[rule_id], line) == expected


@pytest.mark.parametrize(
    ("rule_id", "line"),
    [(rid, line) for rid, lines in NEGATIVE.items() for line in lines],
)
def test_rule_ignores_look_alike(rule_id: str, line: str) -> None:
    assert first_secret(RULES[rule_id], line) is None


def test_fake_values_are_marked() -> None:
    """Guard rail: test secrets must stay visibly fake."""
    for name in dir(fakes):
        value = getattr(fakes, name)
        public_constant = name.isupper() and not name.startswith("_")
        if public_constant and isinstance(value, str) and name not in fakes.UNMARKABLE:
            assert "FAKE" in value or "EXAMPLE" in value, name


def _unbounded_repeats(parsed: object) -> int:
    """Count repeats with no upper bound in a parsed regex (``re._parser`` tree)."""
    count = 0
    for op, arg in parsed:  # type: ignore[attr-defined]
        if op in (_constants.MAX_REPEAT, _constants.MIN_REPEAT):
            _low, high, sub = arg
            count += high == _constants.MAXREPEAT
            count += _unbounded_repeats(sub)
        elif op is _constants.SUBPATTERN:
            count += _unbounded_repeats(arg[-1])
        elif op is _constants.BRANCH:
            count += sum(_unbounded_repeats(branch) for branch in arg[1])
        elif op in (_constants.ASSERT, _constants.ASSERT_NOT):
            count += _unbounded_repeats(arg[1])
    return count


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_default_rules_have_only_bounded_quantifiers(rule_id: str) -> None:
    """ReDoS guard: no `*`, `+` or `{n,}` anywhere in a bundled rule."""
    parsed = _parser.parse(RULES[rule_id].pattern.pattern)
    assert _unbounded_repeats(parsed) == 0
