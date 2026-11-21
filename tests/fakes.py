"""Builders for FAKE secret values used in tests.

Values are assembled at runtime from harmless fragments, so this repository's
source never contains a literal string matching a real provider format. That
keeps secrety's own self-scan clean and avoids tripping GitHub push protection.
Every value contains a visible ``FAKE`` / ``EXAMPLE`` marker where the format
allows it. None of them is, or ever was, a real credential.
"""

_PAD = "0123456789abcdefghij" * 10


def pad(start: str, length: int) -> str:
    """Return ``start`` padded with harmless characters to exactly ``length``."""
    return (start + _PAD)[:length]


AWS_ACCESS_KEY_ID = "AKIA" + "FAKEEXAMPLE23456"
AWS_SECRET_ACCESS_KEY = "fakeEXAMPLEsecretKEY/" + "0123456789+abcdefgh"
GITHUB_TOKEN = "ghp" + "_" + pad("FAKEtestTOKEN", 36)
GITHUB_FINE_GRAINED_PAT = "github" + "_pat_" + pad("FAKE_test_", 82)
STRIPE_SECRET_KEY = "sk" + "_live_" + pad("FAKEtest", 24)
STRIPE_RESTRICTED_KEY = "rk" + "_test_" + pad("FAKEtest", 30)
SLACK_TOKEN = "xox" + "b-" + "FAKE-0000000000-test"
SLACK_WEBHOOK = (
    "https://hooks.slack.com" + "/services/" + "TFAKE0000/BFAKE0000/" + pad("FAKEtest", 24)
)
GOOGLE_API_KEY = "AI" + "za" + pad("FAKE_test-", 35)
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiJGQUtFIn0" + "." + pad("FAKEsig", 22)
PRIVATE_KEY_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"
URL_PASSWORD = "FAKEpassw0rd"
URL_WITH_CREDENTIALS = "postgres://" + "admin:" + URL_PASSWORD + "@db.example.com:5432/app"
GENERIC_PASSWORD = "FAKE-hunter2-EXAMPLE"
STRIPE_LONG_SECRET_KEY = "sk" + "_live_" + pad("FAKElong", 120)
SLACK_APP_TOKEN = "xapp" + "-1-AFAKE0000-" + pad("0000FAKE", 30)
SLACK_ROTATING_TOKEN = "xoxe" + "-1-" + pad("FAKErotating", 40)
DH_PRIVATE_KEY_HEADER = "-----BEGIN " + "DH PRIVATE KEY-----"
PUTTY_KEY_HEADER = "PuTTY-User-Key-File-" + "3: ssh-ed25519"
# Random-looking values with no provider format, for the entropy detector.
HIGH_ENTROPY_BASE64 = "FAKE" + "aB3dE5gH7jK9mN1p" + "Q2rS4tU6vW8xY0zLc"
HIGH_ENTROPY_HEX = "0123456789abcdef" + "fedcba9876543210"
ENV_PASSWORD = "FAKE!pa55-EXAMPLE"

# Key-file headers are fixed strings with no key material, and hex digits
# stop at "f": no FAKE marker fits in them. Listed here, next to the values,
# so a new exemption is made where the value is declared.
UNMARKABLE = frozenset(
    {"PRIVATE_KEY_HEADER", "DH_PRIVATE_KEY_HEADER", "PUTTY_KEY_HEADER", "HIGH_ENTROPY_HEX"}
)
