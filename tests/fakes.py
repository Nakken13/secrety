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
