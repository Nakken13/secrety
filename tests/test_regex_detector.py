import time

import pytest

import fakes
from secrety.detectors import Detector, RegexDetector
from secrety.models import DetectionMethod
from secrety.rules import load_rules, parse_rules


def test_regex_detector_satisfies_protocol() -> None:
    assert isinstance(RegexDetector(load_rules()), Detector)


def test_finds_secret_with_line_and_column() -> None:
    text = f'import os\n\nKEY = "{fakes.AWS_ACCESS_KEY_ID}"\n'
    (finding,) = RegexDetector(load_rules()).scan(text, "app/settings.py")
    assert finding.rule_id == "aws-access-key-id"
    assert finding.path == "app/settings.py"
    assert (finding.line, finding.column) == (3, 8)
    assert finding.secret == fakes.AWS_ACCESS_KEY_ID
    assert finding.line_content == f'KEY = "{fakes.AWS_ACCESS_KEY_ID}"'
    assert finding.method is DetectionMethod.REGEX
    assert finding.confidence == 0.9


def test_column_points_to_secret_group_not_whole_match() -> None:
    line = f"DATABASE_URL={fakes.URL_WITH_CREDENTIALS}"
    (finding,) = RegexDetector(load_rules()).scan(line, "x.env")
    assert line[finding.column - 1 :].startswith(fakes.URL_PASSWORD)


def test_several_matches_on_one_line_and_several_lines() -> None:
    text = f"a={fakes.GITHUB_TOKEN} b={fakes.STRIPE_SECRET_KEY}\nc={fakes.GOOGLE_API_KEY}\n"
    findings = list(RegexDetector(load_rules()).scan(text, "f.txt"))
    assert [(f.rule_id, f.line) for f in findings] == [
        ("github-token", 1),
        ("stripe-secret-key", 1),
        ("google-api-key", 2),
    ]


def test_keyword_prefilter_skips_regex() -> None:
    # Regex would match, but the line lacks the keyword: the pre-filter wins.
    rules = parse_rules("rules:\n  - {id: r, description: R, regex: 'abc', keywords: [zzz]}\n")
    assert list(RegexDetector(rules).scan("abc", "f")) == []
    assert len(list(RegexDetector(rules).scan("abc ZZZ", "f"))) == 1


def test_rule_without_keywords_always_runs() -> None:
    rules = parse_rules("rules:\n  - {id: r, description: R, regex: 'abc'}\n")
    assert len(list(RegexDetector(rules).scan("xabcx", "f"))) == 1


def test_empty_match_is_ignored() -> None:
    rules = parse_rules("rules:\n  - {id: r, description: R, regex: 'a(b?)', secret_group: 1}\n")
    assert list(RegexDetector(rules).scan("a", "f")) == []


def test_clean_text_yields_nothing() -> None:
    assert list(RegexDetector(load_rules()).scan("print('hello')\n", "hello.py")) == []


ADVERSARIAL_LINES = {
    # Worst cases found by measurement: with unbounded quantifiers, every word
    # boundary starts a scan to the end of the line, so time grows as n^2
    # (url-credentials took 2.4 s here, jwt 3+ s).
    "url": "a." * 20_000 + "://x",
    "jwt": "eyJ-" * 20_000,
    "password": "password = '" + "x" * 50_000,
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL_LINES))
def test_adversarial_lines_scan_fast(name: str) -> None:
    detector = RegexDetector(load_rules())
    start = time.perf_counter()
    list(detector.scan(ADVERSARIAL_LINES[name], "minified.js"))
    assert time.perf_counter() - start < 1.0


def test_line_numbers_count_only_newlines() -> None:
    # str.splitlines() also splits on form feed, vertical tab, U+2028...
    # Git, editors and SARIF count only "\n".
    text = "a\x0cb\u2028c\n" + f"k={fakes.GITHUB_TOKEN}\n"
    (finding,) = RegexDetector(load_rules()).scan(text, "f")
    assert finding.line == 2


def test_crlf_lines_are_reported_without_carriage_return() -> None:
    text = f"first\r\nk={fakes.GITHUB_TOKEN}\r\n"
    (finding,) = RegexDetector(load_rules()).scan(text, "f")
    assert finding.line == 2
    assert finding.line_content == f"k={fakes.GITHUB_TOKEN}"


def test_long_lines_are_scanned_by_default() -> None:
    # Minified bundles often embed keys; with bounded rules there is no need
    # to drop long lines.
    line = "x " * 100_000 + fakes.GOOGLE_API_KEY
    (finding,) = RegexDetector(load_rules()).scan(line, "bundle.min.js")
    assert finding.rule_id == "google-api-key"


@pytest.mark.parametrize(
    ("path", "flagged"),
    [("app.env", True), ("deploy/prod.ENV", True), ("app.py", False), ("env/app.py", False)],
)
def test_rule_with_paths_only_runs_on_matching_file_names(path: str, flagged: bool) -> None:
    rules = parse_rules("rules:\n  - {id: r, description: R, regex: 'abc', paths: ['*.env']}\n")
    assert bool(list(RegexDetector(rules).scan("abc", path))) is flagged
