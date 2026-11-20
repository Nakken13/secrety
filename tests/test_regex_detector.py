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
