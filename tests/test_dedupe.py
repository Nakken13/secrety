from secrety.models import DetectionMethod, Finding
from secrety.scanner import merge_duplicates

LINE = "x" * 200


def _finding(
    rule_id: str,
    column: int,
    secret: str,
    confidence: float,
    method: DetectionMethod = DetectionMethod.REGEX,
    line: int = 1,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        description=rule_id,
        path="a.py",
        line=line,
        column=column,
        secret=secret,
        line_content=LINE,
        method=method,
        confidence=confidence,
    )


def test_same_span_keeps_highest_confidence_and_records_the_others() -> None:
    generic = _finding("generic-password-assignment", 10, "S" * 40, 0.4)
    aws = _finding("aws-secret-access-key", 10, "S" * 40, 0.85)
    entropy = _finding("high-entropy-base64", 10, "S" * 40, 0.5, DetectionMethod.ENTROPY)
    [kept] = merge_duplicates([generic, aws, entropy])
    assert kept.rule_id == "aws-secret-access-key"
    assert kept.also_matched == (
        ("generic-password-assignment", DetectionMethod.REGEX),
        ("high-entropy-base64", DetectionMethod.ENTROPY),
    )
    assert kept.methods == (DetectionMethod.REGEX, DetectionMethod.ENTROPY)


def test_overlap_is_transitive() -> None:
    # A JWT is one regex match but three entropy tokens ("." is not base64).
    jwt = _finding("jwt", 1, "J" * 60, 0.6)
    parts = [
        _finding("high-entropy-base64", c, "P" * 20, 0.6, DetectionMethod.ENTROPY)
        for c in (1, 22, 43)
    ]
    [kept] = merge_duplicates([*parts, jwt])
    assert kept.rule_id == "jwt"
    assert len(kept.also_matched) == 3


def test_tie_goes_to_regex_then_earliest_column() -> None:
    entropy = _finding("high-entropy-base64", 5, "E" * 30, 0.6, DetectionMethod.ENTROPY)
    regex = _finding("jwt", 8, "R" * 30, 0.6)
    assert merge_duplicates([entropy, regex])[0].rule_id == "jwt"
    first = _finding("rule-a", 8, "A" * 30, 0.6)
    second = _finding("rule-b", 5, "B" * 30, 0.6)
    assert merge_duplicates([first, second])[0].rule_id == "rule-b"


def test_disjoint_spans_and_other_lines_are_kept_in_position_order() -> None:
    a = _finding("rule-a", 1, "A" * 10, 0.9)
    b = _finding("rule-b", 11, "B" * 10, 0.9)  # starts right where a ends
    c = _finding("rule-c", 1, "A" * 10, 0.9, line=2)
    kept = merge_duplicates([c, b, a])
    assert [f.rule_id for f in kept] == ["rule-a", "rule-b", "rule-c"]
    assert all(f.also_matched == () for f in kept)


def test_single_finding_reports_its_own_method() -> None:
    finding = _finding("rule-a", 1, "A" * 10, 0.9)
    assert finding.methods == (DetectionMethod.REGEX,)
