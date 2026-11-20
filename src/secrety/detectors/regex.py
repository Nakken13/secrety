"""Rule-based detection: one regular expression per known secret format."""

from collections.abc import Iterator, Sequence

from secrety.models import DetectionMethod, Finding
from secrety.rules import Rule


def iter_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, line)`` pairs, splitting on line feeds only.

    ``str.splitlines`` also breaks on form feeds, vertical tabs or U+2028,
    which would shift line numbers compared with Git, editors and SARIF. A
    trailing carriage return (Windows line ending) is removed.
    """
    for number, line in enumerate(text.split("\n"), start=1):
        yield number, line.removesuffix("\r")


class RegexDetector:
    """Match each line against a set of :class:`~secrety.rules.Rule`.

    Scanning is line by line, which gives exact line/column positions. The
    trade-off: a secret split across lines is missed (a PEM key is still
    caught through its one-line header). Every line is scanned, however long:
    the default rules use bounded quantifiers, so their cost stays linear even
    on minified code.

    Keywords act as a two-level pre-filter, both computed from one lowercase
    copy of the file: rules whose keywords appear nowhere in the file are
    dropped once, then the remaining rules only run on lines containing one
    of their keywords.
    """

    def __init__(self, rules: Sequence[Rule]) -> None:
        """Create a detector for ``rules`` (see :func:`secrety.rules.load_rules`)."""
        self.rules = tuple(rules)

    def scan(self, text: str, path: str) -> Iterator[Finding]:
        """Yield a finding for every rule match in ``text``.

        Args:
            text: Content of one file.
            path: Path reported in findings.
        """
        lowered_text = text.lower()
        active = self._rules_for(lowered_text)
        if not active:
            return
        # lower() never adds or removes line feeds, so both sides have the same lines.
        lowered_lines = (line for _, line in iter_lines(lowered_text))
        for (line_no, line), lowered in zip(iter_lines(text), lowered_lines, strict=True):
            for rule in active:
                if rule.keywords and not any(k in lowered for k in rule.keywords):
                    continue
                yield from self._match_line(rule, line, line_no, path)

    def _rules_for(self, lowered_text: str) -> tuple[Rule, ...]:
        """Keep the rules that have no keyword or whose keyword occurs in the file."""
        return tuple(
            rule
            for rule in self.rules
            if not rule.keywords or any(k in lowered_text for k in rule.keywords)
        )

    @staticmethod
    def _match_line(rule: Rule, line: str, line_no: int, path: str) -> Iterator[Finding]:
        """Yield findings for every match of ``rule`` on a single line."""
        for match in rule.pattern.finditer(line):
            secret = match.group(rule.secret_group)
            if not secret:
                continue
            yield Finding(
                rule_id=rule.id,
                description=rule.description,
                path=path,
                line=line_no,
                column=match.start(rule.secret_group) + 1,
                secret=secret,
                line_content=line,
                method=DetectionMethod.REGEX,
                confidence=rule.confidence,
            )
