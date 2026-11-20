"""Rule-based detection: one regular expression per known secret format."""

from collections.abc import Iterator, Sequence

from secrety.models import DetectionMethod, Finding
from secrety.rules import Rule


class RegexDetector:
    """Match each line against a set of :class:`~secrety.rules.Rule`.

    Scanning is line by line, which gives exact line/column positions and keeps
    memory flat on large files. The trade-off: a secret split across lines is
    missed (a PEM key is still caught through its one-line header).
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
        for line_no, line in enumerate(text.splitlines(), start=1):
            lowered = line.lower()
            for rule in self.rules:
                # Cheap substring test before running the regex.
                if rule.keywords and not any(k in lowered for k in rule.keywords):
                    continue
                yield from self._match_line(rule, line, line_no, path)

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
