"""Unquoted secret assignments in configuration files (``.env``, YAML, INI...).

The ``generic-password-assignment`` regex rule only takes quoted values: in
code, ``password = get_password()`` assigns a call, not a literal. Config
files are different, values are plain text there (``DB_PASSWORD=hunter2``).
Entropy cannot gate them either, a short password has too few characters to
look random. So this detector relies on the shape instead: a secret-like key
at the start of a line, in a config file, with a literal value that is not a
reference or a placeholder.
"""

import re
from collections.abc import Iterator

from secrety.detectors.regex import iter_lines
from secrety.models import DetectionMethod, Finding

RULE_ID = "generic-password-unquoted"
_CONFIDENCE = 0.4  # same prior as the quoted generic rule
_CONFIG_SUFFIXES = (".env", ".ini", ".cfg", ".conf", ".properties", ".yaml", ".yml")

# optional YAML list marker (``- KEY=value`` in docker-compose), optional
# ``export``, key, ``=`` or ``:``, then a value of 8 to 256 non-space
# characters. A value starting with ``$ < { %`` is a reference or a template
# (``${VAR}``, ``<your-password>``, ``{{ var }}``, ``%(var)s``); a quote means
# the regex rule handles it. Every quantifier is bounded.
_ASSIGNMENT = re.compile(
    r"(?i)^\s{0,16}(?:-\s{1,8})?(?:export\s{1,8})?[\w.\-]{0,32}?"
    r"(?:password|passwd|pwd|secret|api_?key|access_?token|auth_?token)"
    r"[\w.\-]{0,32}\s{0,16}[:=]\s{0,16}"
    r"([^\s\"'$<{%#][^\s\"']{7,255})(?=\s|$)"
)


def is_config_file(path: str) -> bool:
    """Whether ``path`` looks like a configuration file (``.env*``, YAML, INI...)."""
    name = path.rsplit("/", 1)[-1].lower()
    return name.startswith(".env") or name.endswith(_CONFIG_SUFFIXES)


class UnquotedAssignmentDetector:
    """Flag ``KEY=value`` / ``key: value`` secrets left unquoted in config files."""

    def scan(self, text: str, path: str) -> Iterator[Finding]:
        """Yield a finding per unquoted secret assignment; code files yield nothing."""
        if not is_config_file(path):
            return
        for line_no, line in iter_lines(text):
            match = _ASSIGNMENT.search(line)
            if not match:
                continue
            yield Finding(
                rule_id=RULE_ID,
                description="Unquoted password, secret or token in a config file",
                path=path,
                line=line_no,
                column=match.start(1) + 1,
                secret=match.group(1),
                line_content=line,
                method=DetectionMethod.REGEX,
                confidence=_CONFIDENCE,
            )
