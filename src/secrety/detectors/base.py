"""Common interface for every detection method."""

from collections.abc import Iterator
from typing import Protocol, runtime_checkable

from secrety.models import Finding


def iter_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, line)`` pairs, splitting on line feeds only.

    ``str.splitlines`` also breaks on form feeds, vertical tabs or U+2028,
    which would shift line numbers compared with Git, editors and SARIF. A
    trailing carriage return (Windows line ending) is removed.
    """
    for number, line in enumerate(text.split("\n"), start=1):
        yield number, line.removesuffix("\r")


@runtime_checkable
class Detector(Protocol):
    """Anything that turns the text of one file into findings.

    Detectors are pure: they know nothing about files on disk or Git. A source
    (filesystem, Git history) feeds them text, which keeps each detector easy
    to test and lets every source reuse every detector.
    """

    def scan(self, text: str, path: str) -> Iterator[Finding]:
        """Yield findings for ``text``, reported against ``path``."""
        ...
