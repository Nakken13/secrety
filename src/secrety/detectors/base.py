"""Common interface for every detection method."""

from collections.abc import Iterator
from typing import Protocol, runtime_checkable

from secrety.models import Finding


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
