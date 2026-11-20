"""Orchestration: feed every file of a source to every detector."""

from collections.abc import Iterable, Sequence

from secrety.detectors import Detector
from secrety.models import Finding
from secrety.sources import SourceFile


def scan(source: Iterable[SourceFile], detectors: Sequence[Detector]) -> list[Finding]:
    """Run ``detectors`` on each file of ``source`` and collect the findings.

    Findings keep the source order (files sorted by path, then by line), so a
    scan of the same input always gives the same output.
    """
    findings: list[Finding] = []
    for file in source:
        for detector in detectors:
            findings.extend(detector.scan(file.text, file.path))
    return findings
