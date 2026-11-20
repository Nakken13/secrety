"""Orchestration: feed every file of a source to every detector."""

from collections.abc import Iterable, Sequence
from dataclasses import replace

from secrety.detectors import Detector
from secrety.models import Finding
from secrety.sources import SourceFile


def scan(source: Iterable[SourceFile], detectors: Sequence[Detector]) -> list[Finding]:
    """Run ``detectors`` on each file of ``source`` and collect the findings.

    Detectors only see text and a path; the commit a file comes from (Git
    history source) is attached here, so no detector needs to know about Git.
    Findings keep the source order, so the same input always gives the same
    output.
    """
    findings: list[Finding] = []
    for file in source:
        for detector in detectors:
            for finding in detector.scan(file.text, file.path):
                findings.append(replace(finding, commit=file.commit) if file.commit else finding)
    return findings
