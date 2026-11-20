"""Orchestration: feed every file of a source to every detector."""

from collections.abc import Sequence
from dataclasses import dataclass, replace

from secrety.detectors import Detector
from secrety.models import Finding
from secrety.sources import ScanStats, Source


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything a reporter needs: the findings and what was scanned or skipped."""

    findings: list[Finding]
    stats: ScanStats


def scan(source: Source, detectors: Sequence[Detector]) -> ScanResult:
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
    return ScanResult(findings=findings, stats=source.stats)
