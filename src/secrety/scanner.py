"""Orchestration: feed every file of a source to every detector."""

from collections.abc import Sequence
from dataclasses import dataclass, replace

from secrety.detectors import Detector
from secrety.models import DetectionMethod, Finding
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
    Findings from different detectors that flag the same place are merged
    (see :func:`merge_duplicates`). Files keep the source order and findings
    are sorted by position inside a file, so the same input always gives the
    same output.
    """
    findings: list[Finding] = []
    for file in source:
        file_findings = [f for detector in detectors for f in detector.scan(file.text, file.path)]
        for finding in merge_duplicates(file_findings):
            findings.append(replace(finding, commit=file.commit) if file.commit else finding)
    return ScanResult(findings=findings, stats=source.stats)


def merge_duplicates(findings: Sequence[Finding]) -> list[Finding]:
    """Merge findings of one file whose secrets overlap on the same line.

    Overlap is transitive: a JWT matched by one regex but split into three
    entropy tokens (``.`` is not base64) forms a single group. Each group
    keeps one finding: a regex one if there is any (a known format beats a
    statistical guess), then the most confident, then the earliest column. The others
    are recorded in :attr:`~secrety.models.Finding.also_matched`.

    Returns:
        One finding per group, sorted by line then column.
    """
    ordered = sorted(findings, key=lambda f: (f.line, f.column))
    groups: list[list[Finding]] = []
    group_end = 0
    for finding in ordered:
        end = finding.column + len(finding.secret)
        if groups and groups[-1][0].line == finding.line and finding.column < group_end:
            groups[-1].append(finding)
            group_end = max(group_end, end)
        else:
            groups.append([finding])
            group_end = end
    return [_keep_best(group) for group in groups]


def _keep_best(group: list[Finding]) -> Finding:
    """Return the winner of ``group`` with the losers recorded on it."""
    if len(group) == 1:
        return group[0]
    # Regex first whatever the confidence: entropy confidence moves with the
    # threshold, and an entropy token may be only a fragment of the value.
    # ``group`` is sorted by column and min() keeps the first of equal keys.
    best = min(group, key=lambda f: (f.method is not DetectionMethod.REGEX, -f.confidence))
    others = tuple((f.rule_id, f.method) for f in group if f is not best)
    return replace(best, also_matched=best.also_matched + others)
