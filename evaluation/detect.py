"""Run secrety's detectors on a corpus, once per compared configuration."""

from __future__ import annotations

from pathlib import Path

from secrety.classifier import Classifier
from secrety.detectors import Detector, EntropyDetector, RegexDetector
from secrety.models import Finding
from secrety.rules import load_rules
from secrety.scanner import scan
from secrety.sources.filesystem import FilesystemSource

VARIANTS = ("regex", "entropy", "combined", "combined+classifier")


def run_variant(
    files_dir: Path, variant: str, classifier: Classifier | None = None
) -> list[Finding]:
    """Return the findings of ``variant`` on ``files_dir``.

    The path allowlist is not applied: the corpus folders are named like real
    ones (``tests/``, ``docs/``) and the default allowlist would hide them,
    which measures a path policy, not detection. The scan, the merge of
    duplicates and the classifier rescoring are the ones the CLI runs.
    """
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant {variant!r}, expected one of {VARIANTS}")
    if variant == "combined+classifier" and classifier is None:
        raise ValueError("the combined+classifier variant needs a classifier")
    detectors: list[Detector] = []
    if variant in ("regex", "combined", "combined+classifier"):
        detectors.append(RegexDetector(load_rules()))
    if variant in ("entropy", "combined", "combined+classifier"):
        detectors.append(EntropyDetector())
    findings = scan(FilesystemSource(files_dir), detectors).findings
    if variant == "combined+classifier" and classifier is not None:
        findings = classifier.rescore(findings).kept
    return findings
