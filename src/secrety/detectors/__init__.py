"""Detection methods (regex rules, entropy...)."""

from secrety.detectors.base import Detector
from secrety.detectors.entropy import EntropyDetector
from secrety.detectors.regex import RegexDetector

__all__ = ["Detector", "EntropyDetector", "RegexDetector"]
