"""Detection methods (regex rules, entropy...)."""

from secrety.detectors.base import Detector
from secrety.detectors.regex import RegexDetector

__all__ = ["Detector", "RegexDetector"]
