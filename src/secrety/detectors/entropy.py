"""Entropy-based detection: flag random-looking tokens that no rule knows.

See ``docs/methodology.md`` for the formula, the thresholds and the known
weaknesses of this method.
"""

import math
import re
import string
from collections import Counter
from collections.abc import Iterator
from enum import StrEnum

from secrety.config import MAX_BASE64_ENTROPY, MAX_HEX_ENTROPY, EntropyConfig
from secrety.detectors.regex import iter_lines
from secrety.models import DetectionMethod, Finding

# Standard and URL-safe base64 alphabets; ``=`` only as trailing padding.
# A single character class followed by a fixed suffix cannot backtrack
# badly, so the cost stays linear on long lines.
_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]+={0,2}")
_HEX_CHARS = frozenset(string.hexdigits)

# Entropy alone is a weak signal: findings stay below most regex rules.
_MIN_CONFIDENCE = 0.3
_MAX_CONFIDENCE = 0.6


class Charset(StrEnum):
    """Alphabet a candidate token is drawn from; each has its own threshold."""

    BASE64 = "base64"
    HEX = "hex"


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits per character.

    ``H = -sum(p_i * log2(p_i))`` over the distinct characters of ``value``,
    where ``p_i`` is the frequency of character ``i``. It never exceeds
    ``log2(len(value))``, nor ``log2`` of the alphabet size.
    """
    if not value:
        return 0.0
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values())


def iter_candidates(line: str, min_length: int) -> Iterator[tuple[int, str, Charset]]:
    """Yield ``(column, token, charset)`` for every candidate token in ``line``.

    ``column`` is 0-based. A token is a maximal run of base64 characters at
    least ``min_length`` long; it counts as hex when every character is a hex
    digit. Tokens made only of decimal digits (timestamps, IDs) are skipped.
    """
    for match in _TOKEN.finditer(line):
        token = match.group()
        if len(token) < min_length or token.isdigit():
            continue
        charset = Charset.HEX if _HEX_CHARS.issuperset(token) else Charset.BASE64
        yield match.start(), token, charset


class EntropyDetector:
    """Flag tokens whose Shannon entropy reaches the threshold of their charset.

    Catches secrets that have no known format (internal API keys, random
    tokens), at the cost of more false positives than regex rules. Scanning is
    line by line, with the same line numbering as
    :class:`~secrety.detectors.RegexDetector`.
    """

    def __init__(self, config: EntropyConfig | None = None) -> None:
        """Create a detector; ``config`` defaults to :class:`EntropyConfig` defaults."""
        self.config = config or EntropyConfig()
        self._limits = {
            Charset.BASE64: (self.config.base64_threshold, MAX_BASE64_ENTROPY),
            Charset.HEX: (self.config.hex_threshold, MAX_HEX_ENTROPY),
        }

    def scan(self, text: str, path: str) -> Iterator[Finding]:
        """Yield a finding for every high-entropy token in ``text``."""
        for line_no, line in iter_lines(text):
            for column, token, charset in iter_candidates(line, self.config.min_length):
                entropy = shannon_entropy(token)
                threshold, maximum = self._limits[charset]
                if entropy < threshold:
                    continue
                yield Finding(
                    rule_id=f"high-entropy-{charset}",
                    description=f"High-entropy {charset} string",
                    path=path,
                    line=line_no,
                    column=column + 1,
                    secret=token,
                    line_content=line,
                    method=DetectionMethod.ENTROPY,
                    confidence=_confidence(entropy, threshold, maximum),
                )


def _confidence(entropy: float, threshold: float, maximum: float) -> float:
    """Map ``entropy`` linearly from ``[threshold, maximum]`` onto the confidence range."""
    if maximum <= threshold:
        return _MAX_CONFIDENCE
    ratio = min(1.0, (entropy - threshold) / (maximum - threshold))
    return round(_MIN_CONFIDENCE + ratio * (_MAX_CONFIDENCE - _MIN_CONFIDENCE), 2)
