"""Tunable settings, validated once so detectors can trust them."""

from dataclasses import dataclass

# Entropy can never exceed log2 of the alphabet size: 6 bits for base64
# (64 symbols), 4 bits for hex (16 symbols).
MAX_BASE64_ENTROPY = 6.0
MAX_HEX_ENTROPY = 4.0

DEFAULT_BASE64_THRESHOLD = 4.5
DEFAULT_HEX_THRESHOLD = 3.0
DEFAULT_MIN_LENGTH = 20


@dataclass(frozen=True, slots=True)
class EntropyConfig:
    """Settings of the entropy detector.

    The defaults are starting points from the literature (TruffleHog,
    detect-secrets); they are tuned on a labelled corpus in the evaluation.

    Attributes:
        base64_threshold: Minimum entropy, in bits per character, for a base64 token.
        hex_threshold: Minimum entropy for a hex token.
        min_length: Shortest token considered. Entropy is capped at
            ``log2(length)``, so a 20-character token never exceeds 4.32 bits.
    """

    base64_threshold: float = DEFAULT_BASE64_THRESHOLD
    hex_threshold: float = DEFAULT_HEX_THRESHOLD
    min_length: int = DEFAULT_MIN_LENGTH

    def __post_init__(self) -> None:
        """Reject thresholds no token could ever reach, or that flag everything."""
        if not 0.0 < self.base64_threshold <= MAX_BASE64_ENTROPY:
            raise ValueError(
                f"base64 threshold must be in (0, {MAX_BASE64_ENTROPY}], "
                f"got {self.base64_threshold}"
            )
        if not 0.0 < self.hex_threshold <= MAX_HEX_ENTROPY:
            raise ValueError(
                f"hex threshold must be in (0, {MAX_HEX_ENTROPY}], got {self.hex_threshold}"
            )
        if self.min_length < 1:
            raise ValueError(f"min length must be at least 1, got {self.min_length}")
