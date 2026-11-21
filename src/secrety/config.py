"""Tunable settings, validated once so detectors can trust them."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secrety.allowlist import Allowlist

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


CONFIG_FILE_NAME = ".secrety.toml"
_SECTIONS = {"allowlist": {"paths", "use_defaults"}}


class ConfigError(ValueError):
    """Raised when a ``.secrety.toml`` file is malformed."""


@dataclass(frozen=True, slots=True)
class FileConfig:
    """Settings read from a ``.secrety.toml`` file.

    Attributes:
        allowlist: Path allowlist (defaults plus the file's ``paths``).
        source: The file that was read, or ``None`` when there was none.
    """

    allowlist: Allowlist = field(default_factory=Allowlist)
    source: Path | None = None


def load_file_config(explicit: Path | None, scan_path: Path) -> FileConfig:
    """Read ``explicit``, else ``.secrety.toml`` at the scan root, else defaults.

    The scan root is ``scan_path`` for a folder, its parent for a single
    file. A file is validated in full: an unknown key (a typo such as
    ``path`` for ``paths``) is an error, never ignored.

    Raises:
        ConfigError: The file is not valid TOML or does not match the schema.
    """
    path = explicit
    if path is None:
        root = scan_path if scan_path.is_dir() else scan_path.parent
        candidate = root / CONFIG_FILE_NAME
        if not candidate.is_file():
            return FileConfig()
        path = candidate
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: cannot be read: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: not valid TOML: {exc}") from exc
    return FileConfig(allowlist=_parse_allowlist(data, path), source=path)


def _parse_allowlist(data: dict[str, Any], path: Path) -> Allowlist:
    """Validate the whole file and build its :class:`Allowlist`."""
    for key, value in data.items():
        if key not in _SECTIONS:
            raise ConfigError(f"{path}: unknown key {key!r} (expected {sorted(_SECTIONS)})")
        if not isinstance(value, dict):
            raise ConfigError(f"{path}: [{key}] must be a table")
        unknown = set(value) - _SECTIONS[key]
        if unknown:
            raise ConfigError(
                f"{path}: unknown key {sorted(unknown)} in [{key}] "
                f"(expected {sorted(_SECTIONS[key])})"
            )
    section = data.get("allowlist", {})
    paths = section.get("paths", [])
    if not isinstance(paths, list) or not all(isinstance(p, str) and p for p in paths):
        raise ConfigError(f"{path}: allowlist.paths must be a list of strings (globs)")
    use_defaults = section.get("use_defaults", True)
    if not isinstance(use_defaults, bool):
        raise ConfigError(f"{path}: allowlist.use_defaults must be true or false")
    return Allowlist(paths=tuple(paths), use_defaults=use_defaults)
