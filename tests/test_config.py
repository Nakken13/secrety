from pathlib import Path

import pytest

from secrety.config import CONFIG_FILE_NAME, ConfigError, EntropyConfig, load_file_config


def test_entropy_defaults() -> None:
    config = EntropyConfig()
    assert config.base64_threshold == 4.5
    assert config.hex_threshold == 3.0
    assert config.min_length == 20


@pytest.mark.parametrize(
    "kwargs",
    [
        {"base64_threshold": 0.0},
        {"base64_threshold": 6.5},
        {"hex_threshold": -1.0},
        {"hex_threshold": 4.1},
        {"min_length": 0},
    ],
)
def test_entropy_config_rejects_out_of_range_values(kwargs: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        EntropyConfig(**kwargs)  # type: ignore[arg-type]


# --- .secrety.toml --------------------------------------------------------


def write_config(folder: Path, text: str) -> Path:
    path = folder / CONFIG_FILE_NAME
    path.write_text(text, encoding="utf-8")
    return path


def test_no_config_file_gives_default_allowlist(tmp_path: Path) -> None:
    config = load_file_config(None, tmp_path)
    assert config.allowlist.paths == ()
    assert config.allowlist.use_defaults
    assert config.source is None


def test_config_file_in_scan_root_is_found(tmp_path: Path) -> None:
    path = write_config(tmp_path, '[allowlist]\npaths = ["crew/**"]\nuse_defaults = false\n')
    config = load_file_config(None, tmp_path)
    assert config.allowlist.paths == ("crew/**",)
    assert not config.allowlist.use_defaults
    assert config.source == path


def test_scanning_a_single_file_looks_next_to_it(tmp_path: Path) -> None:
    write_config(tmp_path, '[allowlist]\npaths = ["x/**"]\n')
    target = tmp_path / "a.py"
    target.write_text("", encoding="utf-8")
    assert load_file_config(None, target).allowlist.paths == ("x/**",)


def test_explicit_config_wins_over_scan_root(tmp_path: Path) -> None:
    write_config(tmp_path, '[allowlist]\npaths = ["root/**"]\n')
    other = tmp_path / "other.toml"
    other.write_text('[allowlist]\npaths = ["explicit/**"]\n', encoding="utf-8")
    assert load_file_config(other, tmp_path).allowlist.paths == ("explicit/**",)


def test_empty_config_file_is_valid(tmp_path: Path) -> None:
    write_config(tmp_path, "")
    assert load_file_config(None, tmp_path).allowlist.use_defaults


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[allowlist\n", "not valid TOML"),
        ("[allowlist]\npaths = 'crew/**'\n", "list of strings"),
        ("[allowlist]\npaths = [1]\n", "list of strings"),
        ("[allowlist]\npaths = ['']\n", "list of strings"),
        ("[allowlist]\nuse_defaults = 'no'\n", "true or false"),
        ("[allowlist]\npath = []\n", "unknown key"),
        ("[alowlist]\n", "unknown key"),
        ("allowlist = 3\n", "must be a table"),
    ],
)
def test_invalid_config_is_rejected_with_the_file_name(
    tmp_path: Path, text: str, message: str
) -> None:
    write_config(tmp_path, text)
    with pytest.raises(ConfigError, match=message) as info:
        load_file_config(None, tmp_path)
    assert CONFIG_FILE_NAME in str(info.value)


def test_config_error_is_a_value_error() -> None:
    assert issubclass(ConfigError, ValueError)


def test_config_file_with_utf8_bom_is_read(tmp_path: Path) -> None:
    # PowerShell 5.1 writes UTF-8 with a byte-order mark.
    (tmp_path / CONFIG_FILE_NAME).write_bytes(b'\xef\xbb\xbf[allowlist]\npaths = ["x/**"]\n')
    assert load_file_config(None, tmp_path).allowlist.paths == ("x/**",)


def test_config_can_turn_inline_markers_off(tmp_path: Path) -> None:
    write_config(tmp_path, "[allowlist]\ninline_ignore = false\n")
    assert not load_file_config(None, tmp_path).allowlist.inline_ignore


def test_inline_ignore_must_be_a_boolean(tmp_path: Path) -> None:
    write_config(tmp_path, "[allowlist]\ninline_ignore = 0\n")
    with pytest.raises(ConfigError, match="true or false"):
        load_file_config(None, tmp_path)
