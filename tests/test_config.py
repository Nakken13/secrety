import pytest

from secrety.config import EntropyConfig


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
