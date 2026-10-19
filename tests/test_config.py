import pytest

from dca.config import Config, ConfigError, load_config


def test_defaults_are_usable():
    config = load_config()
    assert 0.0 <= config.rare_field_threshold < 1.0
    assert config.sample_rows >= 0
    assert config.duckdb_threads >= 1


@pytest.mark.parametrize("threshold", [-0.1, 1.0, 1.5])
def test_threshold_out_of_range_is_rejected(threshold):
    with pytest.raises(ConfigError, match="rare_field_threshold"):
        Config(rare_field_threshold=threshold)


def test_negative_sample_rows_rejected():
    with pytest.raises(ConfigError, match="sample_rows"):
        Config(sample_rows=-1)


def test_zero_threads_rejected():
    with pytest.raises(ConfigError, match="duckdb_threads"):
        Config(duckdb_threads=0)


def test_env_override_is_read(monkeypatch):
    monkeypatch.setenv("DCA_RARE_FIELD_THRESHOLD", "0.25")
    monkeypatch.setenv("DCA_SAMPLE_ROWS", "500")
    config = load_config()
    assert config.rare_field_threshold == 0.25
    assert config.sample_rows == 500


def test_non_numeric_env_is_rejected(monkeypatch):
    monkeypatch.setenv("DCA_RARE_FIELD_THRESHOLD", "loose")
    with pytest.raises(ConfigError, match="must be a number"):
        load_config()
