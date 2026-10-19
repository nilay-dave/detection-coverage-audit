"""Shared fixtures. No network, no external services, no API keys."""

from __future__ import annotations

import json
from pathlib import Path

import duckdb
import pandas as pd
import pytest

from dca.config import Config
from dca.telemetry.profile import profile_corpus


@pytest.fixture
def config() -> Config:
    return Config(rare_field_threshold=0.001, sample_rows=0, seed=7, duckdb_threads=2)


def write_corpus(path: Path, rows: list[tuple[str, dict]]) -> Path:
    """Write (logsource_key, event dict) pairs to a parquet corpus."""
    frame = pd.DataFrame(
        [(key, json.dumps(event)) for key, event in rows], columns=["logsource_key", "event"]
    )
    con = duckdb.connect()
    con.register("d", frame)
    con.execute(
        f"COPY (SELECT logsource_key, event::JSON AS event FROM d) "
        f"TO '{path.as_posix()}' (FORMAT PARQUET)"
    )
    con.close()
    return path


@pytest.fixture
def corpus_factory(tmp_path, config):
    """Build a profiled corpus from inline events."""

    def _build(rows: list[tuple[str, dict]]):
        path = write_corpus(tmp_path / "corpus.parquet", rows)
        return profile_corpus(path, config)

    return _build


@pytest.fixture
def rule_factory(tmp_path):
    """Write Sigma rule documents to a directory and return the directory."""
    import yaml

    directory = tmp_path / "rules"
    directory.mkdir(exist_ok=True)
    counter = {"n": 0}

    def _write(rule: dict | str, name: str | None = None) -> Path:
        counter["n"] += 1
        filename = name or f"rule_{counter['n']}.yml"
        target = directory / filename
        target.write_text(
            rule if isinstance(rule, str) else yaml.safe_dump(rule, sort_keys=False),
            encoding="utf-8",
        )
        return directory

    return _write
