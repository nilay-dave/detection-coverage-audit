import json

import duckdb
import pytest

from dca.config import Config
from dca.telemetry.generator import generate
from dca.telemetry.profile import profile_corpus
from dca.telemetry.schemas import load_spec


def _events(path):
    con = duckdb.connect()
    rows = con.execute(
        f"SELECT logsource_key, event FROM read_parquet('{path.as_posix()}')"
    ).fetchall()
    con.close()
    return [(key, json.loads(event)) for key, event in rows]


def test_zero_or_negative_event_count_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="must be positive"):
        generate(tmp_path / "x.parquet", 0)


def test_requested_event_count_is_written(tmp_path):
    result = generate(tmp_path / "c.parquet", 2000, seed=3)
    assert result.events == 2000
    assert sum(result.sources.values()) == 2000
    assert len(_events(result.path)) == 2000


def test_generation_is_deterministic_for_a_seed(tmp_path):
    a = _events(generate(tmp_path / "a.parquet", 800, seed=11).path)
    b = _events(generate(tmp_path / "b.parquet", 800, seed=11).path)
    assert a == b


def test_different_seeds_produce_different_corpora(tmp_path):
    a = _events(generate(tmp_path / "a.parquet", 800, seed=11).path)
    b = _events(generate(tmp_path / "b.parquet", 800, seed=12).path)
    assert a != b


def test_only_declared_fields_are_emitted(tmp_path):
    """Any field in the corpus that the schema does not declare would make a
    coverage finding untraceable to a line in schemas.yml."""
    spec = load_spec()
    result = generate(tmp_path / "c.parquet", 4000, seed=5)
    declared = {s.key: {f.name for f in s.fields} for s in spec.sources}

    def leaves(event, prefix=""):
        found = set()
        for key, value in event.items():
            path = f"{prefix}{key}"
            if isinstance(value, dict):
                found |= leaves(value, f"{path}.")
            else:
                found.add(path)
        return found

    for key, event in _events(result.path):
        assert leaves(event) <= declared[key], f"{key} emitted an undeclared field"


def test_literal_dotted_keys_are_written_as_one_key(tmp_path, config):
    result = generate(tmp_path / "c.parquet", 4000, seed=5)
    profile = profile_corpus(result.path, config)
    for source in ("zeek/dns", "zeek/ssl"):
        fields = profile.fields_for(source)
        assert fields["id.orig_h"].literal_dotted_key is True
        assert fields["id.resp_h"].literal_dotted_key is True


def test_nested_cloudtrail_fields_are_written_as_objects(tmp_path, config):
    result = generate(tmp_path / "c.parquet", 4000, seed=5)
    profile = profile_corpus(result.path, config)
    assert profile.fields_for("aws/cloudtrail")["userIdentity.type"].literal_dotted_key is False


def test_measured_presence_tracks_declared_presence(tmp_path, config):
    """Declared presence is a probability, so a large corpus should land close
    to it. A wide tolerance keeps the test from being flaky while still catching
    a generator that ignores the presence field entirely."""
    spec = load_spec()
    result = generate(tmp_path / "c.parquet", 60_000, seed=9)
    profile = profile_corpus(result.path, config)
    for source in spec.sources:
        measured = profile.fields_for(source.key)
        for field_spec in source.fields:
            if source.key not in profile.observed_sources:
                continue
            assert field_spec.name in measured, f"{source.key}.{field_spec.name} never emitted"
            assert abs(measured[field_spec.name].presence - field_spec.presence) < 0.05


def test_corpus_spans_every_declared_source(tmp_path):
    result = generate(tmp_path / "c.parquet", 20_000, seed=4)
    assert set(result.sources) == load_spec().keys
    assert all(count > 0 for count in result.sources.values())


def test_chunking_does_not_change_the_total(tmp_path):
    from dca.telemetry import generator

    original = generator.CHUNK_ROWS
    try:
        generator.CHUNK_ROWS = 97
        result = generate(tmp_path / "c.parquet", 500, seed=2)
        assert result.events == 500
        assert len(_events(result.path)) == 500
    finally:
        generator.CHUNK_ROWS = original


def test_unknown_field_kind_is_rejected(tmp_path):
    body = (
        "sources:\n  a/b:\n    share: 1.0\n    fields:\n"
        "      x: {presence: 1.0, kind: not_a_kind}\n"
    )
    path = tmp_path / "spec.yml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError, match="unknown field kind"):
        generate(tmp_path / "c.parquet", 10, spec=load_spec(path))
