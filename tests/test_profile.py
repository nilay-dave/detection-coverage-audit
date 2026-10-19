import pytest

from dca.telemetry.profile import profile_corpus
from tests.conftest import write_corpus


def test_missing_corpus_raises(tmp_path, config):
    with pytest.raises(FileNotFoundError):
        profile_corpus(tmp_path / "nope.parquet", config)


def test_empty_corpus_raises(tmp_path, config):
    path = write_corpus(tmp_path / "empty.parquet", [])
    with pytest.raises(ValueError, match="empty"):
        profile_corpus(path, config)


def test_presence_is_measured_per_source(corpus_factory):
    profile = corpus_factory([
        ("windows/process_creation", {"EventID": 4688, "CommandLine": "a"}),
        ("windows/process_creation", {"EventID": 4688}),
        ("aws/cloudtrail", {"eventName": "ConsoleLogin"}),
    ])
    windows = profile.fields_for("windows/process_creation")
    assert windows["EventID"].presence == 1.0
    assert windows["CommandLine"].presence == 0.5
    assert profile.fields_for("aws/cloudtrail")["eventName"].presence == 1.0


def test_nested_object_flattens_to_dotted_path(corpus_factory):
    profile = corpus_factory([("aws/cloudtrail", {"userIdentity": {"type": "Root"}})])
    fields = profile.fields_for("aws/cloudtrail")
    assert "userIdentity.type" in fields
    assert fields["userIdentity.type"].literal_dotted_key is False


def test_literal_dotted_key_is_distinguished_from_nested_path(corpus_factory):
    """Regression: json_tree renders both shapes as $.id.orig_h.

    Zeek writes id.orig_h as one key; a nested object produces the same dotted
    path. The profiler must report which shape the corpus holds, because the two
    need different field extractions in the SIEM.
    """
    profile = corpus_factory([
        ("zeek/conn", {"id.orig_h": "10.0.0.1"}),
        ("aws/cloudtrail", {"id": {"orig_h": "10.0.0.2"}}),
    ])
    zeek = profile.fields_for("zeek/conn")["id.orig_h"]
    cloudtrail = profile.fields_for("aws/cloudtrail")["id.orig_h"]
    assert zeek.field == cloudtrail.field == "id.orig_h"
    assert zeek.literal_dotted_key is True
    assert cloudtrail.literal_dotted_key is False


def test_deeply_nested_paths_resolve(corpus_factory):
    profile = corpus_factory([("aws/cloudtrail", {"a": {"b": {"c": 1}}})])
    assert "a.b.c" in profile.fields_for("aws/cloudtrail")


def test_absent_source_has_no_fields(corpus_factory):
    profile = corpus_factory([("windows/system", {"EventID": 7045})])
    assert profile.fields_for("okta/system") == {}
    assert "okta/system" not in profile.observed_sources


def test_sampling_reduces_scanned_rows(tmp_path, config):
    from dataclasses import replace

    rows = [("windows/system", {"EventID": 7045, "ServiceName": f"svc{i}"}) for i in range(500)]
    path = write_corpus(tmp_path / "big.parquet", rows)
    sampled = profile_corpus(path, replace(config, sample_rows=100))
    assert sampled.total_events == 500
    assert sampled.sampled_events == 100


def test_null_valued_field_still_counts_as_present(corpus_factory):
    profile = corpus_factory([("windows/system", {"EventID": 7045, "ServiceName": None})])
    assert "ServiceName" in profile.fields_for("windows/system")
