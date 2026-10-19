import pytest
from tests.conftest import write_corpus

from dca.telemetry.profile import profile_corpus


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


def test_batched_profile_matches_single_batch(tmp_path, config):
    """Regression: profiling a 10M event corpus in one statement exhausted
    DuckDB's memory budget. Batching must not change the answer."""
    from dca.telemetry import profile as profile_module

    rows = []
    for index in range(2_000):
        event = {"EventID": 4688, "Computer": f"WKS-{index:04d}"}
        if index % 3 == 0:
            event["CommandLine"] = "x"
        rows.append(("windows/process_creation", event))
    for index in range(500):
        rows.append(("zeek/dns", {"id.orig_h": "10.0.0.1", "query": f"h{index}.example.net"}))
    path = write_corpus(tmp_path / "batched.parquet", rows)

    original = profile_module.BATCH_ROWS
    try:
        profile_module.BATCH_ROWS = 10**9
        single = profile_corpus(path, config)
        profile_module.BATCH_ROWS = 137
        batched = profile_corpus(path, config)
    finally:
        profile_module.BATCH_ROWS = original

    assert single.observed_sources == batched.observed_sources
    assert single.source_counts == batched.source_counts
    for source in single.observed_sources:
        left, right = single.fields_for(source), batched.fields_for(source)
        assert set(left) == set(right)
        for name in left:
            assert left[name].events_with_field == right[name].events_with_field
            assert left[name].events_in_source == right[name].events_in_source
            assert left[name].literal_dotted_key == right[name].literal_dotted_key


def test_batch_boundary_does_not_double_count(tmp_path, config):
    """An event must be counted once even when the batch size divides the corpus
    awkwardly, so no event may straddle two batches."""
    from dca.telemetry import profile as profile_module

    rows = [("windows/system", {"EventID": 7045, "ServiceName": "svc"}) for _ in range(101)]
    path = write_corpus(tmp_path / "boundary.parquet", rows)
    original = profile_module.BATCH_ROWS
    try:
        for batch in (1, 2, 7, 50, 100, 101, 1000):
            profile_module.BATCH_ROWS = batch
            fields = profile_corpus(path, config).fields_for("windows/system")
            assert fields["ServiceName"].events_with_field == 101, f"batch={batch}"
            assert fields["ServiceName"].presence == 1.0
    finally:
        profile_module.BATCH_ROWS = original
