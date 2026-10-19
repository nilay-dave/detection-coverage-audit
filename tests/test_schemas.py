import pytest

from dca.telemetry.schemas import SchemaError, load_spec


def test_bundled_spec_loads_and_shares_sum_to_one():
    spec = load_spec()
    assert len(spec.sources) >= 5
    assert abs(sum(s.share for s in spec.sources) - 1.0) < 1e-6


def test_bundled_spec_declares_zeek_dotted_keys_as_literal():
    """Zeek writes id.orig_h as one key. The spec must say so or the generator
    nests it and the corpus misrepresents the log source."""
    spec = load_spec()
    dns = spec.by_key("zeek/dns")
    literal = {f.name for f in dns.fields if f.literal_key}
    assert literal == {"id.orig_h", "id.resp_h"}


def test_cloudtrail_nested_fields_are_not_literal():
    spec = load_spec()
    cloudtrail = spec.by_key("aws/cloudtrail")
    nested = next(f for f in cloudtrail.fields if f.name == "userIdentity.type")
    assert nested.literal_key is False


def test_by_key_returns_none_for_unknown_source():
    assert load_spec().by_key("nope/nope") is None


def test_keys_property_lists_every_source():
    spec = load_spec()
    assert spec.keys == frozenset(s.key for s in spec.sources)


def _write(tmp_path, body):
    path = tmp_path / "spec.yml"
    path.write_text(body, encoding="utf-8")
    return path


def test_spec_without_sources_is_rejected(tmp_path):
    with pytest.raises(SchemaError, match="no 'sources'"):
        load_spec(_write(tmp_path, "other: {}\n"))


def test_shares_that_do_not_sum_to_one_are_rejected(tmp_path):
    body = "sources:\n  a/b:\n    share: 0.5\n    fields:\n      x: {presence: 1.0, kind: word}\n"
    with pytest.raises(SchemaError, match="must sum to 1.0"):
        load_spec(_write(tmp_path, body))


def test_source_with_no_fields_is_rejected(tmp_path):
    body = "sources:\n  a/b:\n    share: 1.0\n    fields: {}\n"
    with pytest.raises(SchemaError, match="declares no fields"):
        load_spec(_write(tmp_path, body))


@pytest.mark.parametrize("presence", ["0", "1.4", "-0.2"])
def test_presence_out_of_range_is_rejected(tmp_path, presence):
    body = f"sources:\n  a/b:\n    share: 1.0\n    fields:\n      x: {{presence: {presence}, kind: word}}\n"
    with pytest.raises(SchemaError, match="presence must be in"):
        load_spec(_write(tmp_path, body))
