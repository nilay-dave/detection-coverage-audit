import pytest

from dca.rules.loader import load_rules


def test_missing_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_rules(tmp_path / "nope")


def test_file_instead_of_directory_raises(tmp_path):
    target = tmp_path / "rules.yml"
    target.write_text("title: x", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        load_rules(target)


def test_valid_rule_is_loaded(rule_factory):
    directory = rule_factory(
        {"title": "T", "id": "abc", "logsource": {"product": "windows", "category": "process_creation"},
         "detection": {"selection": {"Image": "x"}, "condition": "selection"}}
    )
    ruleset = load_rules(directory)
    assert len(ruleset) == 1
    assert ruleset.rules[0].rule_id == "abc"
    assert ruleset.rules[0].logsource_key == "windows/process_creation"


def test_malformed_yaml_is_reported_not_raised(rule_factory):
    directory = rule_factory("title: [unclosed\n  bad: :", name="broken.yml")
    ruleset = load_rules(directory)
    assert len(ruleset) == 0
    assert len(ruleset.errors) == 1
    assert "invalid yaml" in ruleset.errors[0].reason


def test_rule_without_detection_is_an_error(rule_factory):
    directory = rule_factory({"title": "no logic", "logsource": {"product": "windows"}})
    ruleset = load_rules(directory)
    assert len(ruleset) == 0
    assert "no detection block" in ruleset.errors[0].reason


def test_empty_file_is_an_error(rule_factory):
    directory = rule_factory("", name="empty.yml")
    ruleset = load_rules(directory)
    assert "no yaml documents" in ruleset.errors[0].reason


def test_non_mapping_document_is_an_error(rule_factory):
    directory = rule_factory("- just\n- a\n- list\n", name="list.yml")
    ruleset = load_rules(directory)
    assert "not a mapping" in ruleset.errors[0].reason


def test_multi_document_file_yields_several_rules(rule_factory):
    body = (
        "title: A\nid: a\nlogsource: {product: windows}\ndetection: {selection: {Image: x}, condition: selection}\n"
        "---\n"
        "title: B\nid: b\nlogsource: {product: windows}\ndetection: {selection: {Image: y}, condition: selection}\n"
    )
    directory = rule_factory(body, name="multi.yml")
    ruleset = load_rules(directory)
    assert {r.rule_id for r in ruleset.rules} == {"a", "b"}


def test_rule_id_falls_back_to_filename(rule_factory):
    directory = rule_factory(
        {"title": "T", "logsource": {"product": "windows"}, "detection": {"selection": {"Image": "x"}, "condition": "selection"}},
        name="named_rule.yml",
    )
    ruleset = load_rules(directory)
    assert ruleset.rules[0].rule_id == "named_rule"


def test_logsource_key_is_unspecified_when_absent(rule_factory):
    directory = rule_factory({"title": "T", "detection": {"selection": {"a": 1}, "condition": "selection"}})
    ruleset = load_rules(directory)
    assert ruleset.rules[0].logsource_key == "unspecified"


def test_non_rule_files_are_ignored(rule_factory):
    directory = rule_factory({"title": "T", "logsource": {"product": "windows"}, "detection": {"selection": {"Image": "x"}, "condition": "selection"}})
    (directory / "README.md").write_text("not a rule", encoding="utf-8")
    (directory / "notes.txt").write_text("also not a rule", encoding="utf-8")
    ruleset = load_rules(directory)
    assert len(ruleset) == 1
    assert not ruleset.errors


def test_broken_rule_does_not_prevent_loading_good_ones(rule_factory):
    """The reason this loader does not use pySigma.

    pySigma aborts a whole collection when one rule in it is malformed, so a
    single placeholder file in a 500 rule pack would mean the audit reports
    nothing. Here the broken file becomes a finding and the valid rule still
    loads. See ADR-005.
    """
    directory = rule_factory(
        {"title": "valid", "id": "good",
         "logsource": {"product": "windows", "category": "process_creation"},
         "detection": {"selection": {"EventID": 4688}, "condition": "selection"}},
        name="good.yml",
    )
    (directory / "no_detection.yml").write_text(
        "title: placeholder\nid: broken\nlogsource: {product: windows}\n", encoding="utf-8"
    )
    (directory / "malformed.yml").write_text("title: [unclosed\n  bad: :", encoding="utf-8")

    ruleset = load_rules(directory)
    assert [r.rule_id for r in ruleset.rules] == ["good"]
    assert len(ruleset.errors) == 2
    reasons = sorted(e.reason.split(":")[0] for e in ruleset.errors)
    assert reasons == ["invalid yaml", "rule has no detection block"]


def test_loader_accepts_a_rule_pysigma_would_reject(rule_factory):
    """A rule with a status value outside the Sigma specification still has
    readable field references, so it is not this tool's job to reject it."""
    directory = rule_factory({
        "title": "odd status", "id": "odd", "status": "homegrown",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": {"EventID": 4688}, "condition": "selection"},
        "tags": ["attack.t1059", "internal.owner.soc-team"]})
    ruleset = load_rules(directory)
    assert len(ruleset) == 1
    assert not ruleset.errors
