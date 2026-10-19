from dca.rules.attack import extract_techniques
from dca.rules.fields import extract_fields
from dca.rules.loader import load_rules


def _one(rule_factory, rule):
    return load_rules(rule_factory(rule)).rules[0]


def test_simple_selection_fields(rule_factory):
    rule = _one(rule_factory, {"title": "T", "logsource": {"product": "windows"},
        "detection": {"selection": {"Image": "a", "CommandLine": "b"}, "condition": "selection"}})
    result = extract_fields(rule)
    assert result.fields == {"Image", "CommandLine"}
    assert result.keyword_only is False


def test_modifiers_are_stripped_from_field_names(rule_factory):
    rule = _one(rule_factory, {"title": "T", "logsource": {"product": "windows"},
        "detection": {"selection": {"CommandLine|contains|all": ["a", "b"], "Image|endswith": "x"}, "condition": "selection"}})
    assert extract_fields(rule).fields == {"CommandLine", "Image"}


def test_condition_key_is_not_a_field(rule_factory):
    rule = _one(rule_factory, {"title": "T", "logsource": {"product": "windows"},
        "detection": {"selection": {"Image": "a"}, "condition": "selection"}})
    assert "condition" not in extract_fields(rule).fields


def test_multiple_selections_are_merged(rule_factory):
    rule = _one(rule_factory, {"title": "T", "logsource": {"product": "windows"},
        "detection": {"sel_a": {"Image": "a"}, "sel_b": {"User": "b"}, "filter": {"Parent": "c"},
                      "condition": "sel_a and sel_b and not filter"}})
    assert extract_fields(rule).fields == {"Image", "User", "Parent"}


def test_list_of_maps_is_walked(rule_factory):
    rule = _one(rule_factory, {"title": "T", "logsource": {"product": "windows"},
        "detection": {"selection": [{"Image": "a"}, {"TargetImage": "b"}], "condition": "selection"}})
    assert extract_fields(rule).fields == {"Image", "TargetImage"}


def test_keyword_only_rule_is_flagged(rule_factory):
    rule = _one(rule_factory, {"title": "T", "logsource": {"product": "okta"},
        "detection": {"keywords": ["impossible travel", "suspicious"], "condition": "keywords"}})
    result = extract_fields(rule)
    assert result.fields == frozenset()
    assert result.keyword_only is True


def test_mixed_keyword_and_field_rule_is_not_keyword_only(rule_factory):
    rule = _one(rule_factory, {"title": "T", "logsource": {"product": "okta"},
        "detection": {"keywords": ["x"], "selection": {"eventType": "y"}, "condition": "keywords and selection"}})
    result = extract_fields(rule)
    assert result.fields == {"eventType"}
    assert result.keyword_only is False


def test_nested_dotted_field_is_preserved(rule_factory):
    rule = _one(rule_factory, {"title": "T", "logsource": {"product": "aws", "service": "cloudtrail"},
        "detection": {"selection": {"userIdentity.type": "Root"}, "condition": "selection"}})
    assert extract_fields(rule).fields == {"userIdentity.type"}


def test_technique_tags_include_parent_and_subtechnique(rule_factory):
    rule = _one(rule_factory, {"title": "T", "logsource": {"product": "windows"},
        "detection": {"selection": {"Image": "a"}, "condition": "selection"},
        "tags": ["attack.execution", "attack.t1059.001"]})
    assert extract_techniques(rule) == {"T1059", "T1059.001"}


def test_tactic_only_tags_yield_no_techniques(rule_factory):
    rule = _one(rule_factory, {"title": "T", "logsource": {"product": "windows"},
        "detection": {"selection": {"Image": "a"}, "condition": "selection"},
        "tags": ["attack.execution", "cve.2024.1234"]})
    assert extract_techniques(rule) == frozenset()


def test_missing_tags_block_is_safe(rule_factory):
    rule = _one(rule_factory, {"title": "T", "logsource": {"product": "windows"},
        "detection": {"selection": {"Image": "a"}, "condition": "selection"}})
    assert extract_techniques(rule) == frozenset()


def test_malformed_tags_block_is_safe(rule_factory):
    rule = _one(rule_factory, {"title": "T", "logsource": {"product": "windows"},
        "detection": {"selection": {"Image": "a"}, "condition": "selection"},
        "tags": "attack.t1059"})
    assert extract_techniques(rule) == frozenset()
