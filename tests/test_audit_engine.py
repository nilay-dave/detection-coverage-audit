from dca.audit.engine import Verdict, audit


def _rule(**overrides):
    rule = {
        "title": "T",
        "id": overrides.pop("id", "r1"),
        "logsource": overrides.pop("logsource", {"product": "windows", "category": "process_creation"}),
        "detection": overrides.pop("detection", {"selection": {"EventID": 4688}, "condition": "selection"}),
    }
    rule.update(overrides)
    return rule


def test_rule_with_all_fields_present_resolves(rule_factory, corpus_factory, config):
    directory = rule_factory(_rule(detection={"selection": {"EventID": 4688, "CommandLine": "x"}, "condition": "selection"}))
    profile = corpus_factory([("windows/process_creation", {"EventID": 4688, "CommandLine": "a"})])
    result = audit(directory, profile, config)
    assert result.findings[0].verdict is Verdict.RESOLVED


def test_rule_on_absent_log_source_is_no_source(rule_factory, corpus_factory, config):
    directory = rule_factory(_rule(logsource={"product": "okta", "service": "system"}))
    profile = corpus_factory([("windows/process_creation", {"EventID": 4688})])
    finding = audit(directory, profile, config).findings[0]
    assert finding.verdict is Verdict.NO_SOURCE
    assert finding.verdict.is_blind


def test_rule_referencing_absent_field_is_missing_field(rule_factory, corpus_factory, config):
    directory = rule_factory(_rule(detection={"selection": {"Image": "x"}, "condition": "selection"}))
    profile = corpus_factory([("windows/process_creation", {"NewProcessName": "a"})])
    finding = audit(directory, profile, config).findings[0]
    assert finding.verdict is Verdict.MISSING_FIELD
    assert finding.missing_fields == ("Image",)
    assert finding.verdict.is_blind


def test_sysmon_rule_against_security_4688_is_blind(rule_factory, corpus_factory, config):
    """The case this tool exists for.

    Most public detection content is written against Sysmon field names. An
    estate that audits process creation through Security EventID 4688 populates
    different field names, so the rule can never fire even though the technique
    shows as covered on a heatmap.
    """
    directory = rule_factory(_rule(
        detection={"selection": {"Image|endswith": "\\powershell.exe", "ParentImage": "x"}, "condition": "selection"},
        tags=["attack.t1059.001"]))
    profile = corpus_factory([
        ("windows/process_creation", {"EventID": 4688, "NewProcessName": "p", "ParentProcessName": "q"}),
    ])
    result = audit(directory, profile, config)
    assert result.findings[0].verdict is Verdict.MISSING_FIELD
    assert set(result.findings[0].missing_fields) == {"Image", "ParentImage"}
    assert result.techniques["T1059.001"].is_blind
    assert result.blind_technique_pct == 100.0


def test_rare_field_is_its_own_verdict(rule_factory, corpus_factory, config):
    from dataclasses import replace

    directory = rule_factory(_rule(detection={"selection": {"CommandLine": "x"}, "condition": "selection"}))
    rows = [("windows/process_creation", {"EventID": 4688}) for _ in range(999)]
    rows.append(("windows/process_creation", {"EventID": 4688, "CommandLine": "a"}))
    profile = corpus_factory(rows)
    finding = audit(directory, profile, replace(config, rare_field_threshold=0.01)).findings[0]
    assert finding.verdict is Verdict.RARE_FIELD
    assert finding.rare_fields[0][0] == "CommandLine"
    assert finding.verdict.is_blind is False


def test_keyword_only_rule_is_its_own_verdict(rule_factory, corpus_factory, config):
    directory = rule_factory(_rule(detection={"keywords": ["impossible travel"], "condition": "keywords"}))
    profile = corpus_factory([("windows/process_creation", {"EventID": 4688})])
    finding = audit(directory, profile, config).findings[0]
    assert finding.verdict is Verdict.KEYWORD_ONLY
    assert finding.verdict.is_blind is False


def test_absent_source_outranks_keyword_only(rule_factory, corpus_factory, config):
    directory = rule_factory(_rule(
        logsource={"product": "okta", "service": "system"},
        detection={"keywords": ["x"], "condition": "keywords"}))
    profile = corpus_factory([("windows/process_creation", {"EventID": 4688})])
    assert audit(directory, profile, config).findings[0].verdict is Verdict.NO_SOURCE


def test_unparseable_rule_appears_as_a_finding(rule_factory, corpus_factory, config):
    directory = rule_factory({"title": "no detection", "logsource": {"product": "windows"}})
    profile = corpus_factory([("windows/process_creation", {"EventID": 4688})])
    result = audit(directory, profile, config)
    assert result.unparseable_count == 1
    assert result.findings[0].verdict is Verdict.UNPARSEABLE
    assert result.findings[0].verdict.is_blind


def test_technique_is_covered_when_any_mapped_rule_resolves(rule_factory, corpus_factory, config):
    directory = rule_factory(_rule(id="blind", detection={"selection": {"Image": "x"}, "condition": "selection"},
                                   tags=["attack.t1059.001"]))
    rule_factory(_rule(id="good", detection={"selection": {"EventID": 4688}, "condition": "selection"},
                       tags=["attack.t1059.001"]), name="good.yml")
    profile = corpus_factory([("windows/process_creation", {"EventID": 4688})])
    result = audit(directory, profile, config)
    coverage = result.techniques["T1059.001"]
    assert coverage.rule_count == 2
    assert coverage.blind_rule_count == 1
    assert coverage.is_blind is False
    assert result.blind_technique_pct == 0.0


def test_shape_warning_is_raised_for_literal_dotted_key(rule_factory, corpus_factory, config):
    directory = rule_factory(_rule(logsource={"product": "zeek", "service": "conn"},
                                   detection={"selection": {"id.orig_h": "10.0.0.1"}, "condition": "selection"}))
    profile = corpus_factory([("zeek/conn", {"id.orig_h": "10.0.0.1"})])
    finding = audit(directory, profile, config).findings[0]
    assert finding.verdict is Verdict.RESOLVED
    assert finding.shape_warnings and "one dotted key" in finding.shape_warnings[0]


def test_blind_technique_pct_is_zero_when_no_techniques_mapped(rule_factory, corpus_factory, config):
    directory = rule_factory(_rule())
    profile = corpus_factory([("windows/process_creation", {"EventID": 4688})])
    result = audit(directory, profile, config)
    assert result.mapped_technique_count == 0
    assert result.blind_technique_pct == 0.0
