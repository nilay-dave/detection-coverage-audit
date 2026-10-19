import json

from dca.audit.engine import audit
from dca.report.render import render_html, render_json, to_dict


def _result(rule_factory, corpus_factory, config):
    directory = rule_factory({
        "title": "Sysmon rule on a 4688 estate", "id": "r1",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": {"Image": "x"}, "condition": "selection"},
        "tags": ["attack.t1059.001"]})
    profile = corpus_factory([("windows/process_creation", {"EventID": 4688, "NewProcessName": "p"})])
    return audit(directory, profile, config)


def test_dict_shape_carries_the_headline_number(rule_factory, corpus_factory, config):
    payload = to_dict(_result(rule_factory, corpus_factory, config))
    assert payload["summary"]["blind_technique_pct"] == 100.0
    assert payload["summary"]["techniques_mapped"] == 2
    assert set(payload["blind_techniques"]) == {"T1059", "T1059.001"}


def test_every_finding_carries_an_action(rule_factory, corpus_factory, config):
    payload = to_dict(_result(rule_factory, corpus_factory, config))
    assert all(finding["action"] for finding in payload["findings"])


def test_blind_findings_sort_first(rule_factory, corpus_factory, config):
    rule_factory({"title": "fine", "id": "ok", "logsource": {"product": "windows", "category": "process_creation"},
                  "detection": {"selection": {"EventID": 4688}, "condition": "selection"}}, name="ok.yml")
    payload = to_dict(_result(rule_factory, corpus_factory, config))
    assert payload["findings"][0]["verdict"] == "missing_field"


def test_json_render_is_valid_and_complete(tmp_path, rule_factory, corpus_factory, config):
    path = render_json(_result(rule_factory, corpus_factory, config), tmp_path / "out" / "r.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["summary"]["rules_total"] == 1


def test_html_render_includes_the_number_and_the_rule(tmp_path, rule_factory, corpus_factory, config):
    path = render_html(_result(rule_factory, corpus_factory, config), tmp_path / "out" / "r.html")
    html = path.read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    assert "100.0" in html
    assert "Sysmon rule on a 4688 estate" in html
    assert "prefers-color-scheme: dark" in html


def test_html_escapes_rule_titles(tmp_path, rule_factory, corpus_factory, config):
    directory = rule_factory({"title": "<script>alert(1)</script>", "id": "x",
                              "logsource": {"product": "windows", "category": "process_creation"},
                              "detection": {"selection": {"EventID": 4688}, "condition": "selection"}})
    profile = corpus_factory([("windows/process_creation", {"EventID": 4688})])
    path = render_html(audit(directory, profile, config), tmp_path / "r.html")
    html = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
