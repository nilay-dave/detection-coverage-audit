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


def test_report_has_a_skip_link_and_a_table_caption(tmp_path, rule_factory, corpus_factory, config):
    html = render_html(_result(rule_factory, corpus_factory, config), tmp_path / "r.html").read_text(
        encoding="utf-8"
    )
    assert 'class="skip" href="#findings"' in html
    assert 'id="findings"' in html
    assert "<caption>" in html


def test_verdict_severity_is_not_carried_by_colour_alone(tmp_path, rule_factory, corpus_factory, config):
    """A reader who cannot distinguish the verdict colours must still be able to
    tell a blind rule from a resolved one."""
    html = render_html(_result(rule_factory, corpus_factory, config), tmp_path / "r.html").read_text(
        encoding="utf-8"
    )
    assert ".v-missing_field::before" in html
    assert 'content: "x"' in html
    assert 'content: "ok"' in html
    # The word itself is in the cell, not only the colour class.
    assert "missing field" in html


def test_headline_figure_has_a_text_label(tmp_path, rule_factory, corpus_factory, config):
    html = render_html(_result(rule_factory, corpus_factory, config), tmp_path / "r.html").read_text(
        encoding="utf-8"
    )
    assert "percent of mapped techniques are blind" in html


def test_lists_are_marked_up_as_lists(tmp_path, rule_factory, corpus_factory, config):
    html = render_html(_result(rule_factory, corpus_factory, config), tmp_path / "r.html").read_text(
        encoding="utf-8"
    )
    assert 'role="list"' in html
    assert "<ul class=\"chips\"" in html
    assert "<li class=\"chip\">" in html


def test_reduced_motion_is_respected(tmp_path, rule_factory, corpus_factory, config):
    html = render_html(_result(rule_factory, corpus_factory, config), tmp_path / "r.html").read_text(
        encoding="utf-8"
    )
    assert "prefers-reduced-motion: reduce" in html


def test_every_colour_pair_meets_its_contrast_threshold():
    """Runs the same check CI runs, so a palette edit cannot quietly fail AA."""
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(root / "tools" / "check_contrast.py")],
        cwd=root, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
