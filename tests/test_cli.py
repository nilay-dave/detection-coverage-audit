import json

from tests.conftest import write_corpus
from typer.testing import CliRunner

from dca import __version__
from dca.cli import app

runner = CliRunner()


def _corpus(tmp_path):
    return write_corpus(tmp_path / "c.parquet", [
        ("windows/process_creation", {"EventID": 4688, "NewProcessName": "p"}),
        ("windows/process_creation", {"EventID": 4688, "NewProcessName": "q"}),
    ])


def _rules(tmp_path, body):
    import yaml

    directory = tmp_path / "rules"
    directory.mkdir(exist_ok=True)
    (directory / "r.yml").write_text(yaml.safe_dump(body, sort_keys=False), encoding="utf-8")
    return directory


_RESOLVED = {"title": "ok", "id": "ok", "logsource": {"product": "windows", "category": "process_creation"},
             "detection": {"selection": {"EventID": 4688}, "condition": "selection"}, "tags": ["attack.t1059"]}
_BLIND = {"title": "blind", "id": "blind", "logsource": {"product": "windows", "category": "process_creation"},
          "detection": {"selection": {"Image": "x"}, "condition": "selection"}, "tags": ["attack.t1059"]}


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_generate_telemetry_writes_a_corpus(tmp_path):
    out = tmp_path / "t.parquet"
    result = runner.invoke(app, ["generate-telemetry", "--events", "500", "--out", str(out), "--seed", "3"])
    assert result.exit_code == 0
    assert out.exists()
    assert "wrote 500 events" in result.output


def test_audit_reports_the_headline_number(tmp_path):
    result = runner.invoke(app, ["audit", "--rules", str(_rules(tmp_path, _BLIND)),
                                 "--telemetry", str(_corpus(tmp_path))])
    assert result.exit_code == 0
    assert "blind technique pct  100.0%" in result.output


def test_audit_writes_html_and_json(tmp_path):
    html, js = tmp_path / "r.html", tmp_path / "r.json"
    result = runner.invoke(app, ["audit", "--rules", str(_rules(tmp_path, _BLIND)),
                                 "--telemetry", str(_corpus(tmp_path)),
                                 "--out", str(html), "--json", str(js)])
    assert result.exit_code == 0
    assert "<!doctype html>" in html.read_text(encoding="utf-8")
    payload = json.loads(js.read_text(encoding="utf-8"))
    assert payload["summary"]["blind_technique_pct"] == 100.0
    assert payload["findings"][0]["action"]


def test_audit_rejects_a_missing_rules_directory(tmp_path):
    result = runner.invoke(app, ["audit", "--rules", str(tmp_path / "nope"),
                                 "--telemetry", str(_corpus(tmp_path))])
    assert result.exit_code != 0


def test_gate_passes_within_threshold(tmp_path):
    result = runner.invoke(app, ["gate", "--rules", str(_rules(tmp_path, _RESOLVED)),
                                 "--telemetry", str(_corpus(tmp_path)), "--max-blind-pct", "50"])
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_gate_fails_above_threshold(tmp_path):
    result = runner.invoke(app, ["gate", "--rules", str(_rules(tmp_path, _BLIND)),
                                 "--telemetry", str(_corpus(tmp_path)), "--max-blind-pct", "50"])
    assert result.exit_code == 2
    assert "FAIL" in result.output


def test_gate_fails_on_unparseable_rules(tmp_path):
    directory = _rules(tmp_path, _RESOLVED)
    (directory / "broken.yml").write_text("title: x\nlogsource: {product: windows}\n", encoding="utf-8")
    result = runner.invoke(app, ["gate", "--rules", str(directory),
                                 "--telemetry", str(_corpus(tmp_path)), "--max-blind-pct", "99"])
    assert result.exit_code == 2
    assert "unparseable" in result.output


def test_gate_tolerates_unparseable_rules_when_allowed(tmp_path):
    directory = _rules(tmp_path, _RESOLVED)
    (directory / "broken.yml").write_text("title: x\nlogsource: {product: windows}\n", encoding="utf-8")
    result = runner.invoke(app, ["gate", "--rules", str(directory),
                                 "--telemetry", str(_corpus(tmp_path)),
                                 "--max-blind-pct", "99", "--max-unparseable", "1"])
    assert result.exit_code == 0


def test_sample_flag_limits_profiled_events(tmp_path):
    rows = [("windows/process_creation", {"EventID": 4688}) for _ in range(400)]
    corpus = write_corpus(tmp_path / "big.parquet", rows)
    result = runner.invoke(app, ["audit", "--rules", str(_rules(tmp_path, _RESOLVED)),
                                 "--telemetry", str(corpus), "--sample", "50"])
    assert result.exit_code == 0
