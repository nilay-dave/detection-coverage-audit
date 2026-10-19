"""Render an audit result as HTML and as JSON.

The HTML report is the artifact a detection engineering lead reads in a weekly
review, so it leads with the one number that matters and groups findings by what
the reader has to do about them. The JSON output is what CI consumes.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from dca.audit.engine import AuditResult, Verdict

ACTION_BY_VERDICT = {
    Verdict.NO_SOURCE: "Onboard the log source, or retire the rule.",
    Verdict.MISSING_FIELD: "Rewrite the rule against the field names this source emits, or extend the pipeline.",
    Verdict.UNPARSEABLE: "Fix or delete the rule file.",
    Verdict.RARE_FIELD: "Confirm the field is populated often enough for the rule to be useful.",
    Verdict.KEYWORD_ONLY: "Rewrite as a field based rule so coverage can be measured.",
    Verdict.RESOLVED: "No action.",
}


def to_dict(result: AuditResult) -> dict:
    """Serialize an audit result. This is the shape CI and the report both read."""
    return {
        "summary": {
            "rules_total": result.rule_count,
            "rules_unparseable": result.unparseable_count,
            "corpus_events": result.corpus_events,
            "corpus_sampled": result.corpus_sampled,
            "sources_observed": sorted(result.observed_sources),
            "techniques_mapped": result.mapped_technique_count,
            "techniques_blind": len(result.blind_techniques),
            "blind_technique_pct": round(result.blind_technique_pct, 2),
            "verdict_counts": {v.value: result.count(v) for v in Verdict},
        },
        "blind_techniques": [t.technique for t in result.blind_techniques],
        "findings": [
            {
                **{k: v for k, v in asdict(finding).items() if k != "techniques"},
                "verdict": finding.verdict.value,
                "techniques": sorted(finding.techniques),
                "action": ACTION_BY_VERDICT[finding.verdict],
            }
            for finding in sorted(
                result.findings, key=lambda f: (not f.verdict.is_blind, f.verdict.value, f.rule_id)
            )
        ],
    }


def render_json(result: AuditResult, out_path: Path | str) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(to_dict(result), indent=2) + "\n", encoding="utf-8")
    return out_path


def render_html(result: AuditResult, out_path: Path | str, template_dir: Path | None = None) -> Path:
    template_dir = template_dir or Path(__file__).parent / "templates"
    # autoescape is set unconditionally rather than through select_autoescape,
    # which decides by final file extension and therefore left a template named
    # report.html.j2 unescaped. Rule titles and log source names come from YAML
    # files in somebody else's detection repository and are rendered into a page
    # opened in a browser, so escaping is not optional here.
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    payload = to_dict(result)
    html = env.get_template("report.html.j2").render(**payload)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path
