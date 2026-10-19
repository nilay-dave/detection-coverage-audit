"""Command line interface.

Three verbs: generate a corpus, audit rules against one, and gate CI on the
result. The gate exists so the audit can run as a required check on a detection
content repository rather than as a report somebody remembers to read.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import typer

from dca import __version__
from dca.audit.engine import Verdict, audit as run_audit
from dca.config import load_config
from dca.logging import configure, get_logger
from dca.report.render import render_html, render_json, to_dict
from dca.telemetry.generator import generate as generate_corpus
from dca.telemetry.profile import profile_corpus

app = typer.Typer(add_completion=False, help="Measure which detections can fire on the telemetry you actually collect.")
log = get_logger(__name__)

EXIT_OK = 0
EXIT_THRESHOLD_EXCEEDED = 2
EXIT_USAGE = 64


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit(EXIT_OK)


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True, help="Print the version and exit."),
    log_level: str = typer.Option("INFO", "--log-level", help="Log level for the structured JSON log on stderr."),
) -> None:
    configure(log_level.upper())


@app.command("generate-telemetry")
def generate_telemetry(
    events: int = typer.Option(100_000, "--events", min=1, help="Number of events to generate."),
    out: Path = typer.Option(Path("data/generated/telemetry.parquet"), "--out", help="Parquet file to write."),
    seed: int = typer.Option(7, "--seed", help="Seed, so a corpus is reproducible."),
) -> None:
    """Generate a synthetic telemetry corpus from the bundled schema spec."""
    result = generate_corpus(out, events, seed=seed)
    typer.echo(f"wrote {result.events} events to {result.path}")
    for key, count in sorted(result.sources.items(), key=lambda kv: -kv[1]):
        typer.echo(f"  {key:28s} {count:>9,}")


@app.command()
def audit(
    rules: Path = typer.Option(..., "--rules", exists=True, help="Directory of Sigma rules."),
    telemetry: Path = typer.Option(..., "--telemetry", exists=True, help="Parquet telemetry corpus."),
    out: Path | None = typer.Option(None, "--out", help="Write an HTML report here."),
    json_out: Path | None = typer.Option(None, "--json", help="Write the machine readable result here."),
    sample: int = typer.Option(0, "--sample", min=0, help="Profile only this many events. 0 profiles all."),
) -> None:
    """Audit a rule directory against a telemetry corpus."""
    config = replace(load_config(), sample_rows=sample)
    profile = profile_corpus(telemetry, config)
    result = run_audit(rules, profile, config)

    typer.echo("")
    typer.echo(f"  rules audited        {result.rule_count}")
    typer.echo(f"  techniques mapped    {result.mapped_technique_count}")
    typer.echo(f"  techniques blind     {len(result.blind_techniques)}")
    typer.echo(f"  blind technique pct  {result.blind_technique_pct:.1f}%")
    typer.echo("")
    for verdict in Verdict:
        typer.echo(f"  {verdict.value:16s} {result.count(verdict)}")
    typer.echo("")

    if out:
        typer.echo(f"html report  {render_html(result, out)}")
    if json_out:
        typer.echo(f"json result  {render_json(result, json_out)}")


@app.command()
def gate(
    rules: Path = typer.Option(..., "--rules", exists=True, help="Directory of Sigma rules."),
    telemetry: Path = typer.Option(..., "--telemetry", exists=True, help="Parquet telemetry corpus."),
    max_blind_pct: float = typer.Option(50.0, "--max-blind-pct", help="Fail above this percentage of blind techniques."),
    max_unparseable: int = typer.Option(0, "--max-unparseable", min=0, help="Fail above this many unparseable rules."),
) -> None:
    """Exit non zero when coverage falls below a threshold. For use in CI."""
    config = load_config()
    profile = profile_corpus(telemetry, config)
    result = run_audit(rules, profile, config)
    summary = to_dict(result)["summary"]

    failures: list[str] = []
    if result.blind_technique_pct > max_blind_pct:
        failures.append(f"blind technique pct {result.blind_technique_pct:.1f} exceeds limit {max_blind_pct:.1f}")
    if result.unparseable_count > max_unparseable:
        failures.append(f"{result.unparseable_count} unparseable rules exceed limit {max_unparseable}")

    for key in ("rules_total", "techniques_mapped", "techniques_blind", "blind_technique_pct"):
        typer.echo(f"  {key:22s} {summary[key]}")

    if failures:
        typer.echo("")
        for failure in failures:
            typer.echo(f"  FAIL  {failure}", err=True)
        raise typer.Exit(EXIT_THRESHOLD_EXCEEDED)

    typer.echo("")
    typer.echo("  PASS  coverage within thresholds")
