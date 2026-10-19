# detection-coverage-audit

A coverage heatmap counts rules. It cannot tell you whether a rule could ever
fire on the telemetry you actually collect. This tool measures that difference.

Point it at a directory of Sigma rules and a parquet export of your telemetry.
It reports, per rule, whether the log source exists, whether every field the
rule keys on is populated, and how often. Then it rolls that up to ATT&CK
technique level, because technique level is what a heatmap displays and
technique level is where the illusion lives.

## Start here

- [How the audit works](how-it-works.md) walks the pipeline from rule file to
  verdict.
- [Verdicts](verdicts.md) explains the five outcomes and what an engineer does
  about each.
- The [example report](report.html) is generated on every docs deploy from the
  bundled rule pack and a freshly generated synthetic corpus.

## Install

```bash
pip install detection-coverage-audit
```

## The shortest useful run

```bash
dca generate-telemetry --events 200000 --out corpus.parquet --seed 7
dca audit --rules rules/ --telemetry corpus.parquet --out report.html
```

The first command exists so the tool can be evaluated without exporting
anything from a production SIEM. Replace it with your own parquet export and the
numbers stop being a simulation.

## Decisions

Four decisions shaped this tool more than any other, and each is written up with
the options that were rejected and why:

- [ADR-001](adr/adr-001-sampled-field-presence.md): measure field presence from
  a sample rather than replaying every event.
- [ADR-002](adr/adr-002-duckdb-over-elasticsearch.md): depend on a library
  rather than a cluster.
- [ADR-003](adr/adr-003-chunked-dataframe-insert.md): why the generator inserts
  through DataFrames.
- [ADR-004](adr/adr-004-bounded-batch-profiling.md): why profiling is batched,
  and the out of memory error that forced it.
