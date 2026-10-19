# ADR-002: DuckDB over Elasticsearch for the telemetry side

Status: accepted
Date: 2026-10-19

## Context

The audit has to scan a telemetry corpus and count field presence per log
source. The obvious instinct in a security engineering team is to point the tool
at the SIEM, because the data is already there. The less obvious question is
what the tool should depend on in order to run.

## Options considered

1. **Query the SIEM directly** (Splunk REST, Elasticsearch `_search`). Attractive
   because the data is live. Rejected for v1: it makes the tool untestable
   without a cluster, couples it to one vendor's field naming, and means a
   developer cannot run it at all without production credentials. It also turns
   a weekly audit into load on the platform the SOC depends on.
2. **Stand up Elasticsearch locally** for the corpus. Rejected: a container, a
   JVM heap to tune and an index mapping to maintain, in exchange for a
   full text engine whose strengths this workload never touches. The audit does
   aggregation over a columnar scan, which is the one thing Elasticsearch is
   worst at.
3. **Pandas in memory.** Rejected on the 10M event scenario, where holding
   decoded JSON for the whole corpus is the dominant cost and the profile is
   already a single aggregation that never needs the whole corpus resident.
4. **DuckDB over parquet.** Chosen.

## Decision

Read the corpus as parquet with DuckDB. The audit depends on a library, not a
service. No container, no daemon, no credentials, no mapping.

## Consequences

The boring choice buys three things that matter more than novelty here.

The test suite runs with no external services, which is why
`make verify` works on a clean checkout and in CI without a compose file. That
is the single largest reason this repository can be cloned and verified in under
two minutes.

`json_tree` gives recursive field extraction in SQL, which is the entire
profiler. The alternative was walking decoded JSON in Python, which measured
slower and would have been more code.

The cost is that the corpus has to be exported to parquet first rather than read
live from the SIEM. For a weekly audit, an export is a scheduled job and this is
not a real constraint. For an ad hoc "is this new rule going to fire" question,
it is friction, and that is the trigger condition recorded in the Pivot section
of the README for adding a Splunk ingestion path.

DuckDB's `USING SAMPLE` also made ADR-001's sampling a one line change rather
than a sampling implementation.
