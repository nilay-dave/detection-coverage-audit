# ADR-001: Measure field presence from a sample rather than replaying all telemetry

Status: accepted
Date: 2026-10-19

## Context

The audit needs to know which fields a log source actually populates. There are
three ways to find out.

Read the pipeline configuration. This is cheap and wrong: a field declared in a
parser is not a field that arrives populated, and the gap between the two is
exactly what this tool exists to find.

Replay the whole corpus. This is correct and expensive. Profiling measures
107,300 events per second on the hardware recorded in benchmark/results, so a
90 day window at 2,000 events per second, which is a small enterprise, is
15.5 billion events and roughly 40 hours of profiling. Nobody runs that weekly.

Sample the corpus. This is correct within a stated confidence bound and cheap.

## Options considered

1. Parse the pipeline configuration only. Rejected: it measures intent, not fact.
2. Full replay, every run. Rejected on runtime for any realistic window.
3. Full replay with incremental state across runs. Rejected for v1: it adds a
   state store and a cache invalidation problem to a tool whose first version
   should be a single command with no persistent state.
4. Reservoir sample with a fixed seed, with full replay available. Chosen.

## Decision

Profile a reservoir sample of configurable size, seeded so a run is
reproducible, and default to profiling everything so that a small corpus gets an
exact answer with no flag. `--sample N` switches to sampling.

## Consequences

A field that appears in fewer than roughly 1/N of events in its source can be
missed by an N row sample, and the tool will report the rule that keys on it as
blind when it is merely rare. That is the right direction for the error to point:
a false blind finding costs an engineer five minutes of checking, a false
coverage finding costs an undetected intrusion.

Sampling is reservoir rather than Bernoulli so the sample size is exact, and
seeded so two runs over an unchanged corpus produce the same answer. Without the
seed, a rare field would flicker in and out of the report between runs and
nobody would trust it.

The RARE_FIELD verdict exists because of this decision. A field present in
0.04% of events is not missing and not usefully covered either, so collapsing it
into either RESOLVED or MISSING_FIELD would have hidden a real finding.
