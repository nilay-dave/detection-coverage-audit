# ADR-004: Profile the corpus in bounded batches

Status: accepted
Date: 2026-10-19

## Context

The profiler expands each event into one row per leaf field with DuckDB's
`json_tree`, deduplicates those rows per event, and counts them. The first
implementation ran that as a single statement over the whole corpus.

At 100,000 and 1,000,000 events it worked and was fast. At 10,000,000 events it
raised `OutOfMemoryError: could not allocate block of size 256.0 KiB
(4.6 GiB/4.6 GiB used)`.

The arithmetic is unsurprising in hindsight. Six to eight fields per event
across 10M events is roughly 65M leaf rows, and the `DISTINCT` over
(row id, log source, field, shape) has to hold a hash table proportional to
that. Memory scaled with corpus size, which is the one thing a tool meant for
90 day windows cannot do.

This mattered beyond the error itself. The scenario that failed was the one the
README's scalability claim depended on. Had the benchmark quietly skipped it,
the published throughput figure would have been an extrapolation from 1M events
presented as a measurement.

## Options considered

1. **Raise `memory_limit`.** Rejected. It moves the ceiling without removing
   it, and on a host with 8GB of RAM it trades a clean DuckDB error for the OS
   OOM killer, which is a much worse failure mode inside a scheduled job.
2. **`SET preserve_insertion_order = false`.** DuckDB suggests this and it does
   reduce peak memory, but the saving is a fraction and the ceiling remains
   proportional to corpus size.
3. **Require sampling above some corpus size.** Rejected as a silent accuracy
   change: the tool would have started answering a different question than the
   one asked, without the operator choosing that.
4. **Spill to disk via a persistent DuckDB database file.** Workable, and
   rejected for v1 because it introduces a temporary file to manage, clean up
   and fail on when the disk is full.
5. **Aggregate over bounded batches of rows.** Chosen.

## Decision

Materialize the sample once, then profile contiguous `rowid` ranges of
`BATCH_ROWS` events each, summing the per field tallies in Python. Peak memory
is set by the batch size, not the corpus size.

## Consequences

Correctness depends on one property: a batch is a contiguous `rowid` range, so
no event is split across two batches, and therefore an event counted once for a
field in its own batch is counted exactly once overall. Two tests assert this
directly, including one that sweeps batch sizes of 1, 2, 7, 50, 100, 101 and
1000 over a 101 event corpus to catch an off by one at a boundary. Batched
output was also verified identical to single statement output on a 1M event
corpus.

The cost is a small amount of Python level aggregation per batch and the loss of
one single statement elegance. In exchange, runtime stays linear and memory stays
flat, which is what lets the 10M scenario be a measurement rather than a
projection.

`BATCH_ROWS` is a module constant rather than a config value. It is a memory
safety property of the implementation, not a knob an operator should be
reasoning about, and the tests set it directly when they need to.
