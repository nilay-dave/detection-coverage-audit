# ADR-003: Insert generated events through chunked DataFrames

Status: accepted
Date: 2026-10-19

## Context

The corpus generator writes synthetic events into DuckDB before copying them to
parquet. The first implementation used `executemany` with a parameter list,
which is the idiomatic DBAPI approach and is what most examples show.

Measured on the hardware recorded in benchmark/results:

| Insert path | Throughput | 10M event corpus |
| --- | --- | --- |
| `executemany`, one row per bind | 2,403 events/sec | 69 minutes |
| Chunked DataFrame registration | 53,938 events/sec | 3.1 minutes |

The insert path alone measured 308 times faster in isolation; end to end the
generator is 22 times faster, because JSON construction in Python then becomes
the dominant cost.

## Options considered

1. `executemany`. Rejected on the numbers above. A 69 minute generation step
   would have made the 10M event benchmark scenario impractical to run, which
   means it would not have been run, which means the scalability claim in the
   README would have been an extrapolation.
2. **DuckDB appender API.** Comparable throughput, but it binds to a table
   created ahead of time and expresses the column types twice.
3. **Write parquet directly with pyarrow,** bypassing DuckDB on the write path.
   Fastest in principle and rejected as a dependency the project otherwise does
   not need: DuckDB is already present for the read path.
4. **Chunked DataFrame registration.** Chosen.

## Decision

Build rows in Python, then register each chunk of `CHUNK_ROWS` as a DataFrame
and insert it with a single statement.

## Consequences

Peak memory is bounded by the chunk size rather than by corpus size, which is
why the chunking is retained now that it is no longer needed for throughput. A
10M event corpus generates in about 3 minutes with a flat memory profile.

Output is byte identical to the `executemany` implementation at the same seed,
verified with an `EXCEPT` over both parquet files, so the change carries no risk
of having quietly altered the corpora that earlier numbers were measured on.

pandas becomes a hard dependency of the generator. It was already an indirect
one through the test fixtures, and the alternative was adding pyarrow instead,
so this costs nothing in practice.
