"""Profile which fields are actually present in a telemetry corpus.

This is the half of the audit that production deployments get wrong. A coverage
heatmap counts rules. This module counts fields, per log source, from the events
themselves, so a rule keyed on a field that was never onboarded can be told
apart from a rule keyed on a field that is simply rare.

Nested fields are flattened to dotted paths so that a rule referencing
`userIdentity.type` resolves against a CloudTrail record that nests it.

Two field shapes flatten to the same dotted path and must not be conflated:
a literal key containing a dot (Zeek writes `id.orig_h` as one key) and a
nested object (CloudTrail nests `type` under `userIdentity`). Both produce the
json_tree fullkey `$.id.orig_h`. The profiler therefore reconstructs the path
from the parent path plus the leaf key, and records which shape was observed,
because the two require different field extractions in the SIEM. See the
Hardest problem solved section of the README.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import duckdb

from dca.config import Config
from dca.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class FieldPresence:
    logsource_key: str
    field: str
    events_with_field: int
    events_in_source: int
    # True when the corpus stores this path as one key containing a dot rather
    # than as a nested object. Changes the extraction the SIEM needs.
    literal_dotted_key: bool = False

    @property
    def presence(self) -> float:
        if self.events_in_source == 0:
            return 0.0
        return self.events_with_field / self.events_in_source


@dataclass(frozen=True)
class CorpusProfile:
    total_events: int
    sampled_events: int
    source_counts: dict[str, int]
    presence: dict[str, dict[str, FieldPresence]]

    def fields_for(self, logsource_key: str) -> dict[str, FieldPresence]:
        return self.presence.get(logsource_key, {})

    @property
    def observed_sources(self) -> frozenset[str]:
        return frozenset(self.presence)


# Flattens a JSON event into dotted leaf paths. json_tree gives one row per node;
# a node with no children and a non-null key path is a leaf the rule can match.
# Profiles the `sampled` view, which is materialized once by profile_corpus so
# that the field counts and the per source counts describe the same rows. Two
# independent USING SAMPLE clauses would draw two different samples.
_PROFILE_SQL = """
WITH src AS (
    -- rowid rather than a row_number window: the window sorts the whole corpus
    -- for no benefit, and only row identity is needed here.
    SELECT rowid AS rid, logsource_key, event FROM sampled
),
counts AS (
    SELECT logsource_key, count(*) AS events_in_source FROM src GROUP BY 1
),
leaves AS (
    -- DISTINCT here plus count(*) below, rather than count(DISTINCT rid) in the
    -- outer query. Measured 8.78s against 11.47s on a 1M event corpus with
    -- identical output. One event can legitimately carry the same dotted path
    -- twice, once as a literal key and once nested, so the deduplication is
    -- required for correctness and not only for speed.
    SELECT DISTINCT
        s.rid,
        s.logsource_key,
        -- Reconstruct the dotted path from the PARENT path plus this leaf's own
        -- key. Using json_tree's fullkey directly would make a literal dotted
        -- key indistinguishable from a nested object.
        CASE
            WHEN t.path = '$' THEN t.key
            ELSE substr(t.path, 3) || '.' || t.key
        END AS field,
        -- A leaf key that itself contains a dot is the literal shape.
        t.key LIKE '%.%' AS literal_dotted_key
    FROM src s, json_tree(s.event) t
    WHERE t.type NOT IN ('OBJECT', 'ARRAY')
      AND t.key IS NOT NULL
)
SELECT
    l.logsource_key,
    l.field,
    count(*) AS events_with_field,
    c.events_in_source,
    max(l.literal_dotted_key) AS literal_dotted_key
FROM leaves l
JOIN counts c USING (logsource_key)
GROUP BY 1, 2, 4
ORDER BY 1, 2
"""


def profile_corpus(parquet_path: Path | str, config: Config) -> CorpusProfile:
    """Measure field presence per log source in a parquet telemetry corpus."""
    parquet_path = Path(parquet_path)
    if not parquet_path.exists():
        raise FileNotFoundError(f"telemetry corpus not found: {parquet_path}")

    con = duckdb.connect()
    con.execute(f"SET threads = {config.duckdb_threads}")

    path_str = parquet_path.as_posix()
    total = con.execute("SELECT count(*) FROM read_parquet(?)", [path_str]).fetchone()[0]
    if total == 0:
        con.close()
        raise ValueError(f"telemetry corpus is empty: {parquet_path}")

    # Materialize the sample once. Reservoir sampling with an explicit seed keeps
    # a sampled run reproducible, and materializing keeps every downstream query
    # describing the same rows.
    if config.sample_rows and config.sample_rows < total:
        con.execute(
            "CREATE TEMP TABLE sampled AS "
            "SELECT logsource_key, event FROM read_parquet(?) "
            f"USING SAMPLE {config.sample_rows} ROWS (reservoir, {config.seed})",
            [path_str],
        )
    else:
        con.execute(
            "CREATE TEMP TABLE sampled AS SELECT logsource_key, event FROM read_parquet(?)",
            [path_str],
        )

    rows = con.execute(_PROFILE_SQL).fetchall()
    source_rows = con.execute(
        "SELECT logsource_key, count(*) FROM sampled GROUP BY 1"
    ).fetchall()
    con.close()

    presence: dict[str, dict[str, FieldPresence]] = {}
    for logsource_key, field, with_field, in_source, dotted in rows:
        presence.setdefault(logsource_key, {})[field] = FieldPresence(
            logsource_key=logsource_key,
            field=field,
            events_with_field=int(with_field),
            events_in_source=int(in_source),
            literal_dotted_key=bool(dotted),
        )

    source_counts = {k: int(v) for k, v in source_rows}
    sampled = sum(source_counts.values())

    log.info(
        "corpus profiled",
        extra={
            "total_events": total,
            "sampled_events": sampled,
            "sources": len(source_counts),
            "distinct_fields": sum(len(v) for v in presence.values()),
        },
    )
    return CorpusProfile(
        total_events=int(total),
        sampled_events=sampled,
        source_counts=source_counts,
        presence=presence,
    )
