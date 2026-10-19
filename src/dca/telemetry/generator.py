"""Generate a reproducible synthetic telemetry corpus.

The corpus is synthetic on purpose. A portfolio repository cannot ship real
enterprise telemetry, and a sample scraped from a public dataset would not
contain the field level gaps this tool exists to find. What matters for the
audit is that the generator emits exactly the fields the schema specification
declares, no more, so that any gap the audit reports is traceable to a line in
schemas.yml rather than to an accident of generation.

Every number this project publishes that derives from this corpus is labelled
as a simulation.

Known limitation, stated because it would otherwise look like a bug: field
values within one event are drawn independently, so an event can carry a
semantically impossible combination such as eventSource iam.amazonaws.com with
eventName DescribeInstances. The audit joins on field presence and never reads
a field value, so independence does not affect any published result. Any future
feature that reads values will need a correlated generator, which is recorded in
the roadmap.
"""

from __future__ import annotations

import json
import random
import string
from dataclasses import dataclass
from pathlib import Path

import duckdb
import pandas as pd

from dca.logging import get_logger
from dca.telemetry.schemas import FieldSpec, SourceSpec, TelemetrySpec, load_spec

log = get_logger(__name__)

CHUNK_ROWS = 50_000

_HOSTS = [f"WKS-{i:04d}" for i in range(1, 240)] + [f"SRV-{i:03d}" for i in range(1, 60)]
_USERS = ["jdoe", "asmith", "svc_backup", "svc_sql", "mpatel", "rlee", "administrator", "kchen"]
_BINARIES = [
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    r"C:\Windows\System32\schtasks.exe",
    r"C:\Windows\explorer.exe",
]
_DOMAINS = ["updates.contoso.com", "login.microsoftonline.com", "cdn.jsdelivr.net", "api.github.com", "telemetry.example.net"]
_REGPATHS = [
    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
]


@dataclass(frozen=True)
class GenerationResult:
    path: Path
    events: int
    sources: dict[str, int]
    seed: int


def _value(spec: FieldSpec, rng: random.Random) -> object:
    kind = spec.kind
    if kind == "const":
        return spec.value
    if kind == "choice":
        return rng.choice(spec.values or ["unknown"])
    if kind == "host":
        return rng.choice(_HOSTS)
    if kind == "user":
        return rng.choice(_USERS)
    if kind == "path":
        return rng.choice(_BINARIES)
    if kind == "regpath":
        return rng.choice(_REGPATHS)
    if kind == "cmdline":
        binary = rng.choice(_BINARIES)
        tail = rng.choice(["", " /c dir", " -NoProfile -Command Get-Service", " /create /tn Updater", " -enc UwB0AGEAcgB0AA=="])
        return f'"{binary}"{tail}'
    if kind == "pid":
        return rng.randrange(400, 65000)
    if kind == "ip":
        return f"{rng.choice([10, 172, 192])}.{rng.randrange(0, 255)}.{rng.randrange(0, 255)}.{rng.randrange(1, 254)}"
    if kind == "arn":
        return f"arn:aws:iam::{rng.randrange(10**11, 10**12)}:user/{rng.choice(_USERS)}"
    if kind == "policyarn":
        return rng.choice(["arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/AdministratorAccess"])
    if kind == "domain":
        return rng.choice(_DOMAINS)
    if kind == "epoch":
        return round(rng.uniform(1_760_000_000, 1_762_000_000), 3)
    if kind == "word":
        return "".join(rng.choices(string.ascii_lowercase, k=rng.randrange(4, 11)))
    raise ValueError(f"unknown field kind: {kind}")


def _assign(event: dict, dotted: str, value: object) -> None:
    """Write a dotted field name into the event as a nested object."""
    parts = dotted.split(".")
    node = event
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            node[part] = nxt
        node = nxt
    node[parts[-1]] = value


def _build_event(source: SourceSpec, rng: random.Random) -> str:
    event: dict = {}
    for field_spec in source.fields:
        if field_spec.presence < 1.0 and rng.random() > field_spec.presence:
            continue
        _assign(event, field_spec.name, _value(field_spec, rng))
    return json.dumps(event, separators=(",", ":"))


def generate(
    out_path: Path | str,
    events: int,
    seed: int = 7,
    spec: TelemetrySpec | None = None,
) -> GenerationResult:
    """Write `events` synthetic events to a parquet file at `out_path`."""
    if events <= 0:
        raise ValueError(f"events must be positive, got {events}")

    spec = spec or load_spec()
    rng = random.Random(seed)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    sources = list(spec.sources)
    weights = [s.share for s in sources]
    counts: dict[str, int] = {s.key: 0 for s in sources}

    con = duckdb.connect()
    con.execute("CREATE TABLE events (logsource_key VARCHAR, event JSON)")

    # Rows are inserted a chunk at a time through a registered DataFrame rather
    # than with executemany. See ADR-003: executemany binds one row per round
    # trip and measured 2403 events per second, which put a 10M event corpus at
    # 69 minutes. Chunked DataFrame registration measured 308 times faster on
    # the insert path alone. Chunking is retained so peak memory stays bounded
    # by CHUNK_ROWS rather than by corpus size.
    written = 0
    while written < events:
        size = min(CHUNK_ROWS, events - written)
        chosen = rng.choices(sources, weights=weights, k=size)
        rows = []
        for source in chosen:
            counts[source.key] += 1
            rows.append((source.key, _build_event(source, rng)))
        chunk = pd.DataFrame(rows, columns=["logsource_key", "event"])
        con.register("chunk", chunk)
        con.execute("INSERT INTO events SELECT logsource_key, event::JSON FROM chunk")
        con.unregister("chunk")
        written += size

    con.execute(f"COPY events TO '{out_path.as_posix()}' (FORMAT PARQUET, COMPRESSION ZSTD)")
    con.close()

    log.info("telemetry generated", extra={"events": events, "path": str(out_path), "seed": seed})
    return GenerationResult(path=out_path, events=events, sources=counts, seed=seed)
