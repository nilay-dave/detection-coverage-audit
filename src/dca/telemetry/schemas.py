"""Load and validate the telemetry schema specification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_SPEC = Path(__file__).parent / "schemas.yml"


class SchemaError(ValueError):
    """Raised when the telemetry specification cannot be used."""


@dataclass(frozen=True)
class FieldSpec:
    name: str
    presence: float
    kind: str
    values: list | None = None
    value: object | None = None


@dataclass(frozen=True)
class SourceSpec:
    key: str
    share: float
    note: str
    fields: tuple[FieldSpec, ...]


@dataclass(frozen=True)
class TelemetrySpec:
    sources: tuple[SourceSpec, ...]

    def by_key(self, key: str) -> SourceSpec | None:
        for source in self.sources:
            if source.key == key:
                return source
        return None

    @property
    def keys(self) -> frozenset[str]:
        return frozenset(s.key for s in self.sources)


def load_spec(path: Path | str | None = None) -> TelemetrySpec:
    spec_path = Path(path) if path else DEFAULT_SPEC
    raw = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "sources" not in raw:
        raise SchemaError(f"{spec_path} has no 'sources' mapping")

    sources: list[SourceSpec] = []
    for key, body in raw["sources"].items():
        fields = []
        for field_name, field_body in (body.get("fields") or {}).items():
            presence = float(field_body.get("presence", 1.0))
            if not 0.0 < presence <= 1.0:
                raise SchemaError(f"{key}.{field_name}: presence must be in (0, 1], got {presence}")
            fields.append(
                FieldSpec(
                    name=str(field_name),
                    presence=presence,
                    kind=str(field_body.get("kind", "word")),
                    values=field_body.get("values"),
                    value=field_body.get("value"),
                )
            )
        if not fields:
            raise SchemaError(f"source {key} declares no fields")
        sources.append(
            SourceSpec(
                key=str(key),
                share=float(body.get("share", 0.0)),
                note=str(body.get("note", "")),
                fields=tuple(fields),
            )
        )

    total = sum(s.share for s in sources)
    if abs(total - 1.0) > 1e-6:
        raise SchemaError(f"source shares must sum to 1.0, got {total:.6f}")
    return TelemetrySpec(sources=tuple(sources))
