"""Configuration surface.

Every tunable the audit depends on lives here, sourced from environment
variables with documented defaults. Nothing in the audit path reads a literal
path, threshold or field name directly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


class ConfigError(ValueError):
    """Raised when configuration is present but unusable."""


@dataclass(frozen=True)
class Config:
    """Runtime configuration for an audit run."""

    # A field seen in fewer than this fraction of events in its own log source
    # is reported as rare rather than present. ADR-001 explains the choice.
    rare_field_threshold: float = field(default_factory=lambda: _env_float("DCA_RARE_FIELD_THRESHOLD", 0.001))

    # Rows sampled from the telemetry corpus when profiling field presence.
    # Zero means profile the whole corpus.
    sample_rows: int = field(default_factory=lambda: _env_int("DCA_SAMPLE_ROWS", 0))

    # Seed for every random path in the project, so results are reproducible.
    seed: int = field(default_factory=lambda: _env_int("DCA_SEED", 7))

    duckdb_threads: int = field(default_factory=lambda: _env_int("DCA_DUCKDB_THREADS", 4))

    report_template: Path = field(
        default_factory=lambda: Path(os.environ.get("DCA_REPORT_TEMPLATE", "")) or Path(__file__).parent / "report" / "templates" / "report.html.j2"
    )

    def __post_init__(self) -> None:
        if not 0.0 <= self.rare_field_threshold < 1.0:
            raise ConfigError(f"rare_field_threshold must be in [0, 1), got {self.rare_field_threshold}")
        if self.sample_rows < 0:
            raise ConfigError(f"sample_rows must not be negative, got {self.sample_rows}")
        if self.duckdb_threads < 1:
            raise ConfigError(f"duckdb_threads must be at least 1, got {self.duckdb_threads}")


def load_config() -> Config:
    """Build a Config from the environment."""
    return Config()
