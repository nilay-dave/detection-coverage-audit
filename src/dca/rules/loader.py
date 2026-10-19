"""Load Sigma detection rules from disk.

The loader is deliberately tolerant: a detection repository in the real world
always contains a few rules that do not parse, and an audit that aborts on the
first bad file is an audit nobody runs. Unparseable rules are collected and
reported rather than raised, because a rule that cannot be parsed is itself a
coverage finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from dca.logging import get_logger

log = get_logger(__name__)

RULE_SUFFIXES = {".yml", ".yaml"}


@dataclass(frozen=True)
class LoadedRule:
    """One parsed Sigma rule, reduced to what the audit needs."""

    path: Path
    rule_id: str
    title: str
    logsource: dict[str, str]
    raw: dict

    @property
    def logsource_key(self) -> str:
        """Stable key used to join a rule to a telemetry stream."""
        parts = [self.logsource.get(k, "") for k in ("product", "service", "category")]
        return "/".join(p for p in parts if p) or "unspecified"


@dataclass(frozen=True)
class RuleLoadError:
    path: Path
    reason: str


@dataclass(frozen=True)
class RuleSet:
    rules: list[LoadedRule]
    errors: list[RuleLoadError]

    def __len__(self) -> int:
        return len(self.rules)


def _coerce_logsource(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items() if isinstance(v, (str, int))}


def load_rules(directory: Path) -> RuleSet:
    """Load every Sigma rule under `directory`, recursively."""
    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"rule directory does not exist: {directory}")
    if not directory.is_dir():
        raise NotADirectoryError(f"rule path is not a directory: {directory}")

    rules: list[LoadedRule] = []
    errors: list[RuleLoadError] = []

    for path in sorted(directory.rglob("*")):
        if path.suffix.lower() not in RULE_SUFFIXES or not path.is_file():
            continue
        try:
            documents = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
        except yaml.YAMLError as exc:
            errors.append(RuleLoadError(path, f"invalid yaml: {exc.__class__.__name__}"))
            continue
        if not documents:
            errors.append(RuleLoadError(path, "file contains no yaml documents"))
            continue
        for doc in documents:
            if not isinstance(doc, dict):
                errors.append(RuleLoadError(path, "top level yaml is not a mapping"))
                continue
            if "detection" not in doc:
                errors.append(RuleLoadError(path, "rule has no detection block"))
                continue
            rules.append(
                LoadedRule(
                    path=path,
                    rule_id=str(doc.get("id") or path.stem),
                    title=str(doc.get("title") or path.stem),
                    logsource=_coerce_logsource(doc.get("logsource")),
                    raw=doc,
                )
            )

    log.info(
        "rules loaded",
        extra={"rule_count": len(rules), "error_count": len(errors), "directory": str(directory)},
    )
    return RuleSet(rules=rules, errors=errors)
