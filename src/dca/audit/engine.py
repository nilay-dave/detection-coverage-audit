"""The audit: join detection rules to observed telemetry fields.

A coverage heatmap answers "is there a rule for this technique". This module
answers the question a heatmap cannot: "could that rule ever fire on the
telemetry we actually collect". The two answers differ whenever a rule is
written against a log source that was never onboarded, or against a field that
the onboarded source does not populate.

Four verdicts, in order of severity:

  NO_SOURCE       the rule's log source is absent from the corpus entirely.
                  Nothing this rule references can ever be matched.
  MISSING_FIELD   the log source is present, but at least one field the rule
                  keys on never appears in it.
  RARE_FIELD      every field is present, but at least one falls below the
                  configured presence threshold, so the rule will fire on only
                  a fraction of the events it was written for.
  RESOLVED        the log source is present and every field the rule keys on is
                  present above the threshold.

KEYWORD_ONLY is reported separately. A rule that full-text searches the raw
event names no field, so field level resolution does not apply to it. Counting
it as resolved would overstate coverage and counting it as missing would
understate it, so it is its own category.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from enum import Enum
from pathlib import Path

from dca.config import Config
from dca.logging import get_logger
from dca.rules.attack import extract_techniques
from dca.rules.fields import extract_fields
from dca.rules.loader import RuleSet, load_rules
from dca.telemetry.profile import CorpusProfile

log = get_logger(__name__)


class Verdict(str, Enum):
    RESOLVED = "resolved"
    RARE_FIELD = "rare_field"
    MISSING_FIELD = "missing_field"
    NO_SOURCE = "no_source"
    KEYWORD_ONLY = "keyword_only"
    UNPARSEABLE = "unparseable"

    @property
    def is_blind(self) -> bool:
        """True when the rule cannot fire on the observed telemetry."""
        return self in (Verdict.MISSING_FIELD, Verdict.NO_SOURCE, Verdict.UNPARSEABLE)


@dataclass(frozen=True)
class RuleFinding:
    rule_id: str
    title: str
    path: str
    logsource_key: str
    techniques: frozenset[str]
    verdict: Verdict
    missing_fields: tuple[str, ...] = ()
    rare_fields: tuple[tuple[str, float], ...] = ()
    shape_warnings: tuple[str, ...] = ()
    detail: str = ""


@dataclass(frozen=True)
class TechniqueCoverage:
    technique: str
    rule_count: int
    blind_rule_count: int

    @property
    def is_blind(self) -> bool:
        """A technique is blind when every rule mapped to it is blind."""
        return self.rule_count > 0 and self.blind_rule_count == self.rule_count


@dataclass
class AuditResult:
    findings: list[RuleFinding] = dc_field(default_factory=list)
    techniques: dict[str, TechniqueCoverage] = dc_field(default_factory=dict)
    corpus_events: int = 0
    corpus_sampled: int = 0
    observed_sources: frozenset[str] = frozenset()
    rule_count: int = 0
    unparseable_count: int = 0

    @property
    def mapped_technique_count(self) -> int:
        return len(self.techniques)

    @property
    def blind_techniques(self) -> list[TechniqueCoverage]:
        return sorted(
            (t for t in self.techniques.values() if t.is_blind), key=lambda t: t.technique
        )

    @property
    def blind_technique_pct(self) -> float:
        """The headline number: mapped techniques with no rule that can fire."""
        if not self.techniques:
            return 0.0
        return 100.0 * len(self.blind_techniques) / len(self.techniques)

    def count(self, verdict: Verdict) -> int:
        return sum(1 for f in self.findings if f.verdict is verdict)


def _assess_rule(rule, profile: CorpusProfile, config: Config) -> RuleFinding:
    rule_fields = extract_fields(rule)
    techniques = extract_techniques(rule)
    source_key = rule.logsource_key
    common = {
        "rule_id": rule.rule_id,
        "title": rule.title,
        "path": str(rule.path),
        "logsource_key": source_key,
        "techniques": techniques,
    }

    if source_key not in profile.observed_sources:
        return RuleFinding(
            **common,
            verdict=Verdict.NO_SOURCE,
            detail=f"log source {source_key} produced no events in the corpus",
        )

    if rule_fields.keyword_only:
        return RuleFinding(
            **common,
            verdict=Verdict.KEYWORD_ONLY,
            detail="rule performs a full text keyword search and names no field",
        )

    observed = profile.fields_for(source_key)
    missing = sorted(f for f in rule_fields.fields if f not in observed)
    if missing:
        return RuleFinding(
            **common,
            verdict=Verdict.MISSING_FIELD,
            missing_fields=tuple(missing),
            detail=f"{len(missing)} of {len(rule_fields.fields)} referenced fields never appear in {source_key}",
        )

    rare = tuple(
        (f, observed[f].presence)
        for f in sorted(rule_fields.fields)
        if observed[f].presence < config.rare_field_threshold
    )
    shape_warnings = tuple(
        f"{f} is stored as one dotted key, not a nested object"
        for f in sorted(rule_fields.fields)
        if observed[f].literal_dotted_key
    )
    if rare:
        return RuleFinding(
            **common,
            verdict=Verdict.RARE_FIELD,
            rare_fields=rare,
            shape_warnings=shape_warnings,
            detail=f"{len(rare)} referenced fields fall below the {config.rare_field_threshold:.3%} presence threshold",
        )

    return RuleFinding(
        **common,
        verdict=Verdict.RESOLVED,
        shape_warnings=shape_warnings,
        detail="every referenced field is present above the threshold",
    )


def audit(rules_dir: Path | str, profile: CorpusProfile, config: Config) -> AuditResult:
    """Run a full audit of a rule directory against a profiled corpus."""
    ruleset: RuleSet = load_rules(Path(rules_dir))
    result = AuditResult(
        corpus_events=profile.total_events,
        corpus_sampled=profile.sampled_events,
        observed_sources=profile.observed_sources,
        rule_count=len(ruleset.rules),
        unparseable_count=len(ruleset.errors),
    )

    for rule in ruleset.rules:
        result.findings.append(_assess_rule(rule, profile, config))

    for error in ruleset.errors:
        result.findings.append(
            RuleFinding(
                rule_id=error.path.stem,
                title=error.path.name,
                path=str(error.path),
                logsource_key="unknown",
                techniques=frozenset(),
                verdict=Verdict.UNPARSEABLE,
                detail=error.reason,
            )
        )

    # Technique level rollup. A technique counts as covered only if at least one
    # rule mapped to it can actually fire.
    tally: dict[str, list[int]] = {}
    for finding in result.findings:
        for technique in finding.techniques:
            entry = tally.setdefault(technique, [0, 0])
            entry[0] += 1
            if finding.verdict.is_blind:
                entry[1] += 1
    result.techniques = {
        t: TechniqueCoverage(technique=t, rule_count=c[0], blind_rule_count=c[1])
        for t, c in tally.items()
    }

    log.info(
        "audit complete",
        extra={
            "rules": result.rule_count,
            "techniques_mapped": result.mapped_technique_count,
            "techniques_blind": len(result.blind_techniques),
            "blind_technique_pct": round(result.blind_technique_pct, 2),
        },
    )
    return result
