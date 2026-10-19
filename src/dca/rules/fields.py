"""Extract the telemetry field names a Sigma rule depends on.

A Sigma detection block is a mapping of named selections to search criteria.
Each key in a selection is a field name, optionally carrying modifiers after a
pipe (`CommandLine|contains`). The field name is everything before the first
pipe. Keys named `condition` and selections that are bare lists of keywords
carry no field reference and are skipped.

Keyword-only rules are a real category: they full-text search the raw event.
They are reported separately rather than counted as zero-field rules, because
"this rule does not name a field" and "this rule names a field that is missing"
are different findings with different fixes.
"""

from __future__ import annotations

from dataclasses import dataclass

from dca.rules.loader import LoadedRule


@dataclass(frozen=True)
class RuleFields:
    rule_id: str
    fields: frozenset[str]
    keyword_only: bool


def _walk(node: object, found: set[str]) -> bool:
    """Collect field names from a detection node. Returns True if a keyword search was seen."""
    keyword_seen = False
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "condition":
                continue
            field_name = str(key).split("|", 1)[0].strip()
            if field_name:
                found.add(field_name)
            keyword_seen |= _walk(value, found)
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, (dict, list)):
                keyword_seen |= _walk(item, found)
            else:
                # A bare scalar inside a selection list is a full-text keyword.
                keyword_seen = True
    return keyword_seen


def extract_fields(rule: LoadedRule) -> RuleFields:
    """Return the set of field names referenced by a rule's detection block."""
    detection = rule.raw.get("detection")
    found: set[str] = set()
    keyword_seen = False

    if isinstance(detection, dict):
        for name, selection in detection.items():
            if name == "condition":
                continue
            if isinstance(selection, list) and all(not isinstance(i, (dict, list)) for i in selection):
                # A selection that is a flat list of scalars is a keyword search.
                keyword_seen = True
                continue
            keyword_seen |= _walk(selection, found)

    return RuleFields(rule_id=rule.rule_id, fields=frozenset(found), keyword_only=not found and keyword_seen)
