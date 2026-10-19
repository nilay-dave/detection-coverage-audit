"""Extract MITRE ATT&CK technique identifiers from Sigma rule tags.

Sigma encodes ATT&CK references as lowercase tags: `attack.t1059.001` for a
sub-technique, `attack.t1059` for its parent, `attack.execution` for a tactic.
Only technique tags are returned. A sub-technique is also attributed to its
parent technique, because a coverage claim made at technique level is the claim
a heatmap displays.
"""

from __future__ import annotations

import re

from dca.rules.loader import LoadedRule

TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)


def extract_techniques(rule: LoadedRule) -> frozenset[str]:
    """Return technique ids such as {"T1059", "T1059.001"} for one rule."""
    tags = rule.raw.get("tags") or []
    if not isinstance(tags, list):
        return frozenset()

    found: set[str] = set()
    for tag in tags:
        match = TECHNIQUE_TAG.match(str(tag).strip())
        if not match:
            continue
        parent = match.group(1).upper()
        found.add(parent)
        if match.group(2):
            found.add(f"{parent}.{match.group(2)}")
    return frozenset(found)
