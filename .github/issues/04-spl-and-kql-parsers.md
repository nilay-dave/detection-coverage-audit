# Parse Splunk SPL and Sentinel KQL rule sets
labels: enhancement,help wanted,good first issue

The audit only reads Sigma. Plenty of estates are Splunk first or Sentinel
first, and their detection content never passes through Sigma.

## What to do

Field extraction is one function, `dca.rules.fields.extract_fields`, which takes
a loaded rule and returns the set of field names it references. Add a parser
behind the same interface:

- SPL: field references appear in `search` terms, `where` clauses, `stats by` and `eval` assignments.
- KQL: `where` predicates, `project`, `summarize by` and `extend`.

A partial parser that handles the common 80 percent and reports the rest as
unparseable is more useful than no parser, and the loader is already tolerant by
design, so that fits the existing model.

## Why this is a good first issue

The interface is small, the existing Sigma implementation is a worked example,
and `tests/test_rule_fields.py` shows exactly what a test for it looks like.
