# Verdicts

Five outcomes per rule. The ordering is deliberate: the audit reports the most
severe thing that is true, so a rule whose log source is missing entirely is
never reported as merely having a missing field.

| Verdict | Meaning | Counts as blind | What to do |
| --- | --- | --- | --- |
| `no_source` | The rule's log source produced no events in the corpus. | yes | Onboard the log source, or retire the rule. |
| `missing_field` | The source is present, but at least one referenced field never appears. | yes | Rewrite the rule against the field names this source emits, or extend the pipeline. |
| `unparseable` | The rule file could not be parsed. | yes | Fix or delete the rule file. |
| `rare_field` | Every field is present, but one falls below the presence threshold. | no | Confirm the field is populated often enough for the rule to be useful. |
| `keyword_only` | The rule full text searches the raw event and names no field. | no | Rewrite as a field based rule so coverage can be measured. |
| `resolved` | The source is present and every field is present above the threshold. | no | Nothing. |

## Why `missing_field` is the common one

Most public detection content is written against Sysmon field names: `Image`,
`ParentImage`, `TargetImage`, `GrantedAccess`. An estate that audits process
creation through Windows Security EventID 4688 instead populates
`NewProcessName` and `ParentProcessName`. The rule is correct, the telemetry is
present, the technique shows green on the heatmap, and the rule can never fire.

That single mismatch accounts for most of the blind techniques in the bundled
example. It is the reason this tool exists.

## Condition branches

A rule's condition decides which of its selections have to match, and the audit
resolves each alternative separately. This is real detection content, not a
contrived case:

```yaml
detection:
  selection_sysmon:
    Image|endswith: '\powershell.exe'
  selection_4688:
    NewProcessName|endswith: '\powershell.exe'
  condition: selection_sysmon or selection_4688
```

On an estate collecting Windows Security EventID 4688 that rule fires through
`selection_4688`. Resolving the union of every field would report it
`missing_field` because `Image` is absent, which is wrong, and wrong in the
direction that makes the tool look careless to the people who write rules well.

A rule is blind only when every branch its condition offers is blocked. The
report shows the branch count and how many are blocked, so a rule that fires
through one of two paths is visibly different from one that fires through both.

A negated selection is a filter. Its fields do not need to be present for the
rule to fire, so they never make a rule look blind.

An aggregation tail after a pipe, `| count() by host > 5`, is ignored, because it
changes when a rule fires rather than which fields it reads.

When a condition cannot be parsed, the audit falls back to requiring every
selection, which is the old behaviour, and says so on the finding. A parse
failure can therefore only make the audit more pessimistic, never more
permissive. See [ADR-005](adr/adr-005-tolerant-yaml-over-pysigma.md) for why
this parser exists rather than pySigma's.

## Why `rare_field` is not blind

A field present in 0.04% of its source's events is not missing. A rule keyed on
it will fire, occasionally, on the small share of events that carry it. Calling
that blind would be wrong and calling it resolved would be worse, so it is its
own verdict with its own action.

The threshold is configurable through `DCA_RARE_FIELD_THRESHOLD` and defaults to
0.001, meaning 0.1%. Note the interaction with sampling: a field rarer than
roughly 1/N can be missed entirely by an N row sample and will then be reported
as `missing_field`. See [ADR-001](adr/adr-001-sampled-field-presence.md) for why
the error is allowed to point in that direction.

## Why `keyword_only` is separate

A keyword rule searches the raw event text. There is no field to resolve, so
field level coverage does not apply to it. Counting it as resolved would
overstate coverage, counting it as missing would understate it. It gets its own
category and its own action, which is to rewrite it so that its coverage becomes
measurable at all.

## Gating CI on verdicts

`dca gate` exits 2 when the blind technique percentage exceeds a threshold or
when there are more unparseable rules than allowed, which makes the audit a
required check on a detection content repository rather than a report somebody
remembers to read.

```bash
dca gate --rules rules/ --telemetry corpus.parquet \
  --max-blind-pct 40 --max-unparseable 0
```

Pick the starting threshold from the number the audit reports today, then
ratchet it down. A gate set to a number the repository cannot currently meet
gets disabled within a week.
