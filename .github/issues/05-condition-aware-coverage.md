# Report which selections a rule's condition actually requires
labels: enhancement

A rule's condition decides which of its selections have to match. Today the
audit treats every field in every selection as required, so a rule whose
condition is `selection_a or selection_b` is reported as blind when only
`selection_a` has a missing field, even though `selection_b` alone would fire it.

## Example

```yaml
detection:
  selection_sysmon:
    Image|endswith: '\powershell.exe'
  selection_4688:
    NewProcessName|endswith: '\powershell.exe'
  condition: selection_sysmon or selection_4688
```

On an EventID 4688 estate this rule fires correctly through
`selection_4688`, and the audit currently calls it `missing_field` because
`Image` is absent. That is a false positive, and defensively written rules like
this one are exactly what a mature detection repository contains.

## What to do

Parse the condition expression far enough to know which selections are
alternatives and which are required, then resolve fields per selection group. A
rule is blind only when every satisfiable branch has a missing field.

## Note

This is the single largest accuracy improvement available to the tool, and it is
the finding most likely to be argued with by anyone who writes rules well.
