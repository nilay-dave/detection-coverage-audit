# Run the audit against a real public Sigma rule pack
labels: enhancement,help wanted

Every number this repository publishes comes from the bundled 18 rule pack and a
synthetic corpus. That is labelled honestly everywhere it appears, but a real
number is worth more than an honest simulation.

## What to do

Vendor the SigmaHQ Windows rules at a pinned commit under `corpora/sigmahq/`,
add a make target that audits them against a generated corpus, and publish the
blind technique percentage in the README alongside the bundled figure.

## Why it is not already done

The synthetic corpus can be shaped to match a documented schema exactly, so a
finding is always traceable to a line in `schemas.yml`. A real rule pack
introduces a second variable: rules written for log sources the corpus does not
model at all, which would show as `no_source` in bulk and swamp the interesting
`missing_field` findings. The schema spec probably needs two or three more
sources first.

## Acceptance

- Rule pack vendored at a pinned commit, with its license noted.
- `make audit-sigmahq` runs it.
- The number appears in the README through the `<!--number:-->` mechanism so CI checks it.
- The pack's own unparseable and keyword-only counts are reported, since a real pack will have both.
