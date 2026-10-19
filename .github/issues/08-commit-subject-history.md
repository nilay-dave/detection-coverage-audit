# Eight commit subjects exceed 72 characters
labels: chore,wontfix

The provenance audit reports 8 subjects in early history over the 72 character
limit.

## Decision: not fixing

Rewriting history to tidy prose invalidates every existing clone and every commit
reference, including the two fix commits linked from the README's war story, for
no functional gain. The limit is now enforced going forward by
`tools/check_commit_subject.py` as a commit-msg hook, so the count cannot grow.

Recorded as an issue rather than left silent because the audit reports it on
every run, and a reader deserves to find the reason rather than assume nobody
noticed.
