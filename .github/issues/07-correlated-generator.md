# Generate semantically coherent events
labels: enhancement

The corpus generator draws each field value independently, so an event can carry
an impossible combination such as `eventSource: iam.amazonaws.com` with
`eventName: DescribeInstances`.

This does not affect any published result and the generator docstring says so:
the audit joins on field presence and never reads a field value. It would matter
the moment any feature reads values.

## What to do

Add per source value constraints to `schemas.yml`, so a field can declare that
its value set depends on another field's value, and have the generator respect
them.

## Do not do this first

Issue 05 (condition aware coverage) and issue 02 (field drift) both deliver more
than this does. This one is bookkeeping against a future feature, and it is
recorded here so the limitation is not rediscovered as a bug.
