# Add a Splunk REST ingestion path
labels: enhancement

The audit reads a parquet export. That keeps the test suite free of credentials
and keeps a weekly audit off the platform the SOC depends on, which is the right
default and is recorded in ADR-002. It is friction for an ad hoc question: "will
this rule I just wrote actually fire".

## Trigger condition

From the README's Intentionally out of scope section: when a rule set passes 500
rules, or when the audit needs to answer interactively rather than on a schedule.

## What to do

- A `dca.telemetry.sources` interface with the existing parquet reader as one implementation.
- A Splunk implementation issuing a field summary search rather than pulling events, so the tool still never reads field values.
- Credentials from the environment, never logged, with the threat model in SECURITY.md updated.

## Constraint that must not be broken

The audit reads field names and counts and never field values. A Splunk
implementation that pulls raw events to count fields locally would break that
and must not be accepted.
