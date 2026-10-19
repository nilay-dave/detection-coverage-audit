# Security Policy

## Supported versions

The latest minor release receives security fixes. This project is pre 1.0, so
older minors are not patched.

| Version | Supported |
| --- | --- |
| 0.3.x | yes |
| < 0.3 | no |

## Reporting a vulnerability

Open a private security advisory through the repository's Security tab rather
than a public issue. Expect an acknowledgement within three working days.

## Threat model for this tool

This is worth stating plainly, because the tool runs inside a security team's
own environment and handles data that is sensitive by definition.

**The telemetry corpus is the sensitive asset.** A parquet export of production
telemetry contains usernames, hostnames, internal addresses, command lines and
process paths. The tool reads it and never copies it: the HTML and JSON reports
contain field names and counts, never field values. That is a deliberate
constraint, not an accident of implementation, and it is the reason the audit
measures presence rather than sampling values.

**Rule files are untrusted input.** A detection content repository may be
shared across teams or vendors. Rule titles, descriptions and log source names
flow into an HTML report that somebody opens in a browser, so the report
template escapes everything. This was a real finding during the build: the
template is named `report.html.j2`, and Jinja's `select_autoescape` decides by
final file extension, so escaping was silently off until a test caught a rule
titled `<script>alert(1)</script>` rendering as live markup. The fix sets
`autoescape=True` unconditionally and there is a regression test for it.

**Malformed rule files must not stop the audit.** A rule file that fails to
parse is reported as a finding rather than raised as an exception, so a single
broken file in somebody else's repository cannot be used to make the audit
skip the rest of the rule set.

## What this tool never does

- It never writes to the SIEM, the rule repository, or any log source.
- It never transmits anything off the host. There are no network calls in the
  audit path at all, which is why the test suite needs no API keys and no
  network.
- It never logs field values. The structured log records field names, counts and
  verdicts.

## Secrets

The tool needs no credentials, because it reads an exported parquet file rather
than querying a SIEM. If the Splunk ingestion path recorded in the README's
Intentionally out of scope section is ever built, credentials belong in the
environment locally and in a secret manager in production, and the audit path
must continue to avoid logging anything it reads.

## Dependency hygiene

Dependabot is configured for pip and for GitHub Actions. CI runs on every pull
request and on pushes to `main`.
