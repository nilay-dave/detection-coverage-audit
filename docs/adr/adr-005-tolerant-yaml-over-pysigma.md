# ADR-005: Parse Sigma rules as YAML rather than with pySigma

Status: accepted
Date: 2026-10-19

## Context

pySigma is the reference implementation of the Sigma rule format. It is well
maintained, it is what the Sigma project itself uses, and reaching for it is the
obvious default. This repository depended on it for several commits before
anyone checked whether it was actually suitable, which is its own small lesson.

The audit has one requirement that turns out to conflict with how pySigma
works. A rule file that cannot be parsed is a coverage finding, not an error. A
detection content repository in the real world always contains a few files that
are broken, half written, or committed as placeholders before their logic
exists. An audit that aborts on the first one is an audit nobody runs twice, and
worse, a broken rule file is itself a gap in coverage that the report should be
telling someone about.

## What was measured

pySigma 2.0.1, parsing three inputs:

| Input | Result |
| --- | --- |
| A valid rule | Parsed, one rule |
| A rule with no `detection` block | `SigmaDetectionError: Sigma rule must have a detection definitions` |
| Malformed YAML | `ParserError` from the underlying YAML parser |

The decisive case was a multi document collection holding one valid rule and
one rule with no detection block:

```
SigmaDetectionError: Sigma rule must have a detection definitions
```

One broken rule aborts the entire collection. The valid rule alongside it is
never returned. On a pack of 500 rules, a single placeholder file would mean the
audit reports nothing at all, and the operator would have no indication which
file caused it beyond the exception.

## Options considered

1. **pySigma, abort on error.** Rejected on the measurement above. It inverts
   the requirement: the tool would be least able to report on exactly the
   repositories that most need auditing.
2. **pySigma, one `SigmaCollection` per file, catching exceptions per file.**
   Workable, and genuinely tempting. Rejected because it still cannot report
   per rule findings inside a multi document file, and because it makes pySigma's
   full validation strictness the definition of "parseable", which is stricter
   than this audit needs. A rule with an unusual `status` value or a tag pySigma
   does not recognise is still a rule whose field references can be read.
3. **pySigma for the valid subset, own parser for the rest.** Rejected for v1
   as two parsers for one format, which is a maintenance burden and a source of
   disagreement about what a rule means.
4. **Parse YAML directly and read the detection block.** Chosen.

## Decision

Load rules with PyYAML, tolerate failure per document, and report unparseable
files as `UNPARSEABLE` findings. Take field names from the detection block's
mapping keys, stripping Sigma modifiers after the first pipe.

## Consequences

The loader is tolerant by construction: a YAML error, an absent detection block
and a non mapping document each become a finding with a reason, and the audit
continues. One test asserts this directly on a directory holding both a valid
rule and a broken one.

The cost is real and worth stating plainly. This is not a Sigma implementation.
It does not build an abstract syntax tree, resolve field mapping pipelines,
apply backend conversion, or validate that a rule is well formed by the
specification. It reads field references. For a coverage question that is
sufficient, and for anything about rule semantics it is not.

Field extraction is one function, `dca.rules.fields.extract_fields`. If the
audit ever needs real Sigma semantics, that function is the seam where pySigma
comes back, applied to the valid subset of a pack, with the tolerant loader
still in front of it to keep broken files reportable.

The dependency was removed rather than left declared and unused. An unused
dependency in `pyproject.toml` is a claim the code does not support, and this
one had already reached the README's tech stack table before it was caught.
