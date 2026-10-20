# Contributing

## Getting set up

```bash
git clone https://github.com/__GITHUB_USERNAME__/detection-coverage-audit.git
cd detection-coverage-audit
python -m venv .venv && source .venv/bin/activate
make install
make verify
```

`make verify` runs every check CI runs, in the same order: lint, tests with
coverage, the dependency check and the provenance audit. A verify that is a
subset of CI is a verify that lies, so if it passes locally the build should be
green.

It needs no network, no API keys and no containers. If it does not pass on a
clean checkout, that is a bug worth an issue on its own.

Everything runs through `$(PYTHON)`, which defaults to `python3`. The console
scripts pip installs bind to whichever interpreter installed them, which on a
machine with several Pythons is not necessarily the one on PATH. Override it if
you need to: `make verify PYTHON=python3.12`.

## The rules that matter here

**Verify before you commit, as two separate steps.** Run the tests, read the
output, then commit. Do not chain `pytest && git commit`: if the suite fails for
a reason you have not read yet, the commit lands anyway and the history stops
being trustworthy.

**No unused dependencies.** `tools/check_dependencies.py` fails CI on anything
declared in `pyproject.toml` that nothing imports, with an explicit list for the
genuinely indirect ones. An unused dependency is a claim the code does not
support, and if it also appears in the README tech stack it is a capability the
project advertises and does not have. That happened here with pysigma.

**Every published number is measured.** Numbers in the README are tagged with
`<!--number:path-->` markers and checked against `docs/metrics.json` by
`tools/check_numbers.py` in CI. If a change moves a number, run `make report`
and update the README in the same commit. Do not edit `docs/metrics.json` by
hand.

**Numbers from the bundled corpus are labelled as simulations.** The corpus is
synthetic. Any figure derived from it says so at the point it is published,
including in badges.

**Field values never leave the corpus.** The reports contain field names and
counts. If a change would put a field value into a report, a log line or an
error message, it needs to be discussed in an issue first. See SECURITY.md.

## Commit messages

Conventional Commits: `type(scope): imperative summary` under 72 characters, no
trailing period. Types in use: feat, fix, test, docs, ci, chore, refactor, perf,
build.

Fix commits carry a body with one line of symptom and one line of root cause.
A reader six months later needs to know what broke, not only what changed.

No em dashes or en dashes anywhere, in code, comments, commit messages or docs.

## Adding a log source

Log sources live in `src/dca/telemetry/schemas.yml`. Add the fields the source
actually emits, with a `presence` fraction for anything conditionally populated,
and set `literal_key: true` on any name that is one key containing dots rather
than a path into a nested object. Getting that flag wrong makes the generated
corpus misrepresent the source, which was a real bug in this repository. Source
`share` values must sum to 1.0 and the schema loader enforces it.

Add a test asserting the new source's shapes, in the style of
`tests/test_schemas.py::test_bundled_spec_declares_zeek_dotted_keys_as_literal`.

## Adding a verdict

Verdicts are deliberately few. Before adding one, be able to say what an
engineer would do differently on seeing it, and add that sentence to
`ACTION_BY_VERDICT` in `src/dca/report/render.py`. A verdict nobody acts on
differently is a verdict that should have been a detail field.

## Pull requests

One concern per pull request. CI must be green. New behaviour needs a test; a
bug fix needs a regression test that fails before the fix.
