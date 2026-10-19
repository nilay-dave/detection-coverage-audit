# Forensics audit: detection-coverage-audit at v0.3.0

Four personas, each auditing independently, then an integrated verdict. Graded
PASS, WEAK or FAIL. Every FAIL found during this audit was fixed with its own
commit before delivery, and the fix commits are named below.

## Persona 1: The Principal Engineer

| # | Question | Grade | Justification |
| --- | --- | --- | --- |
| 1 | Clone, run, verify | PASS | Tested literally, twice, in a clean directory from the README text alone. Failed the first time with `ModuleNotFoundError: No module named 'tests'`, fixed in `fix(test): put the repo root on pythonpath so a fresh clone verifies`, then re-tested: 100 tests pass in 8.4s with no network, no credentials and no containers. |
| 2 | Architecture and design decisions | PASS | Four packages with a real boundary each: `rules` reads detection content, `telemetry` measures what the corpus contains, `audit` joins them, `report` renders. The join is the only place the two halves meet, which is why adding an SPL parser touches one function. Five ADRs, each with rejected options. |
| 3 | Abstraction and configurability | PASS | Every tunable is on `Config`, sourced from the environment with validation that rejects out of range values. No module reads a literal path, threshold or field name. `BATCH_ROWS` is deliberately a module constant, not config, and the ADR says why. |
| 4 | Error handling and edge cases | PASS | Nine documented failure modes with detection, behaviour and recovery for each. Missing corpus, empty corpus, malformed schema and unparseable rule each have a distinct, tested path. The loader is tolerant by construction, which is a design decision with an ADR rather than an accident. |
| 5 | Testing | PASS | 100 tests, 99.2 percent branch coverage measured by pytest-cov, including regression tests for all nine bugs found during the build. The batch boundary test sweeps batch sizes 1, 2, 7, 50, 100, 101 and 1000 over a 101 event corpus. |

## Persona 2: The UX Director and Product Thinker

| # | Question | Grade | Justification |
| --- | --- | --- | --- |
| 1 | First 30 seconds | PASS | Opens with the problem and a number, not with a technology. The bolded one-liner states what is found and the measured figure; the three bullets give pain, mechanism and result. |
| 2 | The So What of results | PASS | The blind technique percentage is tied to a consequence in plain words: "Every one of those rules parses, deploys, maps to a technique, turns the heatmap green, and can never fire. Nobody finds out until an incident review asks why nothing alerted." |
| 3 | Visual storytelling | PASS after a fix | Was WEAK. The performance chart plotted runtime against corpus size, which shows linear scaling that nobody disputes, while the surrounding prose claimed flat throughput. Replaced with a throughput bar chart in `docs(readme): chart throughput rather than runtime under load`. The architecture diagram labels the three boundaries where failures are handled; the HTML report leads with the headline number and themes for light and dark. |
| 4 | Actionability and handoff | PASS | Every finding in the report carries an action, and the mapping is a named table in code rather than prose. Future Work names the first metric to watch after deploying and says why the aggregate version of it would mislead. |

## Persona 3: The Hiring Manager

| # | Question | Grade | Justification |
| --- | --- | --- | --- |
| 1 | Tutorial smell test | PASS | The problem is specific, current, and not in any tutorial: the gap between a coverage heatmap and the field names a log source actually populates. The Sysmon against EventID 4688 mismatch is a real failure mode in real estates. |
| 2 | Stolen Valor check | PASS after a fix | Was a FAIL. `pysigma` was declared in `pyproject.toml` and listed in the README tech stack table, and no module imported it: an advertised capability the code did not have. Removed in `fix(deps): drop pysigma, which was advertised but never imported`, after measuring what it would have done, with ADR-005 recording the measurement. The tech stack table now distinguishes what DuckDB provides, `json_tree` recursion, from what this project does with it, path reconstruction and shape detection. |
| 3 | Hardest problem solved | PASS | Two bugs that had been cancelling each other out since the first commit: a profiler that could not distinguish a literal dotted key from a nested path, and a generator that nested every dotted name. The writeup states plainly that a test would not have caught it, because the test would have shared the code's assumption. Both fix commits are linked. |
| 4 | One thing I will remember | PASS | That the tool found a bug in its own test data by being made more precise, and that the author said so in the README instead of quietly fixing it. |

## Persona 4: The Sceptic (provenance)

Automated by `scripts/provenance_check.py`. Final run: **25 pass, 2 weak, 0 fail
across 27 checks.**

Three FAILs were found and fixed during this audit:

1. `tools/check_dashes.py` held the forbidden characters as literals, so the one file whose job is to enforce the no-dash rule tripped its own check. Fixed in `fix(tools): build the dash table from code points not literals`.
2. `scripts/provenance_check.py` repeated the same mistake with a second copy of the table. Fixed by deleting the copy and delegating, in `fix(scripts): delegate the dash check instead of duplicating its table`.
3. The package description was 121 characters, one over the profile grid limit. Fixed in `chore: trim the package description under the 120 character grid limit`.

The two remaining WEAKs, both accepted with a reason:

- **8 commit subjects exceed 72 characters.** Left alone rather than rewritten. Rewriting history to tidy prose invalidates every clone and commit reference for no functional gain. `tools/check_commit_subject.py` now runs as a commit-msg hook so the count cannot grow.
- **8 files still carry the identity placeholder.** Expected: the repository was built before the GitHub account was known. `tools/set_identity.sh` binds every URL in one pass and has been tested twice in a scratch clone, including that it is idempotent and that it no longer rewrites its own search pattern.

## Integrated verdict

**Overall portfolio score: 9 out of 10.**

The repository holds up to all four reads. History is 52 commits of real work
with no padding and no date manipulation, three annotated tags with a changelog
that covers each one, badges that read endpoints CI writes rather than static
claims, and 30 published numbers verified against measured values by a CI job.
Nine bugs were found during the build, each with a regression test, and the two
most interesting ones are written up rather than hidden.

It is a 9 and not a 10 because it has not been pushed yet: the Actions tab is
not green because no run has happened, the releases are local tags rather than
GitHub Releases, and the package is publish-ready rather than published. Those
are the three things a sceptic checks that no amount of local work can satisfy.

### Critical failures (do not ship)

None outstanding. All four FAILs found during this audit were fixed with their
own commits, named above, and the affected checks re-run.

### Impact multipliers

The three changes that would take this from a 9 to a 10, in order:

1. **Push and publish.** Green Actions tab, three GitHub Releases cut from the existing annotated tags, the docs site live on Pages so the badge endpoints resolve, and the package on PyPI through trusted publishing. This is the whole gap between 9 and 10 and none of it is more work than an afternoon.
2. **Run it against one real rule pack.** Vendoring the public SigmaHQ Windows rules at a pinned commit and publishing the blind technique percentage against a real corpus would replace the single most questionable thing in the repository, which is that every number is a simulation. The simulation is honestly labelled, but a real number is worth more than an honest simulation.
3. **Ship field drift detection.** Field presence per source is already computed every run and thrown away. Storing it would let the tool answer "which field did we silently stop collecting", which is the same class of failure arriving over time, and it is perhaps 200 lines on top of what exists.

### Elevator pitch

A coverage heatmap tells you a rule exists for a technique; it cannot tell you
whether the field that rule keys on is in the telemetry you actually collect, and
the gap between those two is where real intrusions go unnoticed. This tool joins
Sigma rules to the field names measured in a telemetry export and reports which
ATT&CK techniques are green on the heatmap and blind in production, with a CI
gate so coverage regressions fail a pull request. On the bundled example,
<!--number:audit.blind_technique_pct-->63<!--/number--> percent of mapped
techniques turn out to have no rule that could fire, mostly because public
detection content is written for Sysmon field names and the estate collects
Windows Security EventID 4688.

Note on the figure: this audit was run at v0.3.0, when the number was 66.7
percent. Condition aware resolution, merged after the audit, corrected one rule
whose only missing field sat inside a filter clause, and the figure is now the
value shown above. The pitch carries the tagged current number rather than the
figure as it stood on the day.
