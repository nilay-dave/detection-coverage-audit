# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Condition aware coverage resolution. A rule is now blind only when every branch its condition offers is blocked, so a rule written to match either Sysmon or EventID 4688 field names is no longer reported blind on an estate that collects one of them. Handles `and`, `or`, `not`, parentheses and the `of` forms; a negated selection is treated as a filter and requires no fields; an aggregation tail after a pipe is ignored. An unparseable condition falls back to requiring every selection, so a parse failure can only over report blindness. This moves the bundled pack's headline number from 66.7 to 63.0 percent by correctly resolving a rule whose missing field was only ever referenced inside a filter.
- Findings now carry `branches_total`, `branches_blocked` and `condition_exact`, all surfaced in the HTML report.

### Removed
- The `pysigma` dependency, which was declared and advertised in the README but never imported. It was measured and found unsuitable: it aborts a whole collection when one rule in it is malformed, and an unparseable rule is a finding this tool has to report rather than crash on. ADR-005 records the measurement and the error.

### Added
- ADR-005 on parsing Sigma rules as YAML rather than with pySigma.
- Two loader tests: one asserting a broken rule does not prevent valid rules in the same directory from loading, one asserting a rule with a non specification `status` value is still readable.
- `tools/check_commit_subject.py` as a commit-msg hook enforcing the 72 character subject limit.
- `tools/set_identity.sh` to bind repository URLs to a GitHub account in one pass.
- `scripts/provenance_check.py`, which audits the repository's own provenance signals: history shape, badge liveness, releases, language mix, description length and house style.

### Fixed
- `dca --version` reported 0.1.0 at the v0.3.0 tag, because the version was declared in both `pyproject.toml` and `__init__.py`. The package now reads it from its own metadata.
- `tools/check_dashes.py` held the forbidden characters as literals, so the one file whose job is to enforce the no-dash rule tripped its own check.
- `tools/set_identity.sh` contained the literal placeholder it searches for, so the first run rewrote its own search pattern.

## [0.3.0] - 2026-10-19

Hardening, measured benchmarks and docs. This is the first release whose
published numbers are checked in CI.

### Added
- Benchmark harness covering 100k, 1M and 10M event corpora, with raw results in `benchmark/results/benchmark.json` and a `--reuse` flag so a large corpus is not regenerated per run.
- `tools/collect_metrics.py` writes every published number to `docs/metrics.json`, and `tools/check_numbers.py` fails CI when a README figure drifts from a measured one. 30 numbers are currently checked.
- MkDocs Material documentation site with a Pages deploy workflow, hosting the ADRs, the pipeline walkthrough, the verdict reference and a freshly generated example report.
- Coverage and headline-number badges fed from a JSON endpoint written to `gh-pages` by CI, so both badges show measured values rather than static claims.
- Community health files: SECURITY.md with the tool's threat model, CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue and PR templates, CODEOWNERS and Dependabot.
- Pre-commit hooks including a dash checker and a telemetry schema validity check.
- ADR-004 recording the bounded batch profiling decision.

### Changed
- Profiling now runs in bounded `rowid` batches, so peak memory is set by the batch size rather than the corpus size.
- Ruff line length set to 120, with `B008` ignored only for the CLI module where call expressions in parameter defaults are Typer's documented interface.
- `Verdict` is now a `StrEnum`.

### Fixed
- Profiling a 10M event corpus raised `OutOfMemoryError` from DuckDB at 4.6GiB, because leaf deduplication ran as one `DISTINCT` over roughly 65M rows.
- `make verify` failed on a fresh clone with `ModuleNotFoundError: No module named 'tests'`, because pytest resolved the tests directory rather than the repo root as the import root.
- DuckDB drew a progress bar on the caller's stdout, which corrupted piped output and made a redirected benchmark run unreadable.
- `tools/collect_metrics.py` recorded a null test count, because it looked for a pytest summary line this version does not print.

### Performance
- Leaf deduplication moved from `count(DISTINCT rid)` to `SELECT DISTINCT` plus `count(*)`, and a `row_number` window replaced with `rowid`: 8.96s against 11.47s profiling a 1M event corpus, output identical.

## [0.2.0] - 2026-10-19

The CLI, the report and the measurements.

### Added
- `dca generate-telemetry`, `dca audit` and `dca gate`. The gate exits 2 above a blind technique percentage or an unparseable rule count, so the audit can be a required check on a detection content repository.
- HTML report with a light and dark theme, leading with the blind technique percentage and grouping findings by the action each one implies.
- Machine readable JSON output, which is the shape CI consumes.
- Structured JSON logging with a per-run id.

### Fixed
- Rule titles rendered as live markup in the HTML report. Jinja's `select_autoescape` decides by final file extension, and the template is named `report.html.j2`, so escaping was never switched on. Rule files come from repositories a team may not own, so this was a real cross-site scripting hole.
- Every log call raised a logging error once anything replaced `sys.stderr`, because `logging.StreamHandler` captures the stream at construction.

## [0.1.0] - 2026-10-19

Core audit.

### Added
- Tolerant Sigma rule loader. Unparseable files become findings rather than exceptions, so one broken file in a shared repository cannot stop the audit.
- Field extraction from detection blocks, stripping Sigma modifiers, with keyword-only rules tracked separately from zero-field rules.
- ATT&CK technique extraction from rule tags, attributing sub-techniques to their parent.
- Telemetry schema specification covering Windows Security 4688, Windows System, Windows registry, AWS CloudTrail, Zeek DNS and Zeek SSL, shaped from published event documentation.
- Reproducible synthetic corpus generator, seeded, emitting only fields the schema declares.
- Field presence profiler measuring per source, per field presence from parquet.
- Audit engine with five verdicts and a technique level rollup that treats a technique as covered when at least one mapped rule can fire.
- Bundled rule pack of 18 Sigma rules across four log source families, including one deliberately unparseable file.

### Fixed
- The profiler could not distinguish a literal key containing a dot, which is how Zeek writes `id.orig_h`, from a nested object, which is how CloudTrail writes `userIdentity.type`. DuckDB's `json_tree` reports the same `fullkey` for both.
- The corpus generator nested every dotted field name, so every Zeek field in every generated corpus had the wrong shape. The two bugs had been cancelling each other out.

### Performance
- Corpus generation moved from `executemany` to chunked DataFrame insertion: 53,938 against 2,403 events per second, output byte identical at the same seed.

[Unreleased]: https://github.com/__GITHUB_USERNAME__/detection-coverage-audit/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/__GITHUB_USERNAME__/detection-coverage-audit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/__GITHUB_USERNAME__/detection-coverage-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/__GITHUB_USERNAME__/detection-coverage-audit/releases/tag/v0.1.0
