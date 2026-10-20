# PYTHON is the interpreter everything runs through. The console scripts pip
# installs (pytest, dca) bind to whichever interpreter installed them, which is
# not necessarily the one on PATH: on a machine with several Pythons a bare
# `pytest` can resolve to one that cannot import this project's dependencies.
# Override with: make verify PYTHON=python3.12
PYTHON ?= python3

.PHONY: install verify test lint demo report bench clean

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check src tests tools benchmark scripts

test:
	$(PYTHON) -m pytest --cov=dca --cov-report=term-missing --cov-report=xml

# Runs every check CI runs, in the same order, so a green local verify means a
# green build. A verify that is a subset of CI is a verify that lies.
verify: lint test
	$(PYTHON) tools/check_dependencies.py
	$(PYTHON) scripts/provenance_check.py

demo:
	$(PYTHON) -m dca.cli generate-telemetry --events 100000 --out data/generated/telemetry.parquet --seed 7
	$(PYTHON) -m dca.cli audit --rules rules/ --telemetry data/generated/telemetry.parquet --out docs/report.html

report:
	$(PYTHON) tools/collect_metrics.py

bench:
	$(PYTHON) benchmark/run_benchmark.py

clean:
	rm -rf .pytest_cache .ruff_cache htmlcov coverage.xml .coverage data/generated
