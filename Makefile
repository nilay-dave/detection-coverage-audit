.PHONY: install verify demo report bench clean

install:
	pip install -e ".[dev]"

verify:
	ruff check src tests
	pytest --cov=dca --cov-report=term-missing --cov-report=xml

demo:
	dca generate-telemetry --events 100000 --out data/generated/telemetry.parquet --seed 7
	dca audit --rules rules/ --telemetry data/generated/telemetry.parquet --out docs/report.html

report:
	python tools/collect_metrics.py

bench:
	python benchmark/run_benchmark.py

clean:
	rm -rf .pytest_cache .ruff_cache htmlcov coverage.xml .coverage data/generated
