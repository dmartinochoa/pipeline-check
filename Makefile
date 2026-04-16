.PHONY: install test lint docs build-lambda clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=pipeline_check --cov-report=term-missing

lint:
	ruff check pipeline_check/ tests/

docs:
	python scripts/gen_provider_docs.py

build-lambda:
	bash scripts/build_lambda.sh

clean:
	rm -rf dist/ build/ *.egg-info __pycache__ .pytest_cache .coverage
