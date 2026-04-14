.PHONY: install test lint build-lambda clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=pipelineguard --cov-report=term-missing

lint:
	ruff check pipelineguard/ tests/

build-lambda:
	bash scripts/build_lambda.sh

clean:
	rm -rf dist/ build/ *.egg-info __pycache__ .pytest_cache .coverage
