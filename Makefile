.PHONY: install test lint docs build-lambda clean

install:
	pip install --require-hashes -r requirements-dev.txt
	pip install -e .

test:
	pytest tests/ -v --cov=pipeline_check --cov-report=term-missing

lint:
	ruff check pipeline_check/ tests/ scripts/

docs:
	python scripts/gen_provider_docs.py

build-lambda:
	bash scripts/build_lambda.sh

# Cross-platform clean. ``rm -rf`` doesn't exist on Windows; shutil
# does, so use Python to keep the target portable.
clean:
	python -c "import shutil, glob, os; [shutil.rmtree(p, ignore_errors=True) for p in ['dist','build','.pytest_cache','.ruff_cache','.mypy_cache']]; [shutil.rmtree(p, ignore_errors=True) for p in glob.glob('*.egg-info')]; [os.remove(p) for p in glob.glob('.coverage*') if os.path.isfile(p)]"
