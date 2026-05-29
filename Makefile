.PHONY: install test fast-test lint fmt types check docs docs-all new-rule build-lambda clean

install:
	pip install --require-hashes -r requirements-dev.txt
	pip install -e .

test:
	pytest tests/ -v --cov=pipeline_check --cov-report=term-missing

lint:
	ruff check pipeline_check/ tests/ scripts/

docs:
	python scripts/gen_provider_docs.py

# Regenerate every derived doc tree (providers, standards, attack chains).
docs-all:
	python scripts/gen_provider_docs.py
	python scripts/gen_standards_docs.py
	python scripts/gen_attack_chains_doc.py

# Scaffold a new rule module + test stub:
#   make new-rule PROVIDER=github SLUG=self_hosted_runner
# Pass --severity / --title by calling scripts/new_rule.py directly.
new-rule:
	python scripts/new_rule.py $(PROVIDER) $(SLUG) --apply

# One-command pre-PR gate: lint, doc-freshness, mypy, tests.
check:
	python scripts/preflight.py

# Auto-format the way the pre-commit hook does.
fmt:
	ruff format pipeline_check/ tests/ scripts/

# Strict mypy, same invocation as CI.
types:
	python -m mypy pipeline_check/

# Fast inner-loop test run: stop on first failure, no coverage.
fast-test:
	pytest tests/ -x -q

build-lambda:
	bash scripts/build_lambda.sh

# Cross-platform clean. ``rm -rf`` doesn't exist on Windows; shutil
# does, so use Python to keep the target portable.
clean:
	python -c "import shutil, glob, os; [shutil.rmtree(p, ignore_errors=True) for p in ['dist','build','.pytest_cache','.ruff_cache','.mypy_cache']]; [shutil.rmtree(p, ignore_errors=True) for p in glob.glob('*.egg-info')]; [os.remove(p) for p in glob.glob('.coverage*') if os.path.isfile(p)]"
