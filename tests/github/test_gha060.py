"""Per-rule tests for GHA-060 (pip install without `--require-hashes`)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA060PipRequireHashes:
    def test_fails_on_pip_install_requirements_without_require_hashes(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: pip install -r requirements.txt
              - run: python -m pytest
        """
        f = run_check(wf, "GHA-060")
        assert not f.passed
        assert "hash" in f.description.lower() or "require-hashes" in f.description.lower()

    def test_passes_when_require_hashes_used(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: pip install -r requirements.txt --require-hashes
        """
        f = run_check(wf, "GHA-060")
        assert f.passed

    def test_passes_when_uv_sync_used(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: uv sync --frozen
        """
        f = run_check(wf, "GHA-060")
        assert f.passed

    def test_passes_when_poetry_install_used(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: poetry install --no-interaction
        """
        f = run_check(wf, "GHA-060")
        assert f.passed

    def test_passes_when_pipenv_deploy_used(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: pipenv install --deploy
        """
        f = run_check(wf, "GHA-060")
        assert f.passed

    def test_passes_silently_with_no_pip_install(self):
        wf = """
        name: lint
        on: push
        jobs:
          lint:
            runs-on: ubuntu-latest
            steps:
              - run: pre-commit run --all-files
        """
        f = run_check(wf, "GHA-060")
        assert f.passed

    def test_passes_when_only_tooling_bootstrap_installed(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: pip install --upgrade pip
              - run: pip install --upgrade setuptools wheel
              - run: pip install pip-audit
              - run: pip install pipx
        """
        f = run_check(wf, "GHA-060")
        assert f.passed

    def test_fails_when_tooling_install_mixed_with_real_install(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  pip install --upgrade pip
                  pip install -r requirements.txt
        """
        f = run_check(wf, "GHA-060")
        assert not f.passed

    def test_fails_on_python_m_pip_install(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: python -m pip install -r requirements.txt
        """
        f = run_check(wf, "GHA-060")
        assert not f.passed

    def test_does_not_match_pip_show_or_pip_list(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: pip list
              - run: pip show requests
        """
        f = run_check(wf, "GHA-060")
        assert f.passed

    def test_fails_on_cicd_goat_scenario_11_body(self):
        # Body lifted verbatim from
        # cicd-goat/.github/workflows/scenario-11-pip-install-no-hashes.yml.
        # Locks the contract so a regression that lets this exact
        # shape silent-pass would fail the suite. Pairs with the
        # scenarios.yaml expected list in ``greylag-ci/cicd-goat``.
        wf = """
        name: scenario-11-pip-install-no-hashes
        on:
          push:
          pull_request:
        permissions:
          contents: read
        jobs:
          build:
            if: false
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-python@v5
                with:
                  python-version: '3.12'
              - name: Install deps (DANGER - unpinned, no hashes)
                run: pip install -r scenarios/11-pip-install-no-hashes/requirements.txt
              - run: python -c "import requests; print(requests.__version__)"
        """
        f = run_check(wf, "GHA-060")
        assert not f.passed
        assert "Install deps" in f.description or "require-hashes" in f.description.lower()

    def test_require_hashes_in_separate_job_still_passes(self):
        # Verification anywhere in the workflow is sufficient; this
        # matches the GHA-059 contract for npm audit signatures.
        wf = """
        name: ci
        on: push
        jobs:
          install:
            runs-on: ubuntu-latest
            steps:
              - run: pip install -r requirements.txt
          verify:
            runs-on: ubuntu-latest
            steps:
              - run: pip install -r requirements.txt --require-hashes
        """
        f = run_check(wf, "GHA-060")
        assert f.passed
