"""Per-rule tests for GL-035 (pip install without `--require-hashes`)."""
from __future__ import annotations

from .conftest import run_check


class TestGL035PipRequireHashes:
    def test_fails_on_real_pip_install(self):
        cfg = """
        build:
          stage: build
          image: python:3.12
          script:
            - pip install -r requirements.txt
            - pytest
        """
        f = run_check(cfg, "GL-035")
        assert not f.passed

    def test_passes_when_require_hashes_used(self):
        cfg = """
        build:
          stage: build
          script:
            - pip install -r requirements.txt --require-hashes
        """
        f = run_check(cfg, "GL-035")
        assert f.passed

    def test_passes_when_uv_sync_used(self):
        cfg = """
        build:
          stage: build
          script:
            - uv sync --frozen
        """
        f = run_check(cfg, "GL-035")
        assert f.passed

    def test_passes_when_poetry_install_used(self):
        cfg = """
        build:
          stage: build
          script:
            - poetry install --no-interaction
        """
        f = run_check(cfg, "GL-035")
        assert f.passed

    def test_passes_silently_with_no_pip(self):
        cfg = """
        lint:
          script:
            - pre-commit run --all-files
        """
        f = run_check(cfg, "GL-035")
        assert f.passed

    def test_passes_when_only_tooling_bootstrap(self):
        cfg = """
        build:
          script:
            - pip install --upgrade pip
            - pip install pip-tools
        """
        f = run_check(cfg, "GL-035")
        assert f.passed

    def test_fails_when_tooling_install_mixed_with_real_install(self):
        cfg = """
        build:
          script:
            - pip install --upgrade pip
            - pip install -r requirements.txt
        """
        f = run_check(cfg, "GL-035")
        assert not f.passed

    def test_recognizes_top_level_before_script_install(self):
        cfg = """
        before_script:
          - pip install -r requirements.txt

        build:
          script:
            - pytest
        """
        f = run_check(cfg, "GL-035")
        assert not f.passed

    def test_recognizes_top_level_before_script_uv_sync(self):
        cfg = """
        before_script:
          - uv sync --frozen

        build:
          script:
            - pytest
        """
        f = run_check(cfg, "GL-035")
        assert f.passed
