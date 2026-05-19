"""Per-rule tests for BB-031 (pip install without `--require-hashes`)."""
from __future__ import annotations

from .conftest import run_check


class TestBB031PipRequireHashes:
    def test_fails_on_real_pip_install(self):
        cfg = """
        pipelines:
          default:
            - step:
                image: python:3.12
                script:
                  - pip install -r requirements.txt
                  - pytest
        """
        f = run_check(cfg, "BB-031")
        assert not f.passed

    def test_passes_when_require_hashes_used(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - pip install -r requirements.txt --require-hashes
        """
        f = run_check(cfg, "BB-031")
        assert f.passed

    def test_passes_when_uv_sync_used(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - uv sync --frozen
        """
        f = run_check(cfg, "BB-031")
        assert f.passed

    def test_passes_when_poetry_install_used(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - poetry install --no-interaction
        """
        f = run_check(cfg, "BB-031")
        assert f.passed

    def test_passes_silently_with_no_pip_install(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - pre-commit run --all-files
        """
        f = run_check(cfg, "BB-031")
        assert f.passed

    def test_passes_when_only_tooling_bootstrap(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - pip install --upgrade pip
                  - pip install pipx
        """
        f = run_check(cfg, "BB-031")
        assert f.passed

    def test_fails_when_tooling_mixed_with_real_install(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - pip install --upgrade pip
                  - pip install -r requirements.txt
        """
        f = run_check(cfg, "BB-031")
        assert not f.passed
