"""Tests for BB-035 (ML model loaded with trust_remote_code)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestBB035TrustRemoteCode:
    def test_metadata(self):
        f = run_check(
            "pipelines:\n  default:\n    - step:\n        script: [make]\n",
            "BB-035",
        )
        assert f.check_id == "BB-035"
        assert f.severity == Severity.HIGH

    def test_fails_on_trust_remote_code_true(self):
        cfg = """
        pipelines:
          default:
            - step:
                name: eval
                script:
                  - python -c "from transformers import AutoModel; AutoModel.from_pretrained('acme/m', trust_remote_code=True)"
        """
        f = run_check(cfg, "BB-035")
        assert not f.passed

    def test_fails_on_cli_trust_remote_code_flag(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - text-generation-launcher --model acme/m --trust-remote-code
        """
        f = run_check(cfg, "BB-035")
        assert not f.passed

    def test_passes_on_clean_pipeline(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - python train.py --model bert
        """
        f = run_check(cfg, "BB-035")
        assert f.passed

    def test_passes_on_trust_remote_code_false(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - python -c "AutoModel.from_pretrained('acme/m', trust_remote_code=False)"
        """
        f = run_check(cfg, "BB-035")
        assert f.passed
