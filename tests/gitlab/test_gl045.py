"""Tests for GL-045 (ML model loaded with trust_remote_code)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestGL045TrustRemoteCode:
    def test_metadata(self):
        f = run_check("build:\n  script: [make]\n", "GL-045")
        assert f.check_id == "GL-045"
        assert f.severity == Severity.HIGH

    def test_fails_on_trust_remote_code_true(self):
        cfg = """
        eval:
          script:
            - python -c "from transformers import AutoModel; AutoModel.from_pretrained('acme/m', trust_remote_code=True)"
        """
        f = run_check(cfg, "GL-045")
        assert not f.passed

    def test_fails_on_cli_trust_remote_code_flag(self):
        cfg = """
        serve:
          before_script:
            - text-generation-launcher --model acme/m --trust-remote-code
        """
        f = run_check(cfg, "GL-045")
        assert not f.passed

    def test_passes_on_clean_training_run(self):
        cfg = """
        train:
          script:
            - python train.py --model bert
        """
        f = run_check(cfg, "GL-045")
        assert f.passed

    def test_passes_on_trust_remote_code_false(self):
        cfg = """
        eval:
          script:
            - python -c "AutoModel.from_pretrained('acme/m', trust_remote_code=False)"
        """
        f = run_check(cfg, "GL-045")
        assert f.passed
