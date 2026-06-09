"""Tests for ADO-034 (ML model loaded with trust_remote_code)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestADO034TrustRemoteCode:
    def test_metadata(self) -> None:
        f = run_check("steps:\n  - script: make\n", "ADO-034")
        assert f.check_id == "ADO-034"
        assert f.severity == Severity.HIGH

    def test_fails_on_trust_remote_code_true(self) -> None:
        f = run_check("""
        steps:
          - script: python -c "from transformers import AutoModel; AutoModel.from_pretrained('acme/m', trust_remote_code=True)"
        """, "ADO-034")
        assert not f.passed

    def test_fails_in_bash_step(self) -> None:
        f = run_check("""
        steps:
          - bash: |
              text-generation-launcher --model acme/m --trust-remote-code
        """, "ADO-034")
        assert not f.passed

    def test_fails_in_task_inputs_script(self) -> None:
        f = run_check("""
        steps:
          - task: Bash@3
            inputs:
              script: python load.py --trust_remote_code=True
        """, "ADO-034")
        assert not f.passed

    def test_passes_on_clean_pipeline(self) -> None:
        f = run_check("""
        steps:
          - script: python train.py --model bert
        """, "ADO-034")
        assert f.passed

    def test_passes_on_trust_remote_code_false(self) -> None:
        f = run_check("""
        steps:
          - script: python -c "AutoModel.from_pretrained('acme/m', trust_remote_code=False)"
        """, "ADO-034")
        assert f.passed
