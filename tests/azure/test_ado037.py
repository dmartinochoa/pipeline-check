"""Tests for ADO-037 (AI model pulled without a pinned revision)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestADO037ModelPinning:
    def test_metadata(self) -> None:
        f = run_check("steps:\n  - script: make\n", "ADO-037")
        assert f.check_id == "ADO-037"
        assert f.severity == Severity.MEDIUM

    def test_fails_on_unpinned_from_pretrained(self) -> None:
        f = run_check("""
        steps:
          - script: python -c "from transformers import AutoModel; AutoModel.from_pretrained('vendor/llm')"
        """, "ADO-037")
        assert not f.passed
        assert "vendor/llm" in f.description

    def test_fails_on_unpinned_cli_download_in_bash(self) -> None:
        f = run_check("""
        steps:
          - bash: |
              huggingface-cli download vendor/llm
        """, "ADO-037")
        assert not f.passed

    def test_passes_on_pinned_revision(self) -> None:
        f = run_check("""
        steps:
          - script: python -c "AutoModel.from_pretrained('vendor/llm', revision='9f0a1b2c3d4e5f60718293a4b5c6d7e8f9012345')"
        """, "ADO-037")
        assert f.passed

    def test_passes_on_cli_revision_flag(self) -> None:
        f = run_check("""
        steps:
          - bash: huggingface-cli download vendor/llm --revision 9f0a1b2c3d4e
        """, "ADO-037")
        assert f.passed

    def test_passes_on_canonical_first_party_name(self) -> None:
        f = run_check("""
        steps:
          - script: python -c "AutoModel.from_pretrained('bert-base-uncased')"
        """, "ADO-037")
        assert f.passed

    def test_passes_without_a_fetch_call(self) -> None:
        f = run_check("""
        steps:
          - script: python train.py --data vendor/llm
        """, "ADO-037")
        assert f.passed
