"""Tests for BB-038 (AI model pulled without a pinned revision)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestBB038ModelPinning:
    def test_metadata(self):
        f = run_check(
            "pipelines:\n  default:\n    - step:\n        script: [make]\n",
            "BB-038",
        )
        assert f.check_id == "BB-038"
        assert f.severity == Severity.MEDIUM

    def test_fails_on_unpinned_from_pretrained(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - python -c "from transformers import AutoModel; AutoModel.from_pretrained('vendor/llm')"
        """
        f = run_check(cfg, "BB-038")
        assert not f.passed
        assert "vendor/llm" in f.description

    def test_fails_on_unpinned_cli_download(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - huggingface-cli download vendor/llm
        """
        f = run_check(cfg, "BB-038")
        assert not f.passed

    def test_passes_on_pinned_revision(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - python -c "AutoModel.from_pretrained('vendor/llm', revision='9f0a1b2c3d4e5f60718293a4b5c6d7e8f9012345')"
        """
        f = run_check(cfg, "BB-038")
        assert f.passed

    def test_passes_on_cli_revision_flag(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - huggingface-cli download vendor/llm --revision 9f0a1b2c3d4e
        """
        f = run_check(cfg, "BB-038")
        assert f.passed

    def test_passes_on_canonical_first_party_name(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - python -c "AutoModel.from_pretrained('bert-base-uncased')"
        """
        f = run_check(cfg, "BB-038")
        assert f.passed

    def test_passes_without_a_fetch_call(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - python train.py --data vendor/llm
        """
        f = run_check(cfg, "BB-038")
        assert f.passed
