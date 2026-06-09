"""Tests for BB-037 (unsafe deserialization of a fetched artifact)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestBB037UnsafeModelDeser:
    def test_metadata(self):
        f = run_check(
            "pipelines:\n  default:\n    - step:\n        script: [make]\n",
            "BB-037",
        )
        assert f.check_id == "BB-037"
        assert f.severity == Severity.HIGH

    def test_fails_on_explicit_weights_only_false(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - python -c "import torch; torch.load('m.bin', weights_only=False)"
        """
        f = run_check(cfg, "BB-037")
        assert not f.passed

    def test_fails_on_fetch_then_unpickle(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - curl -o model.bin https://example.com/model.bin
                  - python -c "import torch; torch.load('model.bin')"
        """
        f = run_check(cfg, "BB-037")
        assert not f.passed

    def test_passes_on_safetensors(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - curl -o m.safetensors https://example.com/m.safetensors
                  - python -c "from safetensors.torch import load_file; load_file('m.safetensors')"
        """
        f = run_check(cfg, "BB-037")
        assert f.passed

    def test_passes_on_bare_local_load_no_fetch(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - python -c "import torch; torch.load('local.pt')"
        """
        f = run_check(cfg, "BB-037")
        assert f.passed
