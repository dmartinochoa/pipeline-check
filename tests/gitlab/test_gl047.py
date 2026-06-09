"""Tests for GL-047 (unsafe deserialization of a fetched artifact)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestGL047UnsafeModelDeser:
    def test_metadata(self):
        f = run_check("build:\n  script: [make]\n", "GL-047")
        assert f.check_id == "GL-047"
        assert f.severity == Severity.HIGH

    def test_fails_on_weights_only_false(self):
        cfg = """
        load:
          script:
            - python -c "import torch; torch.load('model.pt', weights_only=False)"
        """
        f = run_check(cfg, "GL-047")
        assert not f.passed

    def test_fails_on_numpy_allow_pickle(self):
        cfg = """
        load:
          script:
            - python -c "import numpy; numpy.load('a.npy', allow_pickle=True)"
        """
        f = run_check(cfg, "GL-047")
        assert not f.passed

    def test_fails_on_fetch_plus_pickle_loader(self):
        cfg = """
        load:
          script:
            - hf_hub_download(repo_id='vendor/llm', filename='m.bin')
            - python -c "import torch; torch.load('m.bin')"
        """
        f = run_check(cfg, "GL-047")
        assert not f.passed

    def test_passes_on_weights_only_true(self):
        cfg = """
        load:
          script:
            - curl -O https://example.com/m.pt
            - python -c "import torch; torch.load('m.pt', weights_only=True)"
        """
        f = run_check(cfg, "GL-047")
        assert f.passed

    def test_passes_on_safetensors(self):
        cfg = """
        load:
          script:
            - curl -O https://example.com/m.safetensors
            - python -c "from safetensors.torch import load_file; load_file('m.safetensors')"
        """
        f = run_check(cfg, "GL-047")
        assert f.passed

    def test_passes_on_bare_local_load_without_fetch(self):
        cfg = """
        load:
          script:
            - python -c "import torch; torch.load('local.pt')"
        """
        f = run_check(cfg, "GL-047")
        assert f.passed
