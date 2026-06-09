"""Tests for ADO-036 (unsafe deserialization of a fetched artifact)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestADO036UnsafeModelDeser:
    def test_metadata(self) -> None:
        f = run_check("steps:\n  - script: make\n", "ADO-036")
        assert f.check_id == "ADO-036"
        assert f.severity == Severity.HIGH

    def test_fails_on_explicit_allow_pickle(self) -> None:
        f = run_check("""
        steps:
          - script: python -c "import numpy; numpy.load('a.npy', allow_pickle=True)"
        """, "ADO-036")
        assert not f.passed

    def test_fails_on_fetch_then_unpickle(self) -> None:
        f = run_check("""
        steps:
          - bash: |
              hf_hub_download(repo_id='acme/m', filename='model.bin')
              python -c "import torch; torch.load('model.bin')"
        """, "ADO-036")
        assert not f.passed

    def test_passes_on_safetensors(self) -> None:
        f = run_check("""
        steps:
          - bash: |
              curl -o m.safetensors https://example.com/m.safetensors
              python -c "from safetensors.torch import load_file; load_file('m.safetensors')"
        """, "ADO-036")
        assert f.passed

    def test_passes_on_bare_local_load_no_fetch(self) -> None:
        f = run_check("""
        steps:
          - script: python -c "import torch; torch.load('local.pt')"
        """, "ADO-036")
        assert f.passed
