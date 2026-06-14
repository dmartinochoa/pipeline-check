"""Tests for CC-036 (unsafe deserialization of a fetched artifact)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestCC036UnsafeModelDeser:
    def test_metadata(self) -> None:
        f = run_check("""
        jobs:
          train:
            steps:
              - run: make build
        """, "CC-036")
        assert f.check_id == "CC-036"
        assert f.severity == Severity.HIGH

    def test_fails_on_explicit_unsafe_opt_in(self) -> None:
        f = run_check("""
        jobs:
          train:
            steps:
              - run: python -c "torch.load(m, weights_only=False)"
        """, "CC-036")
        assert not f.passed

    def test_fails_on_fetch_plus_unpickle(self) -> None:
        f = run_check("""
        jobs:
          train:
            steps:
              - run: |
                  curl -fsSL -o m.pt https://x/m.pt
                  python -c "import torch; torch.load('m.pt')"
        """, "CC-036")
        assert not f.passed

    def test_passes_on_local_unpickle_without_fetch(self) -> None:
        f = run_check("""
        jobs:
          train:
            steps:
              - run: python -c "import torch; torch.load('local.pt')"
        """, "CC-036")
        assert f.passed
