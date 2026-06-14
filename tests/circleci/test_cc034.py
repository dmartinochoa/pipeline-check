"""Tests for CC-034 (model loaded with trust_remote_code)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestCC034ModelTrustRemoteCode:
    def test_metadata(self) -> None:
        f = run_check("""
        jobs:
          train:
            steps:
              - run: make build
        """, "CC-034")
        assert f.check_id == "CC-034"
        assert f.severity == Severity.HIGH

    def test_fails_on_trust_remote_code_true(self) -> None:
        f = run_check("""
        jobs:
          train:
            steps:
              - run: python -c "AutoModel.from_pretrained('x/y', trust_remote_code=True)"
        """, "CC-034")
        assert not f.passed

    def test_fails_on_cli_flag(self) -> None:
        f = run_check("""
        jobs:
          train:
            steps:
              - run: huggingface-cli download x/y --trust-remote-code
        """, "CC-034")
        assert not f.passed

    def test_passes_without_trust_remote_code(self) -> None:
        f = run_check("""
        jobs:
          train:
            steps:
              - run: python -c "AutoModel.from_pretrained('x/y')"
        """, "CC-034")
        assert f.passed

    def test_passes_on_trust_remote_code_false(self) -> None:
        f = run_check("""
        jobs:
          train:
            steps:
              - run: python -c "AutoModel.from_pretrained('x/y', trust_remote_code=False)"
        """, "CC-034")
        assert f.passed
