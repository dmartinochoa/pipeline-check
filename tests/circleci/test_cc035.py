"""Tests for CC-035 (model pulled without a pinned revision)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check

_PIN = "0123456789abcdef0123456789abcdef01234567"


class TestCC035ModelPinning:
    def test_metadata(self) -> None:
        f = run_check("""
        jobs:
          train:
            steps:
              - run: make build
        """, "CC-035")
        assert f.check_id == "CC-035"
        assert f.severity == Severity.MEDIUM

    def test_fails_on_unpinned_cli_download(self) -> None:
        f = run_check("""
        jobs:
          train:
            steps:
              - run: huggingface-cli download acme/llm
        """, "CC-035")
        assert not f.passed

    def test_passes_when_revision_pinned(self) -> None:
        f = run_check(f"""
        jobs:
          train:
            steps:
              - run: huggingface-cli download acme/llm --revision {_PIN}
        """, "CC-035")
        assert f.passed

    def test_passes_on_first_party_hub_name(self) -> None:
        f = run_check("""
        jobs:
          train:
            steps:
              - run: python -c "AutoModel.from_pretrained('bert-base-uncased')"
        """, "CC-035")
        assert f.passed
