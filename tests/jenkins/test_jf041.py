"""Tests for JF-041 (unsafe deserialization of a fetched artifact)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


def _pipe(cmd: str) -> str:
    return (
        "pipeline { agent any\n stages { stage('load') { steps {\n"
        f" {cmd} }} }} }} }}"
    )


class TestJF041UnsafeModelDeser:
    def test_metadata(self):
        f = run_check(_pipe("sh 'make build'"), "JF-041")
        assert f.check_id == "JF-041"
        assert f.severity == Severity.HIGH

    def test_fails_on_explicit_unsafe_opt_in(self):
        f = run_check(
            _pipe("sh \"python -c 'torch.load(m, weights_only=False)'\""),
            "JF-041",
        )
        assert not f.passed

    def test_fails_on_fetch_plus_unpickle(self):
        f = run_check(
            _pipe(
                "sh 'curl -fsSL -o m.pt https://x/m.pt && "
                "python -c \"import torch; torch.load(1)\"'"
            ),
            "JF-041",
        )
        assert not f.passed

    def test_passes_on_local_unpickle_without_fetch(self):
        f = run_check(
            _pipe("sh \"python -c 'import torch; torch.load(1)'\""),
            "JF-041",
        )
        assert f.passed

    def test_passes_on_weights_only_true(self):
        f = run_check(
            _pipe(
                "sh 'curl -fsSL -o m.pt https://x/m.pt && "
                "python -c \"import torch; torch.load(1, weights_only=True)\"'"
            ),
            "JF-041",
        )
        assert f.passed
