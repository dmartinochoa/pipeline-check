"""Tests for JF-040 (model pulled without a pinned revision)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check

_PIN = "0123456789abcdef0123456789abcdef01234567"


def _pipe(cmd: str) -> str:
    return (
        "pipeline { agent any\n stages { stage('load') { steps {\n"
        f" {cmd} }} }} }} }}"
    )


class TestJF040ModelPinning:
    def test_metadata(self):
        f = run_check(_pipe("sh 'make build'"), "JF-040")
        assert f.check_id == "JF-040"
        assert f.severity == Severity.MEDIUM

    def test_fails_on_unpinned_cli_download(self):
        f = run_check(_pipe("sh 'huggingface-cli download acme/llm'"), "JF-040")
        assert not f.passed

    def test_fails_on_unpinned_from_pretrained(self):
        # Single-quoted model id so SHELL_STEP_RE feeds clean text to the
        # detector (Groovy backslash-escaped double quotes would not).
        f = run_check(
            _pipe("sh \"python -c \\\"AutoModel.from_pretrained('acme/llm')\\\"\""),
            "JF-040",
        )
        assert not f.passed

    def test_passes_when_revision_pinned(self):
        f = run_check(
            _pipe(f"sh 'huggingface-cli download acme/llm --revision {_PIN}'"),
            "JF-040",
        )
        assert f.passed

    def test_passes_on_first_party_hub_name(self):
        f = run_check(
            _pipe("sh \"python -c \\\"AutoModel.from_pretrained('bert-base-uncased')\\\"\""),
            "JF-040",
        )
        assert f.passed
