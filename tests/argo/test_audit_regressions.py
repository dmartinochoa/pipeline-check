"""Regression tests from the rule audit (Argo batch 3 — example fixes)."""
from __future__ import annotations

from pipeline_check.core.checks.argo.rules import argo001_image_pinning as argo001

from .conftest import argo_ctx


class TestARGO001ImagePinning:
    def test_exploit_example_strong_check(self):
        # Safe fragment previously used ``@sha256:abc123...``, which is not a
        # valid 64-char lowercase-hex digest, so the check fired instead of
        # passing. Replaced with the full 64-char digest so the Safe fragment
        # actually passes.
        vuln, safe = argo001.RULE.exploit_example.split("\n\n", 1)
        assert argo001.check(argo_ctx(vuln)).passed is False
        assert argo001.check(argo_ctx(safe)).passed is True
