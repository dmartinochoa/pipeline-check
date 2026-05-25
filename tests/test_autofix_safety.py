"""Enforcement tests for autofix safety tiers.

Every registered fixer must have an explicit safety declaration. This
test fails the moment a new fixer lands without a label, forcing the
author to decide whether the edit is safe or unsafe.
"""
from __future__ import annotations

from pipeline_check.core import autofix
from pipeline_check.core.autofix import SAFE, UNSAFE
from pipeline_check.core.checks.base import Finding, Severity


def _finding(check_id: str) -> Finding:
    return Finding(
        check_id=check_id, title="x", severity=Severity.MEDIUM,
        resource="wf.yml", description="", recommendation="",
        passed=False,
    )


class TestSafetyLabels:
    def test_every_fixer_has_explicit_safety(self):
        for check_id in autofix.available_fixers():
            safety = autofix.fixer_safety(check_id)
            assert safety in (SAFE, UNSAFE), (
                f"{check_id}: fixer registered without explicit "
                f"safety={{\"safe\"|\"unsafe\"}} declaration"
            )

    def test_safe_and_unsafe_counts_are_nonzero(self):
        safe = [
            cid for cid in autofix.available_fixers()
            if autofix.fixer_safety(cid) == SAFE
        ]
        unsafe = [
            cid for cid in autofix.available_fixers()
            if autofix.fixer_safety(cid) == UNSAFE
        ]
        assert len(safe) > 0, "no safe fixers found"
        assert len(unsafe) > 0, "no unsafe fixers found"

    def test_gha003_is_unsafe(self):
        assert autofix.fixer_safety("GHA-003") == UNSAFE

    def test_gha034_is_unsafe(self):
        assert autofix.fixer_safety("GHA-034") == UNSAFE

    def test_gha004_is_safe(self):
        assert autofix.fixer_safety("GHA-004") == SAFE


class TestTierFiltering:
    def test_safe_tier_runs_safe_fixer(self):
        wf = (
            "name: ci\n\non: push\n\njobs:\n"
            "  build:\n    runs-on: ubuntu-latest\n"
            "    steps: [{run: echo}]\n"
        )
        f = _finding("GHA-004")
        after = autofix.generate_fix(f, wf, tier="safe")
        assert after is not None
        assert "permissions:" in after

    def test_safe_tier_blocks_unsafe_fixer(self):
        wf = (
            "name: ci\non: pull_request_target\njobs:\n"
            "  build:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo ${{ github.event.pull_request.title }}\n"
        )
        f = _finding("GHA-003")
        after = autofix.generate_fix(f, wf, tier="safe")
        assert after is None

    def test_unsafe_tier_runs_both(self):
        wf = (
            "name: ci\n\non: push\n\njobs:\n"
            "  build:\n    runs-on: ubuntu-latest\n"
            "    steps: [{run: echo}]\n"
        )
        f = _finding("GHA-004")
        after = autofix.generate_fix(f, wf, tier="unsafe")
        assert after is not None

    def test_unsafe_only_blocks_safe_fixer(self):
        wf = (
            "name: ci\n\non: push\n\njobs:\n"
            "  build:\n    runs-on: ubuntu-latest\n"
            "    steps: [{run: echo}]\n"
        )
        f = _finding("GHA-004")
        after = autofix.generate_fix(f, wf, tier="unsafe-only")
        assert after is None
