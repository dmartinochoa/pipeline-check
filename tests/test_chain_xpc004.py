"""XPC-004 cross-provider chain tests.

Chain-specific cases only; the mechanical-contract assertions live
in ``tests/test_chain_xpc_mechanical.py``.

XPC-004's SCM leg accepts either ``SCM-001`` (no protection rule) or
``SCM-007`` (rule exists but force-pushes allowed) — both signal
"anyone with write access can land arbitrary code on the default
branch." The tests cover each leg path independently.
"""
from __future__ import annotations

from pipeline_check.core.chains.rules import (
    xpc004_token_leak_unprotected_branch as r,
)
from pipeline_check.core.checks.base import Severity

from ._chain_helpers import make_failing


class TestXPC004:
    def test_fires_on_scm001_plus_gha019(self) -> None:
        findings = [
            make_failing("SCM-001", "github:org/repo"),
            make_failing("GHA-019", ".github/workflows/release.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-004"
        assert c.severity == Severity.CRITICAL
        assert "github:org/repo" in c.resources
        assert ".github/workflows/release.yml" in c.resources
        assert "SCM-001" in c.triggering_check_ids
        assert "GHA-019" in c.triggering_check_ids
        # Narrative reflects the no-protection-rule branch.
        assert "no branch protection rule" in c.narrative

    def test_fires_on_scm007_plus_gha019(self) -> None:
        """SCM-007 (force-push allowed) is the alternative SCM leg —
        same chain, different SCM rule satisfies the governance side."""
        findings = [
            make_failing("SCM-007", "github:org/repo"),
            make_failing("GHA-019", ".github/workflows/release.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert "SCM-007" in c.triggering_check_ids
        assert "force-pushes" in c.narrative

    def test_fires_when_both_scm_legs_present(self) -> None:
        """Both SCM-001 and SCM-007 failing on the same repo plus a
        single GHA-019 should produce two composites (one per SCM
        leg) so the operator sees both governance vectors."""
        findings = [
            make_failing("SCM-001", "github:org/repo"),
            make_failing("SCM-007", "github:org/repo"),
            make_failing("GHA-019", ".github/workflows/release.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 2
        triggers = {tuple(sorted(c.triggering_check_ids)) for c in chains}
        assert ("GHA-019", "SCM-001") in triggers
        assert ("GHA-019", "SCM-007") in triggers

    def test_emits_one_chain_per_pair(self) -> None:
        # Two SCM repos + three offending workflows -> six pairs.
        findings = [
            make_failing("SCM-001", "github:org/repo-a"),
            make_failing("SCM-001", "github:org/repo-b"),
            make_failing("GHA-019", ".github/workflows/build.yml"),
            make_failing("GHA-019", ".github/workflows/release.yml"),
            make_failing("GHA-019", ".github/workflows/deploy.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6
