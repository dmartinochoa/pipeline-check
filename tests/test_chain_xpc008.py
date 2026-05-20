"""XPC-008 cross-provider chain tests.

Chain-specific cases only; the mechanical-contract assertions live
in ``tests/test_chain_xpc_mechanical.py``.

XPC-008's SCM leg accepts either ``SCM-001`` (no protection rule) or
``SCM-007`` (rule exists but force-pushes allowed). Per-leg
specifics stay here; cross-product / dispatch / confidence
behavior ride on the mechanical contract.
"""
from __future__ import annotations

from pipeline_check.core.chains.rules import (
    xpc008_unreviewed_source_mutable_runtime as r,
)
from pipeline_check.core.checks.base import Severity

from ._chain_helpers import make_failing


class TestXPC008:
    def test_fires_on_scm001_plus_df001(self) -> None:
        findings = [
            make_failing("SCM-001", "github:org/repo"),
            make_failing("DF-001", "Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-008"
        assert c.severity == Severity.HIGH
        assert "github:org/repo" in c.resources
        assert "Dockerfile" in c.resources
        assert "SCM-001" in c.triggering_check_ids
        assert "DF-001" in c.triggering_check_ids
        # Narrative names the no-protection branch.
        assert "no branch protection rule" in c.narrative

    def test_fires_on_scm007_plus_df001(self) -> None:
        """SCM-007 (force-push allowed) is the alternative SCM leg."""
        findings = [
            make_failing("SCM-007", "github:org/repo"),
            make_failing("DF-001", "Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert "SCM-007" in c.triggering_check_ids
        assert "force-pushes" in c.narrative

    def test_fires_when_both_scm_legs_present(self) -> None:
        findings = [
            make_failing("SCM-001", "github:org/repo"),
            make_failing("SCM-007", "github:org/repo"),
            make_failing("DF-001", "Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 2
        triggers = {tuple(sorted(c.triggering_check_ids)) for c in chains}
        assert ("DF-001", "SCM-001") in triggers
        assert ("DF-001", "SCM-007") in triggers

    def test_emits_one_chain_per_pair(self) -> None:
        # Two SCM repos + three Dockerfiles -> six pairs.
        findings = [
            make_failing("SCM-001", "github:org/repo-a"),
            make_failing("SCM-001", "github:org/repo-b"),
            make_failing("DF-001", "api/Dockerfile"),
            make_failing("DF-001", "worker/Dockerfile"),
            make_failing("DF-001", "cron/Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6
