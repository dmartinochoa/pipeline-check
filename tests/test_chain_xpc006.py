"""XPC-006 cross-provider chain tests.

Chain-specific cases only; the mechanical-contract assertions live
in ``tests/test_chain_xpc_mechanical.py``.
"""
from __future__ import annotations

from pipeline_check.core.chains.rules import (
    xpc006_unreviewed_fork_pr_privilege_escalation as r,
)
from pipeline_check.core.checks.base import Severity

from ._chain_helpers import make_failing


class TestXPC006:
    def test_fires_on_combined_scm002_gha002(self) -> None:
        findings = [
            make_failing("SCM-002", "github:org/repo"),
            make_failing(
                "GHA-002", ".github/workflows/triage.yml",
                severity=Severity.CRITICAL,
            ),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-006"
        # Composite carries CRITICAL — matches GHA-002's severity
        # rather than SCM-002's HIGH (the chain rule asserts the
        # combined risk is at least as severe as the worst leg).
        assert c.severity == Severity.CRITICAL
        assert "github:org/repo" in c.resources
        assert ".github/workflows/triage.yml" in c.resources
        assert "SCM-002" in c.triggering_check_ids
        assert "GHA-002" in c.triggering_check_ids
        # Narrative spells out the single-identity-introduction
        # framing the chain is built around.
        assert "single insider" in c.narrative.lower() or \
               "single identity" in c.narrative.lower() or \
               "compromised maintainer" in c.narrative.lower()

    def test_emits_one_chain_per_pair(self) -> None:
        # Two SCM repos + three offending workflows -> six pairs.
        findings = [
            make_failing("SCM-002", "github:org/repo-a"),
            make_failing("SCM-002", "github:org/repo-b"),
            make_failing("GHA-002", ".github/workflows/triage.yml"),
            make_failing("GHA-002", ".github/workflows/labeler.yml"),
            make_failing("GHA-002", ".github/workflows/comment-bot.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6
