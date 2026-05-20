"""XPC-007 cross-provider chain tests.

Chain-specific cases only; the mechanical-contract assertions live
in ``tests/test_chain_xpc_mechanical.py``.
"""
from __future__ import annotations

from pipeline_check.core.chains.rules import (
    xpc007_unpinned_actions_no_remediation as r,
)
from pipeline_check.core.checks.base import Severity

from ._chain_helpers import make_failing


class TestXPC007:
    def test_fires_on_combined_scm005_gha001(self) -> None:
        findings = [
            make_failing("SCM-005", "github:org/repo", severity=Severity.MEDIUM),
            make_failing("GHA-001", ".github/workflows/ci.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-007"
        assert c.severity == Severity.HIGH
        assert "github:org/repo" in c.resources
        assert ".github/workflows/ci.yml" in c.resources
        assert "SCM-005" in c.triggering_check_ids
        assert "GHA-001" in c.triggering_check_ids
        # Narrative cites the canonical real-world incident.
        assert "tj-actions" in c.narrative.lower()

    def test_emits_one_chain_per_pair(self) -> None:
        # Two SCM repos + three offending workflows -> six pairs.
        findings = [
            make_failing("SCM-005", "github:org/repo-a"),
            make_failing("SCM-005", "github:org/repo-b"),
            make_failing("GHA-001", ".github/workflows/ci.yml"),
            make_failing("GHA-001", ".github/workflows/release.yml"),
            make_failing("GHA-001", ".github/workflows/deploy.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6
