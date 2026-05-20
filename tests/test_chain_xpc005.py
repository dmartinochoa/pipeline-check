"""XPC-005 cross-provider chain tests.

Chain-specific cases only; the mechanical-contract assertions live
in ``tests/test_chain_xpc_mechanical.py``.
"""
from __future__ import annotations

from pipeline_check.core.chains.rules import (
    xpc005_unsigned_source_to_unsigned_artifact as r,
)
from pipeline_check.core.checks.base import Severity

from ._chain_helpers import make_failing


class TestXPC005:
    def test_fires_on_combined_scm006_gha006(self) -> None:
        findings = [
            make_failing("SCM-006", "github:org/repo", severity=Severity.MEDIUM),
            make_failing(
                "GHA-006", ".github/workflows/release.yml",
                severity=Severity.MEDIUM,
            ),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-005"
        assert c.severity == Severity.HIGH
        assert "github:org/repo" in c.resources
        assert ".github/workflows/release.yml" in c.resources
        assert "SCM-006" in c.triggering_check_ids
        assert "GHA-006" in c.triggering_check_ids
        # Narrative spells out the end-to-end provenance gap.
        assert "chain of custody" in c.narrative.lower()
        assert "slsa" in c.narrative.lower()

    def test_emits_one_chain_per_pair(self) -> None:
        # Two SCM repos + three offending workflows -> six pairs.
        findings = [
            make_failing("SCM-006", "github:org/repo-a", severity=Severity.MEDIUM),
            make_failing("SCM-006", "github:org/repo-b", severity=Severity.MEDIUM),
            make_failing(
                "GHA-006", ".github/workflows/build.yml",
                severity=Severity.MEDIUM,
            ),
            make_failing(
                "GHA-006", ".github/workflows/release.yml",
                severity=Severity.MEDIUM,
            ),
            make_failing(
                "GHA-006", ".github/workflows/deploy.yml",
                severity=Severity.MEDIUM,
            ),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6
