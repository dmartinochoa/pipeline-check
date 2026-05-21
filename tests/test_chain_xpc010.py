"""XPC-010 cross-provider chain tests.

Chain-specific cases only; the mechanical-contract assertions
(silent-when-only-one-leg, engine dispatch, weakest-finding
confidence) live in ``tests/test_chain_xpc_mechanical.py``.
"""
from __future__ import annotations

from pipeline_check.core.chains.rules import (
    xpc010_npm_cooldown_dockerfile_lifecycle as r,
)
from pipeline_check.core.checks.base import Severity

from ._chain_helpers import make_failing


class TestXPC010:
    def test_fires_on_npm008_plus_df024(self) -> None:
        findings = [
            make_failing("NPM-008", "package.json"),
            make_failing("DF-024", "Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-010"
        assert c.severity == Severity.HIGH
        assert "package.json" in c.resources
        assert "Dockerfile" in c.resources
        assert "NPM-008" in c.triggering_check_ids
        assert "DF-024" in c.triggering_check_ids
        # Narrative names both halves of the consumer-side topology.
        assert "cooldown window" in c.narrative
        assert "lifecycle scripts" in c.narrative

    def test_recommendation_names_both_fixes(self) -> None:
        """Both halves of the fix should appear so the operator can
        pick either or both."""
        findings = [
            make_failing("NPM-008", "package.json"),
            make_failing("DF-024", "Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        rec = chains[0].recommendation
        assert "--ignore-scripts" in rec
        assert "cooldown window" in rec

    def test_emits_one_chain_per_pair(self) -> None:
        """Two manifests + three Dockerfiles -> six pairs."""
        findings = [
            make_failing("NPM-008", "frontend/package.json"),
            make_failing("NPM-008", "service/package.json"),
            make_failing("DF-024", "api/Dockerfile"),
            make_failing("DF-024", "worker/Dockerfile"),
            make_failing("DF-024", "cron/Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6

    def test_passing_legs_do_not_trigger(self) -> None:
        """Only ``passed=False`` findings count toward the chain."""
        from ._chain_helpers import make_passing
        findings = [
            make_passing("NPM-008", "package.json"),
            make_failing("DF-024", "Dockerfile"),
        ]
        assert r.match(findings) == []
        findings = [
            make_failing("NPM-008", "package.json"),
            make_passing("DF-024", "Dockerfile"),
        ]
        assert r.match(findings) == []

    def test_rule_metadata(self) -> None:
        """ChainRule fields surface in --list-chains and SARIF."""
        assert r.RULE.id == "XPC-010"
        assert r.RULE.severity == Severity.HIGH
        assert r.RULE.providers == ("npm", "dockerfile")
        assert r.RULE.triggering_check_ids == ("NPM-008", "DF-024")
        # Shai-Hulud reference is part of why this composite escalates.
        assert any("shai-hulud" in ref.lower() for ref in r.RULE.references)
        # MITRE techniques span supply chain + valid accounts + event-
        # triggered execution (the postinstall is the trigger).
        assert "T1195.002" in r.RULE.mitre_attack
        assert "T1546" in r.RULE.mitre_attack
