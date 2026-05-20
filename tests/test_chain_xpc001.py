"""XPC-001 cross-provider chain tests.

Chain-specific cases only. The five mechanical assertions every XPC
chain shares (silent-on-single-leg, silent-on-neither, engine
dispatch, confidence inheritance from the weakest leg) live in
``tests/test_chain_xpc_mechanical.py``, parametrized off the contract
declared in ``tests/_chain_helpers.py``.
"""
from __future__ import annotations

from pipeline_check.core.chains.rules import (
    xpc001_deploy_without_provenance as r,
)
from pipeline_check.core.checks.base import Severity

from ._chain_helpers import make_failing


class TestXPC001:
    def test_fires_on_combined_gha_oci_failures(self) -> None:
        findings = [
            make_failing("GHA-006", ".github/workflows/release.yml"),
            make_failing("OCI-002", "image.json"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        chain = chains[0]
        assert chain.chain_id == "XPC-001"
        assert chain.severity == Severity.HIGH
        assert ".github/workflows/release.yml" in chain.resources
        assert "image.json" in chain.resources
        assert "GHA-006" in chain.triggering_check_ids
        assert "OCI-002" in chain.triggering_check_ids

    def test_emits_one_chain_per_combination(self) -> None:
        # Two failing workflows + two failing manifests -> four
        # composite chains (one per cross-product entry).
        findings = [
            make_failing("GHA-006", ".github/workflows/release.yml"),
            make_failing("GHA-006", ".github/workflows/build.yml"),
            make_failing("OCI-002", "image-amd64.json"),
            make_failing("OCI-002", "image-arm64.json"),
        ]
        chains = r.match(findings)
        assert len(chains) == 4
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert pairs == {
            (".github/workflows/build.yml", "image-amd64.json"),
            (".github/workflows/build.yml", "image-arm64.json"),
            (".github/workflows/release.yml", "image-amd64.json"),
            (".github/workflows/release.yml", "image-arm64.json"),
        }
