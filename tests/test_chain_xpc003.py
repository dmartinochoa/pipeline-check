"""XPC-003 cross-provider chain tests.

Chain-specific cases only; the mechanical-contract assertions live
in ``tests/test_chain_xpc_mechanical.py``.
"""
from __future__ import annotations

from pipeline_check.core.chains.rules import (
    xpc003_unverified_helm_release as r,
)
from pipeline_check.core.checks.base import Severity

from ._chain_helpers import make_failing


class TestXPC003:
    def test_fires_on_combined_helm_oci_failures(self) -> None:
        findings = [
            make_failing("HELM-002", "charts/api/Chart.lock"),
            make_failing("OCI-002", "image.json"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-003"
        assert c.severity == Severity.HIGH
        assert "charts/api/Chart.lock" in c.resources
        assert "image.json" in c.resources
        assert "HELM-002" in c.triggering_check_ids
        assert "OCI-002" in c.triggering_check_ids

    def test_emits_one_chain_per_pair(self) -> None:
        findings = [
            make_failing("HELM-002", "charts/api/Chart.lock"),
            make_failing("HELM-002", "charts/worker/Chart.lock"),
            make_failing("OCI-002", "img-amd64.json"),
            make_failing("OCI-002", "img-arm64.json"),
        ]
        chains = r.match(findings)
        assert len(chains) == 4
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 4
