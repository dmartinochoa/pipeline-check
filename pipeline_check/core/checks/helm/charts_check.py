"""Helm chart-metadata orchestrator.

Pairs with :class:`KubernetesManifestChecks`: the K8s orchestrator
runs every ``K8S-*`` rule against rendered manifests; this one runs
every ``HELM-*`` rule against the charts' parsed ``Chart.yaml`` /
``Chart.lock`` content. Both share the same :class:`HelmContext`, so
the helm provider can register both classes and let each pass
iterate the slice of the context it cares about.

Each ``HELM-*`` rule lives in its own module under ``rules/`` and
exports a ``RULE`` (metadata) plus a ``check(ctx)`` callable that
returns a :class:`Finding`. Discovery uses the same
:func:`discover_rules` helper every other provider relies on, so
the doc generator and the rule-test-coverage meta-test see HELM-*
the same way they see K8S-*.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import discover_rules
from .base import HelmChartBaseCheck, HelmContext


class HelmChartChecks(HelmChartBaseCheck):
    """Run every ``HELM-*`` rule against the charts in *ctx*."""

    def __init__(
        self, ctx: HelmContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.helm.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule, check_fn in self._rules:
            finding = check_fn(self.ctx)
            finding.cwe = list(rule.cwe)
            findings.append(finding)
        return findings


__all__ = ["HelmChartChecks"]
