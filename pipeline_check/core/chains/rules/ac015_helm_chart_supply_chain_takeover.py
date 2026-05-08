"""AC-015 — Helm chart-supply-chain takeover via legacy + unlocked + plaintext.

A chart that combines all three of HELM-001 (legacy ``apiVersion: v1``),
HELM-002 (missing ``Chart.lock`` digests), and HELM-003 (non-HTTPS
dependency repository) has every layer of supply-chain defense
removed at once:

- **Schema lock-out (HELM-001).** A v1 chart predates the in-tree
  ``Chart.lock`` mechanism. Dependencies live in a sibling
  ``requirements.yaml`` whose own lock format (``requirements.lock``)
  is rarely committed on v1 charts in the wild. The chart simply
  has no place to record what dep version was last verified.

- **No digest verification (HELM-002).** Even with a v2 chart, an
  absent or digest-less ``Chart.lock`` lets ``helm dependency build``
  accept whatever the registry returns, with no integrity check.

- **Plaintext fetch (HELM-003).** A ``http://``, ``git://``, or
  ``ftp://`` dependency repository is fetched in clear over the
  network. An attacker on the path to the CI runner — a coffee-shop
  Wi-Fi for a developer running ``helm dependency build`` locally,
  or a compromised proxy in the CI fabric — can substitute the
  tarball before Helm sees it.

Any one of these is a HIGH or MEDIUM finding on its own. The
combination is the recipe for a *silent* compromise: the attacker
swaps the dependency, the chart renders cleanly, the rendered
manifests pass every K8S-* posture rule (because they're the same
shape as the legitimate ones, just running attacker-supplied code),
and the next install propagates the backdoor to every cluster the
chart deploys to.

The chain mirrors AC-009 ("Supply Chain Repo Poisoning" for GitHub
Actions) and AC-011 ("Kubernetes Cluster Takeover via hostPath +
cluster-admin") in shape: each leg is independently bad; the chain
captures the combination's removed-every-defense character.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, has_failing, min_confidence

RULE = ChainRule(
    id="AC-015",
    title="Helm chart-supply-chain takeover via legacy + unlocked + plaintext",
    severity=Severity.CRITICAL,
    summary=(
        "A Helm chart simultaneously declares the legacy v1 schema "
        "(HELM-001), ships dependencies without ``Chart.lock`` digest "
        "verification (HELM-002), and lists at least one dependency "
        "on a non-HTTPS repository (HELM-003). An attacker on the path "
        "to ``helm dependency build`` substitutes the dependency "
        "tarball; nothing in the chart's metadata can detect or "
        "reject the swap, so the substituted code runs in every "
        "cluster the chart deploys to."
    ),
    mitre_attack=(
        "T1195.002",  # Supply Chain Compromise: Compromise Software Supply Chain
        "T1557",      # Adversary-in-the-Middle
        "T1078.004",  # Valid Accounts: Cloud Accounts
    ),
    kill_chain_phase="initial-access -> execution -> persistence",
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
        "https://helm.sh/docs/topics/charts/#chart-dependencies",
        "https://helm.sh/docs/helm/helm_dependency_build/",
    ),
    recommendation=(
        "Bump every chart to ``apiVersion: v2`` so the in-tree "
        "``Chart.lock`` mechanism is available. Re-run ``helm "
        "dependency update`` to populate per-dependency ``sha256:`` "
        "digests in the lock and commit it alongside ``Chart.yaml``. "
        "Switch each ``dependencies[].repository`` to ``https://``, "
        "``oci://``, or a ``file://`` sibling — Helm 3.8+ pulls "
        "OCI-hosted charts over HTTPS by default and is the "
        "recommended distribution shape. Removing any *one* of these "
        "three legs breaks this chain (the lock catches a swap on "
        "the next update; HTTPS catches it before the tarball lands; "
        "v2 makes the lock possible in the first place)."
    ),
    providers=("helm",),
)


def match(findings: list[Finding]) -> list[Chain]:
    if not has_failing(findings, "HELM-001"):
        return []
    if not has_failing(findings, "HELM-002"):
        return []
    if not has_failing(findings, "HELM-003"):
        return []
    triggers = [
        f for f in findings
        if (not f.passed) and f.check_id in {"HELM-001", "HELM-002", "HELM-003"}
    ]
    resources = sorted({f.resource for f in triggers})
    narrative = (
        "In this Helm chart set:\n"
        "  1. At least one chart still declares ``apiVersion: v1`` "
        "(HELM-001). The v1 schema predates ``Chart.lock`` — there is "
        "no in-tree, committed record of which dependency tarballs "
        "the maintainer last verified, only a sibling "
        "``requirements.yaml`` whose lock format is rarely shipped.\n"
        "  2. A v2 chart in the same set ships ``dependencies:`` "
        "without a complete ``Chart.lock`` carrying ``sha256:`` "
        "digests (HELM-002). ``helm dependency build`` accepts "
        "whatever the registry returns, with no integrity check, on "
        "every fresh checkout of the chart repo.\n"
        "  3. At least one ``dependencies[].repository`` URL is on "
        "a plaintext scheme — ``http://``, ``git://``, ``ftp://``, "
        "or similar (HELM-003). The dep tarball travels in clear "
        "over the wire on every fetch.\n"
        "  4. An attacker on the network path to a CI runner, a "
        "developer laptop, or any proxy between Helm and the chart "
        "registry can substitute the dependency tarball during "
        "``helm dependency build``. Because (1) and (2) leave the "
        "chart with nothing to compare against, the substitute is "
        "rendered, packaged, and ``helm install``-ed across every "
        "downstream cluster as if it were the genuine dependency. "
        "The rendered K8s manifests look identical to the legitimate "
        "render — the attacker chose the substitute, after all — "
        "so K8S-* posture rules score the chart clean."
    )
    return [Chain(
        chain_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        confidence=min_confidence(triggers),
        summary=RULE.summary,
        narrative=narrative,
        mitre_attack=list(RULE.mitre_attack),
        kill_chain_phase=RULE.kill_chain_phase,
        triggering_check_ids=["HELM-001", "HELM-002", "HELM-003"],
        triggering_findings=triggers,
        resources=resources,
        references=list(RULE.references),
        recommendation=RULE.recommendation,
    )]
