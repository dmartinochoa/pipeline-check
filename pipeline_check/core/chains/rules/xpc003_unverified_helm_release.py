"""XPC-003. Unverified Helm release flow (Helm chart + OCI image).

The third cross-provider chain. Fires when a single multi-provider
scan run carries failures in both:

  * ``HELM-002`` — the chart's ``Chart.lock`` doesn't pin per-
    dependency digests; the chart's transitive dependency graph
    can change under a fixed version pin;
  * ``OCI-002`` — the image manifest the chart will deploy lacks
    a build attestation manifest; there's no signed record of how
    the image was built or what's in it.

Independently each rule says "one supply-chain provenance gap on
this side." Together they say the gap spans BOTH the chart layer
(what gets templated into Kubernetes manifests) and the image
layer (what those manifests actually pull at runtime). A
downstream consumer running ``helm install`` has no signed chain
of custody from chart contents to image digest, so an attacker
who compromises either layer (a poisoned chart dependency that
flips the rendered image ref, a registry tag silently moved to a
malicious blob) lands content into the cluster with neither
producer nor verifier able to detect it.

The chain currently activates only when scanning Helm + OCI in
the same multi-provider invocation
(``--pipelines helm,oci``); single-provider runs of either alone
won't have both legs in the chain engine's input.

Reachability-model carve-out: this chain does not migrate to the
``job_anchors`` intersection model. The HELM finding lives on a
``Chart.lock``, the OCI finding lives on an image-manifest JSON,
the two halves never share a CI job and the resource strings never
collide. Per-scan co-occurrence is the reachability claim, the
consumer's verification surface is unsigned on both the chart side
and the image side when the same scan saw both gaps.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, failing, min_confidence

RULE = ChainRule(
    id="XPC-003",
    title="Unverified Helm release flow (chart + image)",
    severity=Severity.HIGH,
    summary=(
        "The Helm chart's ``Chart.lock`` doesn't pin per-dependency "
        "digests AND the image the chart deploys lacks a build "
        "attestation manifest. Neither the chart contents nor the "
        "image bytes are independently verifiable, so a downstream "
        "consumer running ``helm install`` has no signed chain of "
        "custody between chart authoring and image runtime."
    ),
    mitre_attack=(
        "T1195.001",  # Compromise Software Dependencies and Tools
        "T1525",      # Implant Internal Image
    ),
    kill_chain_phase=(
        "package -> distribution -> deploy "
        "(no provenance link at any of the three boundaries)"
    ),
    references=(
        "https://helm.sh/docs/topics/chart_repository/#provenance-and-integrity",
        "https://slsa.dev/spec/v1.0/levels#build-l2",
    ),
    recommendation=(
        "Pin both ends of the release flow. In the Helm chart, "
        "regenerate ``Chart.lock`` after every dependency update so "
        "every entry carries a digest, and gate consumers behind "
        "``helm install --verify`` to enforce the lock at install "
        "time. In the image build, pass "
        "``--attest=type=provenance,mode=max`` to "
        "``docker buildx build`` so the manifest carries a "
        "BuildKit attestation manifest. Verify post-deploy with "
        "``cosign verify-attestation`` against the workflow's "
        "OIDC identity. Both legs together close the producer-"
        "to-verifier loop the chart-image pipeline currently has "
        "open at every step."
    ),
    providers=("helm", "oci"),
    triggering_check_ids=("HELM-002", "OCI-002"),
)


def match(findings: list[Finding]) -> list[Chain]:
    """Match when at least one HELM-002 and one OCI-002 fail in the same run.

    One composite chain per ``(chart, manifest)`` pair so a scan
    with multiple offenders in either column produces one chain
    entry per cross-product cell. The chain doesn't try to assert
    that the chart references *this specific* image (no
    cross-resource ref resolution at scan time, the scanner stays
    read-from-disk-only). The composite's value is the triage
    prompt: "you have provenance gaps on both ends of the flow,
    audit whether the chart's images are attested and whether
    the lock file actually pins those exact digests."
    """
    helm_002 = failing(findings, "HELM-002")
    oci_002 = failing(findings, "OCI-002")
    if not helm_002 or not oci_002:
        return []

    out: list[Chain] = []
    for chart_finding in helm_002:
        for image_finding in oci_002:
            triggers = [chart_finding, image_finding]
            narrative = (
                f"Cross-provider chain:\n"
                f"  1. Helm chart `{chart_finding.resource}` ships a "
                f"``Chart.lock`` whose dependency entries don't carry "
                f"per-dependency digests (HELM-002). Two consumers "
                f"running ``helm dep update`` against the same "
                f"version constraints can pull different bytes; the "
                f"lock file can't tell them apart.\n"
                f"  2. Image manifest `{image_finding.resource}` "
                f"ships without a BuildKit attestation manifest "
                f"(OCI-002). The image the chart eventually pulls "
                f"at runtime carries no signed record of its "
                f"build pipeline or contents.\n"
                f"  3. A downstream ``helm install`` lands content "
                f"into the cluster from a chart whose contents can "
                f"change AND from an image whose bytes can change, "
                f"with no signed chain of custody between author "
                f"and operator. Compromise at either layer "
                f"(poisoned chart dependency, registry tag "
                f"mutation) is undetectable from the verifier's "
                f"perspective."
            )
            out.append(Chain(
                chain_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                confidence=min_confidence(triggers),
                summary=RULE.summary,
                narrative=narrative,
                mitre_attack=list(RULE.mitre_attack),
                kill_chain_phase=RULE.kill_chain_phase,
                triggering_check_ids=["HELM-002", "OCI-002"],
                triggering_findings=triggers,
                resources=[
                    chart_finding.resource,
                    image_finding.resource,
                ],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    return out
