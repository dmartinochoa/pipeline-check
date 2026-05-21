"""XPC-001. Deploy without verifiable provenance (GHA + OCI).

The first cross-provider chain. Fires when a single scan run carries
findings from BOTH the GitHub Actions provider and the OCI image-
manifest provider, and:

  * a workflow runs without emitting SLSA provenance attestation
    (``GHA-006``), AND
  * the published image manifest lacks an attestation manifest
    (``OCI-002``).

Independently each finding is a "Build hygiene" gap. Together they
break the verifier-side contract: a downstream consumer pulling the
image has no signed evidence the workflow produced it, AND the
workflow has no record of having stamped one. Either signal alone
is fixable in isolation; the composite means the producer-verifier
loop is unclosed and the image is consumed on trust.

This chain currently requires a multi-provider scan run (the user
scans GHA + OCI in the same invocation, or correlates two JSON
reports through the existing chain engine). The single-provider
runs that ``Scanner`` does today won't trigger XPC-001 because
findings from a different provider aren't in the result set. The
multi-provider scan mode is roadmapped under v0.6.0 vision.

Reachability-model carve-out: this chain does not migrate to the
``job_anchors`` intersection model. The GHA finding lives on a
workflow file path, the OCI finding lives on an image-manifest
JSON path, and they're never the same resource string nor share a
CI-job identity. The two halves are reachable to each other
through the real-world build-then-publish handoff, not through one
shared CI job. Per-scan co-occurrence is the reachability claim,
the producer-verifier loop is unclosed when the same scan saw a
provenance-skipping workflow AND an attestation-less image.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, failing, min_confidence

RULE = ChainRule(
    id="XPC-001",
    title="Deploy without verifiable provenance (workflow + image)",
    severity=Severity.HIGH,
    summary=(
        "The CI workflow doesn't emit SLSA provenance and the "
        "image it deploys ships without a build-attestation "
        "manifest. The verifier-side contract is broken on both "
        "ends, so a downstream consumer pulling the image has no "
        "way to prove it came from this workflow's build."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1525",      # Implant Internal Image
    ),
    kill_chain_phase=(
        "build -> distribution (no provenance link between them)"
    ),
    references=(
        "https://slsa.dev/spec/v1.0/levels#build-l2",
        "https://docs.docker.com/build/attestations/slsa-provenance/",
    ),
    recommendation=(
        "Close the verifier loop on both ends. In the workflow, "
        "add a provenance-emitting step (``actions/attest-build-"
        "provenance`` or the SLSA generic-generator). In the "
        "image build, pass ``--attest=type=provenance,mode=max`` "
        "to ``docker buildx build`` so the manifest carries a "
        "BuildKit attestation manifest. Verify post-deploy with "
        "``cosign verify-attestation`` against the workflow's "
        "OIDC identity."
    ),
    providers=("github", "oci"),
    triggering_check_ids=("GHA-006", "OCI-002"),
)


def match(findings: list[Finding]) -> list[Chain]:
    """Match when at least one GHA-006 and one OCI-002 fail in the same run.

    Cross-provider chains can't use :func:`group_by_resource` the
    way single-provider chains do — the GHA finding lives on a
    workflow file path, the OCI finding lives on a JSON manifest
    path, and they're never the same resource string. Instead, we
    emit one composite chain instance per ``(workflow, manifest)``
    pair, so a scan with two failing workflows and three failing
    manifests produces six XPC-001 chain entries (one per
    combination). That keeps the chain readable when the operator
    triages it, each entry names exactly which workflow + image
    pair lacks the closure.
    """
    gha_006 = failing(findings, "GHA-006")
    oci_002 = failing(findings, "OCI-002")
    if not gha_006 or not oci_002:
        return []

    out: list[Chain] = []
    for wf_finding in gha_006:
        for img_finding in oci_002:
            triggers = [wf_finding, img_finding]
            narrative = (
                f"Cross-provider chain:\n"
                f"  1. Workflow `{wf_finding.resource}` builds and "
                f"deploys without emitting SLSA provenance "
                f"(GHA-006). No signed record of WHO built the "
                f"image.\n"
                f"  2. Image manifest `{img_finding.resource}` "
                f"ships without a BuildKit attestation manifest "
                f"(OCI-002). No signed record of WHAT was built.\n"
                f"  3. A downstream consumer pulling this image has "
                f"no chain of custody back to the workflow that "
                f"produced it. Either the workflow was bypassed, "
                f"or the build pipeline doesn't enforce SLSA "
                f"Build-L2+ — both indistinguishable from the "
                f"verifier's perspective."
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
                triggering_check_ids=["GHA-006", "OCI-002"],
                triggering_findings=triggers,
                resources=[wf_finding.resource, img_finding.resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    return out
