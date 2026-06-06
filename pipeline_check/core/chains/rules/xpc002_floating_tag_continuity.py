"""XPC-002. Tag mutability across pipeline + runtime (Dockerfile + K8s).

The second cross-provider chain. Fires when a single multi-provider
scan run carries failures in both:

  * ``DF-001`` — Dockerfile pulls a base image with a floating tag
    (``FROM python:3.12`` instead of ``@sha256:...``);
  * ``K8S-001`` — a Kubernetes Deployment / StatefulSet / DaemonSet
    references a floating-tag image (``image: my-org/app:1`` rather
    than ``@sha256:...``).

Independently each rule says "tag mutability is bad on this side."
Together they say the tag mutability spans the build-time *and*
runtime boundaries: an attacker who pushes a malicious manifest to
the same upstream tag affects both the build artifact (the image
the Dockerfile pulls into ``FROM`` chains) and the runtime workload
(the cluster pulls the new digest on the next image refresh). The
composite is therefore higher-impact than either singleton, the
attacker doesn't need to compromise both layers individually.

This chain currently activates only when scanning Dockerfile + k8s
in the same multi-provider invocation
(``--pipelines dockerfile,kubernetes``); single-provider runs of
either alone won't have both legs in the chain engine's input.

ResourceAnchor phase 1: prefers a confirmed pairing when DF-001 and
K8S-001 both reference the same canonical ``oci_image`` identity.
Both legs now emit ``oci_image`` anchors via the
``_primitives/anchors.oci_image()`` canonicalizer (DF-001 walks each
``FROM`` ref, K8S-001 walks every workload container's ``image:``
field). When an anchor identity matches across the two legs, the
chain emits ONE confirmed chain (``confirmed_reachable=True``,
``Confidence.HIGH``, image identity as the chain resource) — the
"build pulls X, cluster runs X, tag mutation hits both at once"
claim is then direct, not inferred from co-occurrence. Falls back
to the legacy per-pair cross-product co-occurrence signal for
findings that don't share an identity so the original triage
prompt ("here are the (dockerfile, manifest) pairs to investigate")
still surfaces when build and runtime reference different images.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import (
    Chain,
    ChainRule,
    failing,
    group_by_anchor,
    min_confidence,
)

RULE = ChainRule(
    id="XPC-002",
    title="Tag mutability across pipeline + runtime (Dockerfile + K8s)",
    severity=Severity.HIGH,
    summary=(
        "Both the Dockerfile's ``FROM`` line and the Kubernetes "
        "workload manifest reference floating image tags. An "
        "attacker who pushes a malicious blob under a known tag "
        "(stolen registry credentials, compromised upstream CI) "
        "affects the build artifact AND the running workload at "
        "the same time, with no separate fix-once-and-it's-done "
        "place to break the chain."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1525",      # Implant Internal Image
    ),
    kill_chain_phase=(
        "build -> deploy (tag mutation propagates through both)"
    ),
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-3",
        "https://kubernetes.io/docs/concepts/containers/images/"
        "#image-pull-policy",
    ),
    recommendation=(
        "Pin both ends to ``@sha256:<digest>``. In the Dockerfile, "
        "rewrite ``FROM python:3.12`` to ``FROM python:3.12@sha256:"
        "<digest>``. In the Kubernetes manifest, rewrite "
        "``image: my-org/app:1`` to ``image: my-org/app:1@sha256:"
        "<digest>`` (and configure ``imagePullPolicy: IfNotPresent`` "
        "so the kubelet doesn't re-resolve on every pod restart). "
        "Capture the digest with ``crane digest`` or ``docker buildx "
        "imagetools inspect`` and update the digest deliberately in "
        "version control when the upstream version moves."
    ),
    providers=("dockerfile", "kubernetes"),
    triggering_check_ids=("DF-001", "K8S-001"),
)


def _emit_confirmed(
    image: str,
    df_finding: Finding,
    k8s_finding: Finding,
) -> Chain:
    triggers = [df_finding, k8s_finding]
    narrative = (
        f"For image `{image}`:\n"
        f"  1. Dockerfile `{df_finding.resource}` pulls `{image}` "
        f"under a floating tag in its ``FROM`` line (DF-001). The "
        f"build base is whatever the registry currently serves under "
        f"that tag.\n"
        f"  2. Kubernetes manifest `{k8s_finding.resource}` deploys "
        f"a workload whose container image is `{image}`, also pinned "
        f"by a floating tag (K8S-001). The cluster pulls the current "
        f"digest on every fresh pod schedule.\n"
        "  3. Reachability confirmed: build base and runtime workload "
        "reference the SAME canonical image identity. A tag mutation "
        "upstream (compromised registry credentials, namespace "
        "recovery, malicious push under a known tag) lands in both "
        "the next build AND the next pod schedule simultaneously, "
        "with no separate place to break the chain. Pin both ends to "
        "``@sha256:<digest>`` (either fix breaks the chain on its "
        "own; pinning both is defense in depth)."
    )
    return Chain(
        chain_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        confidence=Confidence.HIGH,
        summary=RULE.summary,
        narrative=narrative,
        mitre_attack=list(RULE.mitre_attack),
        kill_chain_phase=RULE.kill_chain_phase,
        triggering_check_ids=["DF-001", "K8S-001"],
        triggering_findings=triggers,
        resources=[image],
        references=list(RULE.references),
        recommendation=RULE.recommendation,
        confirmed_reachable=True,
        reachability_note=(
            f"DF-001 and K8S-001 share image `{image}`"
        ),
    )


def match(findings: list[Finding]) -> list[Chain]:
    """Confirmed-pair per shared ``oci_image`` identity; per-pair
    cross-product fallback for everything else.

    Phase 1 confirmed path: ``group_by_anchor`` intersects DF-001
    and K8S-001 on the canonical ``oci_image`` identity. Each
    matched image emits one confirmed chain at ``Confidence.HIGH``
    with the image identity as the chain resource.

    Fallback: any DF-001 / K8S-001 finding that did NOT contribute
    to a confirmed pair feeds the legacy per-pair fan-out, so a
    scan with multiple offenders in either column still surfaces
    every cross-product cell to investigate. Suppressing the
    fallback for confirmed findings avoids double-counting the
    same evidence as both a confirmed and a co-occurrence chain.
    """
    out: list[Chain] = []
    # Track at (finding, anchor_identity) granularity, not finding
    # alone — a single DF-001 / K8S-001 finding can carry multiple
    # ``oci_image`` anchors (e.g., a Dockerfile with two FROM refs,
    # a manifest deploying two containers). Suppressing the whole
    # finding when only one of its anchors matches would drop the
    # legacy co-occurrence prompt for the other unmatched images
    # on the same file pair (DF={python, alpine} +
    # K8S={python, redis} would lose ``alpine × redis``).
    matched_pairs: set[tuple[int, str]] = set()

    # Phase 1: confirmed pairs per shared image identity.
    grouped = group_by_anchor(
        findings, ["DF-001", "K8S-001"], "oci_image",
    )
    for image, ck_map in grouped.items():
        df_f = ck_map["DF-001"]
        k8s_f = ck_map["K8S-001"]
        matched_pairs.add((id(df_f), image))
        matched_pairs.add((id(k8s_f), image))
        out.append(_emit_confirmed(image, df_f, k8s_f))

    def _all_anchors_matched(f: Finding) -> bool:
        """True only when every ``oci_image`` anchor on *f* lands in
        a confirmed pair. Findings with no ``oci_image`` anchor at
        all return False so the legacy file-pair fallback still
        sees them.
        """
        identities = {
            a.identity for a in f.resource_anchors
            if a.kind == "oci_image"
        }
        if not identities:
            return False
        return all((id(f), ident) in matched_pairs for ident in identities)

    # Fallback: per-pair cross-product over findings that DIDN'T
    # have every anchor consumed by a confirmed pair. Preserves the
    # legacy triage prompt for cases where image identity didn't
    # match (different registries, multi-arch tag aliases, or
    # un-canonicalizable refs) AND for the unmatched images riding
    # on the same finding as a confirmed one.
    df_001 = [
        f for f in failing(findings, "DF-001")
        if not _all_anchors_matched(f)
    ]
    k8s_001 = [
        f for f in failing(findings, "K8S-001")
        if not _all_anchors_matched(f)
    ]
    if not df_001 or not k8s_001:
        return out

    for dockerfile_finding in df_001:
        for manifest_finding in k8s_001:
            triggers = [dockerfile_finding, manifest_finding]
            narrative = (
                f"Cross-provider chain:\n"
                f"  1. Dockerfile `{dockerfile_finding.resource}` "
                f"references a floating-tag base image in its "
                f"``FROM`` line (DF-001). The image the build pulls "
                f"is whatever the registry currently serves under "
                f"that tag.\n"
                f"  2. Kubernetes manifest "
                f"`{manifest_finding.resource}` deploys a "
                f"workload whose container image is also pinned by "
                f"a floating tag (K8S-001). The cluster pulls the "
                f"current digest on every fresh pod schedule.\n"
                f"  3. An attacker who pushes a malicious blob "
                f"under a known tag (compromised upstream CI, "
                f"stolen registry credentials, typosquat the "
                f"registry resolves to) affects BOTH the build "
                f"artifact and the runtime workload at the same "
                f"time. There's no separate compensating control "
                f"to break the chain at."
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
                triggering_check_ids=["DF-001", "K8S-001"],
                triggering_findings=triggers,
                resources=[
                    dockerfile_finding.resource,
                    manifest_finding.resource,
                ],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    return out
