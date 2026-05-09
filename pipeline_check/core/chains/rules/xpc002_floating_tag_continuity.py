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
composite is therefore higher-leverage than either singleton, the
attacker doesn't need to compromise both layers individually.

This chain currently activates only when scanning Dockerfile + k8s
in the same multi-provider invocation
(``--pipelines dockerfile,kubernetes``); single-provider runs of
either alone won't have both legs in the chain engine's input.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, failing, min_confidence

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


def match(findings: list[Finding]) -> list[Chain]:
    """Match when at least one DF-001 and one K8S-001 fail in the same run.

    Cross-provider chains can't use :func:`group_by_resource` the
    way single-provider chains do — the Dockerfile finding lives on
    a Dockerfile path, the K8s finding lives on a manifest YAML
    path, and they're never the same resource string. We emit one
    composite per ``(dockerfile, manifest)`` pair so a scan with
    multiple offenders in either column produces one chain entry
    per cross-product cell, naming exactly the pair the operator
    needs to look at.

    The chain is loosely-matched on purpose: there's no reliable
    way to assert that the ``FROM`` image and the ``image:`` field
    reference the same upstream registry tag without resolving
    image refs at scan time (which the scanner deliberately
    doesn't do — it stays read-from-disk-only). The composite's
    value is "you have tag mutability on both sides of the
    pipeline; check if the upstream artifact is the same and pin
    accordingly," which is itself a useful triage prompt even when
    the two refs are unrelated.
    """
    df_001 = failing(findings, "DF-001")
    k8s_001 = failing(findings, "K8S-001")
    if not df_001 or not k8s_001:
        return []

    out: list[Chain] = []
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
