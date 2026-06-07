"""AC-005. Unsigned Artifact to Production (cross-provider).

A pipeline that builds artifacts without signing/provenance AND
auto-deploys to production without approval lets a build-time
compromise reach production with no detection or rollback gate.

ResourceAnchor phase 1: prefers a confirmed pairing when an
unsigned-build leg and an ungated-deploy leg both reference the
same canonical ``oci_image`` identity. Image-ref extraction is
live on the GHA legs (GHA-006 + GHA-014) via the
``_primitives/oci_refs.py`` helper — it walks
``docker/build-push-action`` ``tags:`` inputs and deploy-shaped
shell commands (``docker push``, ``kubectl set image``, ``helm
upgrade --set image=``, ``gcloud run deploy``, ``az
containerapp``, ``aws ecs update-service``) and canonicalizes
each through the phase 0 ``oci_image()`` helper (strips tag /
digest, normalizes implicit Docker Hub registries).

Each matched image identity composes ONE confirmed chain with
``confirmed_reachable=True``, ``Confidence.HIGH``, and the image
identity as the chain resource. Falls back to scan-level
co-occurrence when no shared image identity matches — most cases
where the build / deploy legs live in different providers
(Cloud Build → AWS CodePipeline, GitLab → ArgoCD, etc.), where
image extraction isn't wired on every leg yet, or where the
build and deploy genuinely reference different images. The
fallback preserves the legacy multi-provider signal the chain
was originally designed for.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_anchor, min_confidence

RULE = ChainRule(
    id="AC-005",
    title="Unsigned Artifact to Production",
    severity=Severity.HIGH,
    summary=(
        "Artifacts are produced without signing or provenance AND the "
        "deployment path to production has no manual approval gate. "
        "A build-time compromise (compromised dependency, malicious "
        "action, runner takeover) reaches prod uninspected and "
        "post-incident attribution is impossible."
    ),
    mitre_attack=(
        "T1195.002",  # Supply Chain Compromise: Software Supply Chain
        "T1554",      # Compromise Host Software Binary
    ),
    kill_chain_phase="supply-chain -> defense-evasion -> impact",
    references=(
        "https://slsa.dev/spec/v1.0/levels",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10-Insufficient-Logging-and-Visibility",
    ),
    recommendation=(
        "Add a signing step (`cosign sign`, `gh attestation`) or SLSA "
        "provenance generation, AND require manual approval before "
        "production deploys (CodePipeline approval action, GHA "
        "environment with required reviewers)."
    ),
    # Provider-agnostic: the chain spans multiple providers in practice.
    triggering_check_ids=(
        "GHA-006",
        "GL-006",
        "BB-006",
        "ADO-006",
        "JF-006",
        "CC-006",
        "GCB-009",
        "SIGN-001",
        "GHA-014",
        "GL-004",
        "BB-004",
        "ADO-004",
        "JF-005",
        "CC-009",
        "CP-001",
        "CP-005",
    ),
)

# A build-side check id (lack of signing/provenance) → list of
# deploy-side check ids that, if also failing, complete the chain.
# Key insight: signing failures live on workflow files; deploy-gate
# failures live on AWS pipeline ARNs / workflow files / Cloud Build
# configs. We don't require same-resource, the chain is real even
# when build and deploy live in different files.
_BUILD_FAILS = (
    "GHA-006", "GL-006", "BB-006", "ADO-006", "JF-006", "CC-006",
    "GCB-009", "SIGN-001",
)
_DEPLOY_FAILS = (
    "GHA-014", "GL-004", "BB-004", "ADO-004", "JF-005", "CC-009",
    "CP-001", "CP-005",
)


def _emit_confirmed(
    image: str,
    build_f: Finding,
    deploy_f: Finding,
) -> Chain:
    triggers = [build_f, deploy_f]
    narrative = (
        f"For image `{image}`:\n"
        f"  1. The build leg ({build_f.check_id}) produces and tags "
        f"`{image}` without a signing / provenance step. Whatever "
        f"the build's inputs (compromised dependency, malicious "
        f"action, runner takeover) the published image carries no "
        f"cryptographic break with the upstream identity.\n"
        f"  2. The deploy leg ({deploy_f.check_id}) ships the same "
        f"image `{image}` to production with no manual approval "
        f"gate. The image flows from build to prod uninspected; a "
        f"poisoned build version has nothing between it and the "
        f"customer.\n"
        "  3. Reachability confirmed: build and deploy reference the "
        "SAME canonical image identity, the produce → consume edge "
        "is direct, not inferred from co-occurrence. Adding signing "
        "AND an approval gate are independent fixes; either breaks "
        "the chain. Best is both, plus signature verification at "
        "deploy time."
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
        triggering_check_ids=[build_f.check_id, deploy_f.check_id],
        triggering_findings=triggers,
        resources=[image],
        references=list(RULE.references),
        recommendation=RULE.recommendation,
        confirmed_reachable=True,
        via_structural=True,
        reachability_note=(
            f"Build leg {build_f.check_id} and deploy leg "
            f"{deploy_f.check_id} share image `{image}`"
        ),
    )


def match(findings: list[Finding]) -> list[Chain]:
    # ResourceAnchor phase 1: confirmed pairing per oci_image
    # identity shared between any build-side leg and any deploy-side
    # leg. group_by_anchor takes one check_id per leg, so we iterate
    # the cross-product of (build_id, deploy_id) and union the
    # matches by image identity. A single image that triggers
    # confirmed paths through multiple build/deploy id pairs only
    # emits one chain per image — the first (build, deploy) pair
    # wins for the narrative.
    out: list[Chain] = []
    matched_findings: set[int] = set()
    confirmed_images: dict[str, tuple[Finding, Finding]] = {}
    for build_id in _BUILD_FAILS:
        for deploy_id in _DEPLOY_FAILS:
            grouped = group_by_anchor(
                findings, [build_id, deploy_id], "oci_image",
            )
            for image, ck_map in grouped.items():
                if image in confirmed_images:
                    continue
                confirmed_images[image] = (
                    ck_map[build_id], ck_map[deploy_id],
                )
    for image, (build_f, deploy_f) in confirmed_images.items():
        matched_findings.add(id(build_f))
        matched_findings.add(id(deploy_f))
        out.append(_emit_confirmed(image, build_f, deploy_f))

    # Co-occurrence fallback: any build-side leg fails AND any
    # deploy-side leg fails, regardless of whether anchors matched.
    # This preserves the legacy multi-provider signal: a GitLab
    # build that doesn't sign + an AWS CodePipeline deploy that
    # doesn't gate are a real chain even without image-level
    # reachability proof. We exclude findings that already
    # contributed to a confirmed chain so the same evidence doesn't
    # double-count.
    failing_build = [
        f for f in findings
        if (not f.passed)
        and f.check_id in _BUILD_FAILS
        and id(f) not in matched_findings
    ]
    failing_deploy = [
        f for f in findings
        if (not f.passed)
        and f.check_id in _DEPLOY_FAILS
        and id(f) not in matched_findings
    ]
    if failing_build and failing_deploy:
        triggers = failing_build + failing_deploy
        build_ids = sorted({f.check_id for f in failing_build})
        deploy_ids = sorted({f.check_id for f in failing_deploy})
        resources = sorted({f.resource for f in triggers if f.resource})
        narrative = (
            "Across this scan:\n"
            f"  1. Artifacts are produced without signing/provenance "
            f"(failing: {', '.join(build_ids)}) on "
            f"{', '.join(sorted({f.resource for f in failing_build}))}.\n"
            f"  2. The deploy path is not gated by manual approval "
            f"(failing: {', '.join(deploy_ids)}) on "
            f"{', '.join(sorted({f.resource for f in failing_deploy}))}.\n"
            "  3. Reachability unconfirmed: no shared image identity "
            "between the unsigned-build and the ungated-deploy legs "
            "(different providers, image-extraction not wired on "
            "this leg, or the legs reference different images). The "
            "chain remains a co-occurrence signal — any successful "
            "poisoning of a build that flows to one of these "
            "ungated deploys still reaches prod uninspected."
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
            triggering_check_ids=build_ids + deploy_ids,
            triggering_findings=triggers,
            resources=resources,
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=False,
            reachability_note="",
        ))
    return out
