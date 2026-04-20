"""AC-005 — Unsigned Artifact to Production (cross-provider).

A pipeline that builds artifacts without signing/provenance AND
auto-deploys to production without approval lets a build-time
compromise reach production with no detection or rollback gate.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, min_confidence

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
)

# A build-side check id (lack of signing/provenance) → list of
# deploy-side check ids that, if also failing, complete the chain.
# Key insight: signing failures live on workflow files; deploy-gate
# failures live on AWS pipeline ARNs / workflow files / Cloud Build
# configs. We don't require same-resource — the chain is real even
# when build and deploy live in different files.
_BUILD_FAILS = (
    "GHA-006", "GL-006", "BB-006", "ADO-006", "JF-006", "CC-006",
    "GCB-009", "SIGN-001",
)
_DEPLOY_FAILS = (
    "GHA-014", "GL-004", "BB-004", "ADO-004", "JF-005", "CC-009",
    "CP-001", "CP-005",
)


def match(findings: list[Finding]) -> list[Chain]:
    failing_build = [
        f for f in findings
        if (not f.passed) and f.check_id in _BUILD_FAILS
    ]
    failing_deploy = [
        f for f in findings
        if (not f.passed) and f.check_id in _DEPLOY_FAILS
    ]
    if not failing_build or not failing_deploy:
        return []
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
        "  3. Any successful poisoning of the build (compromised "
        "dependency, runner backdoor, malicious action) propagates "
        "to production on the next merge with no signature check or "
        "human gate to catch it."
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
        triggering_check_ids=build_ids + deploy_ids,
        triggering_findings=triggers,
        resources=resources,
        references=list(RULE.references),
        recommendation=RULE.recommendation,
    )]
