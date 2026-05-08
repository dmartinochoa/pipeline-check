"""ARGO-009 — Argo workflow should sign artifacts it produces."""
from __future__ import annotations

from ...base import Finding, Severity, has_signing, produces_artifacts
from ...rule import Rule
from ..base import ArgoContext

RULE = Rule(
    id="ARGO-009",
    title="Artifacts not signed (no cosign/sigstore step)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a cosign step to the Workflow. The most common shape "
        "is a final ``sign`` template that runs ``cosign sign --yes "
        "<repo>@sha256:<digest>`` after the build. Sign by digest, "
        "not tag, so a re-pushed tag can't bypass the signature."
    ),
    docs_note=(
        "Detection mirrors GHA-006 / TKN-009 / BK-009 — the shared "
        "signing-token catalog (cosign, sigstore, slsa-github-"
        "generator, slsa-framework, notation-sign) is searched "
        "across every string in each Argo document. Fires only on "
        "artifact-producing Workflows / WorkflowTemplates (those "
        "that invoke ``docker build`` / ``docker push`` / kaniko / "
        "``helm upgrade`` / ``aws s3 sync`` / etc.) so lint-only "
        "Workflows don't trip it."
    ),
)


def check(ctx: ArgoContext) -> Finding:
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    artifact_producers = [d for d in ctx.docs if produces_artifacts(d.data)]
    if not artifact_producers:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No artifact production detected — check not applicable.",
            recommendation=RULE.recommendation, passed=True,
        )
    unsigned = [d for d in artifact_producers if not has_signing(d.data)]
    passed = not unsigned
    desc = (
        "Every artifact-producing Argo document invokes a signing tool."
        if passed else
        f"{len(unsigned)} Argo document(s) produce artifacts but do "
        f"not invoke any signing tool: "
        f"{', '.join(d.display for d in unsigned[:5])}"
        f"{'…' if len(unsigned) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
