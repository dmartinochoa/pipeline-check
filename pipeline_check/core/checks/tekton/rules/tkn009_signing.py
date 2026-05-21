"""TKN-009. Tekton Task should sign produced artifacts."""
from __future__ import annotations

from ...base import NO_ARTIFACT_DESC, Finding, Severity, has_signing, produces_artifacts
from ...rule import Rule
from ..base import TektonContext

RULE = Rule(
    id="TKN-009",
    title="Artifacts not signed (no cosign/sigstore step)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a signing step to the Task, either a dedicated "
        "``cosign sign`` step after the build, or use the official "
        "``cosign`` Tekton catalog Task as a referenced step. The "
        "Task should sign by digest (``cosign sign --yes "
        "<repo>@sha256:<digest>``) so a re-pushed tag can't bypass "
        "the signature."
    ),
    docs_note=(
        "Detection mirrors GHA-006 / BK-009 / CC-006, the shared "
        "signing-token catalog (cosign, sigstore, slsa-github-"
        "generator, slsa-framework, notation-sign) is searched "
        "across every string in the Task / Pipeline document. The "
        "rule only fires on artifact-producing Tasks (those that "
        "invoke ``docker build`` / ``docker push`` / ``buildah`` / "
        "``kaniko`` / ``helm upgrade`` / ``aws s3 sync`` / etc.) so "
        "lint-only Tasks don't trip it."
    ),
)


def check(ctx: TektonContext) -> Finding:
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Tekton documents to check.",
            recommendation="No action required.", passed=True,
        )
    # Only Tasks / ClusterTasks declare the build steps that actually
    # produce artifacts. PipelineRun / TaskRun reference a Task by
    # name and would otherwise false-positive on a "deploy" / "release"
    # substring in their reference name.
    artifact_producers = [
        d for d in ctx.docs
        if d.kind in ("Task", "ClusterTask") and produces_artifacts(d.data)
    ]
    if not artifact_producers:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description=NO_ARTIFACT_DESC,
            recommendation=RULE.recommendation, passed=True,
        )
    unsigned = [d for d in artifact_producers if not has_signing(d.data)]
    passed = not unsigned
    desc = (
        "Every artifact-producing Tekton document invokes a signing "
        "tool (cosign / sigstore / slsa-github-generator / notation)."
        if passed else
        f"{len(unsigned)} Tekton document(s) produce artifacts but "
        f"do not invoke any signing tool: "
        f"{', '.join(d.display for d in unsigned[:5])}"
        f"{'…' if len(unsigned) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
