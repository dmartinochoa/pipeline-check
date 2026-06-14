"""DR-019. Pipeline should sign produced artifacts (cosign / sigstore)."""
from __future__ import annotations

from ...base import (
    NO_ARTIFACT_DESC,
    Finding,
    Severity,
    has_signing,
    produces_artifacts,
)
from ...rule import Rule
from ..base import Pipeline

RULE = Rule(
    id="DR-019",
    title="Artifacts not signed (no cosign/sigstore step)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a signing step after the build: install cosign in the step "
        "image and call ``cosign sign --yes <repo>@sha256:<digest>`` so a "
        "re-pushed tag can't bypass the signature. Publish the signature "
        "alongside the artifact and verify it at consumption time."
    ),
    docs_note=(
        "Detection mirrors GHA-006 / BK-009 / CC-006 / TKN-009, the shared "
        "signing-token catalog (cosign, sigstore, slsa-github-generator, "
        "slsa-framework, notation-sign) is searched across every string in "
        "the pipeline document. The rule only fires on artifact-producing "
        "pipelines (those that invoke ``docker build`` / ``docker push`` / "
        "``buildah`` / ``kaniko`` / etc.) so lint / test-only pipelines "
        "don't trip it. The Drone analog of BK-009 / TKN-009."
    ),
)


def check(pipeline: Pipeline) -> Finding:
    doc = pipeline.data
    if not produces_artifacts(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path, description=NO_ARTIFACT_DESC,
            recommendation=RULE.recommendation, passed=True,
        )
    passed = has_signing(doc)
    desc = (
        "Pipeline invokes a signing tool (cosign / sigstore / "
        "slsa-github-generator / notation)."
        if passed else
        "Pipeline produces build artifacts but does not invoke any signing "
        "tool (cosign, sigstore, slsa-github-generator, notation). Unsigned "
        "artifacts cannot be verified downstream."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
