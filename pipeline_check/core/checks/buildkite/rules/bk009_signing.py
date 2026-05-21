"""BK-009, pipeline should sign artifacts (cosign / sigstore / …)."""
from __future__ import annotations

from typing import Any

from ...base import NO_ARTIFACT_DESC, Finding, Severity, has_signing, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="BK-009",
    title="Artifacts not signed (no cosign/sigstore step)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a signing step, install cosign once (``brew install cosign`` "
        "in the agent image, or a ``cosign-install`` plugin) and call "
        "``cosign sign --yes <ref>`` after the build. For container "
        "images pushed to ECR / GCR / GHCR, the same call signs by "
        "digest. Publish the signature alongside the artifact and "
        "verify it at consumption time."
    ),
    docs_note=(
        "Unsigned artifacts can't be verified downstream, a tampered "
        "build is indistinguishable from a legitimate one. The check "
        "recognizes cosign, sigstore, slsa-github-generator, slsa-"
        "framework, and notation-sign as signing tools, matching the "
        "shared signing-token catalog used by the other CI packs."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    if not produces_artifacts(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=NO_ARTIFACT_DESC,
            recommendation=RULE.recommendation, passed=True,
        )
    passed = has_signing(doc)
    desc = (
        "Pipeline invokes a signing tool (cosign / sigstore / slsa-github-"
        "generator / notation)."
        if passed else
        "Pipeline produces build artifacts but does not invoke any "
        "signing tool (cosign, sigstore, slsa-github-generator, "
        "notation). Unsigned artifacts cannot be verified downstream."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
