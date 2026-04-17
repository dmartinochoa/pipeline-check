"""GHA-006 — workflow should sign artifacts (cosign / sigstore / …)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_signing, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="GHA-006",
    title="Artifacts not signed (no cosign/sigstore step)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a signing step — e.g. `sigstore/cosign-installer` followed "
        "by `cosign sign`, or `slsa-framework/slsa-github-generator` "
        "for keyless SLSA provenance. Publish the signature alongside "
        "the artifact and verify it at consumption time."
    ),
    docs_note=(
        "Unsigned artifacts cannot be verified downstream, so a "
        "tampered build is indistinguishable from a legitimate one. "
        "The check recognises cosign, sigstore, slsa-github-"
        "generator, slsa-framework, and notation-sign as signing "
        "tools."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    passed = has_signing(doc)
    if not passed and not produces_artifacts(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No artifact production detected — check not applicable.",
            recommendation=RULE.recommendation, passed=True,
        )
    desc = (
        "Workflow invokes a signing tool (cosign / sigstore / slsa-github-"
        "generator / notation)."
        if passed else
        "Workflow produces build artifacts but does not invoke any "
        "signing tool (cosign, sigstore, slsa-github-generator, "
        "notation). Unsigned artifacts cannot be verified downstream, "
        "so a tampered build is indistinguishable from a legitimate one."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
