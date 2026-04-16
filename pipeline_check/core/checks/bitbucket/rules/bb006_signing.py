"""BB-006 — artifact signing."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_signing, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="BB-006",
    title="Artifacts not signed",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a step that runs `cosign sign` against the built image "
        "or archive, using Bitbucket OIDC for keyless signing where "
        "possible. Publish the signature next to the artifact and "
        "verify it at deploy time."
    ),
    docs_note=(
        "Unsigned artifacts can't be verified downstream. Passes "
        "when cosign / sigstore / slsa-* / notation-sign appears in "
        "the pipeline body."
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
        "Pipeline invokes a signing tool (cosign / sigstore / notation)."
        if passed else
        "Pipeline produces build artifacts but does not invoke any "
        "signing tool (cosign, sigstore, notation). Unsigned "
        "artifacts cannot be verified downstream."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
