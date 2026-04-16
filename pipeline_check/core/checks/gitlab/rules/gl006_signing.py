"""GL-006 — artifact signing (cosign / sigstore / notation)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_signing
from ...rule import Rule

RULE = Rule(
    id="GL-006",
    title="Artifacts not signed",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a job that runs `cosign sign` (keyless OIDC with "
        "GitLab's id_tokens works out of the box) or `notation sign`. "
        "Publish the signature next to the artifact and verify it on "
        "consume."
    ),
    docs_note=(
        "Unsigned artifacts can't be verified downstream, so a "
        "tampered build is indistinguishable from a legitimate one. "
        "Pass when any of cosign / sigstore / slsa-* / notation-sign "
        "appears in the pipeline text."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    passed = has_signing(doc)
    desc = (
        "Pipeline invokes a signing tool (cosign / sigstore / notation)."
        if passed else
        "Pipeline produces build artifacts but does not invoke any "
        "signing tool (cosign, sigstore, notation). Unsigned artifacts "
        "cannot be verified downstream."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
