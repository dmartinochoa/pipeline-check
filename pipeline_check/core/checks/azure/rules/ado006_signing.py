"""ADO-006 — artifact signing."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_signing
from ...rule import Rule

RULE = Rule(
    id="ADO-006",
    title="Artifacts not signed",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a task that runs `cosign sign` or `notation sign` — "
        "Azure Pipelines' workload identity federation enables "
        "keyless signing. Publish the signature to the artifact "
        "feed and verify it at deploy time."
    ),
    docs_note=(
        "Passes when cosign / sigstore / slsa-* / notation-sign "
        "appears anywhere in the pipeline text."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    passed = has_signing(doc)
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
