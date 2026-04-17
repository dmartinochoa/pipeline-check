"""JF-006 — artifact signing."""
from __future__ import annotations

from ...base import _ARTIFACT_TOKENS, SIGN_TOKENS, Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-006",
    title="Artifacts not signed",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a `sh 'cosign sign --yes …'` step (the cosign-"
        "installer Jenkins plugin handles binary install). Publish "
        "the signature next to the artifact and verify it at deploy."
    ),
    docs_note=(
        "Passes when cosign / sigstore / slsa-* / notation-sign "
        "appears in executable Jenkinsfile text (comments are "
        "stripped before matching)."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    text = jf.text_no_comments.lower()
    passed = any(tok in text for tok in SIGN_TOKENS)
    if not passed and not any(tok in jf.text.lower() for tok in _ARTIFACT_TOKENS):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=jf.path,
            description="No artifact production detected — check not applicable.",
            recommendation=RULE.recommendation, passed=True,
        )
    desc = (
        "Pipeline invokes a signing tool (cosign / sigstore / notation)."
        if passed else
        "Pipeline produces build artifacts but does not invoke any "
        "signing tool. Unsigned artifacts cannot be verified "
        "downstream."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
