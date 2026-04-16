"""JF-006 — artifact signing."""
from __future__ import annotations

from ...base import SIGN_TOKENS, Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-006",
    title="Artifacts not signed",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SIGN-ARTIFACTS",),
    recommendation=(
        "Add a `sh 'cosign sign --yes …'` step (the cosign-"
        "installer Jenkins plugin handles binary install). Publish "
        "the signature next to the artifact and verify it at deploy."
    ),
    docs_note=(
        "Passes when cosign / sigstore / slsa-* / notation-sign "
        "appears in the raw Jenkinsfile text."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    text = jf.text.lower()
    passed = any(tok in text for tok in SIGN_TOKENS)
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
