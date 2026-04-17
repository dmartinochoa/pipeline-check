"""JF-008 — whole-document credential-shaped literal scan."""
from __future__ import annotations

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-008",
    title="Credential-shaped literal in pipeline body",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Rotate the exposed credential. Move the value to a "
        "Jenkins credential and reference it via "
        "`withCredentials([string(credentialsId: '…', variable: '…')])`."
    ),
    docs_note=(
        "Scans the raw Jenkinsfile text against the cross-provider "
        "credential-pattern catalogue. Secrets committed to Groovy "
        "source are visible in every fork and every build log."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    hits = find_secret_values([jf.text])
    passed = not hits
    desc = (
        "No string in the Jenkinsfile matches a known credential pattern."
        if passed else
        f"Jenkinsfile contains {len(hits)} literal value(s) matching "
        f"known credential patterns: "
        f"{', '.join(hits[:5])}{'…' if len(hits) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
