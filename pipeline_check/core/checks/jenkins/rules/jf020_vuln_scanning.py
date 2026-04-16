"""JF-020 — no vulnerability scanning step."""
from __future__ import annotations

from ...base import Finding, Severity, has_vuln_scanning
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-020",
    title="No vulnerability scanning step",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VULN-MGMT",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add a vulnerability scanning step \u2014 trivy, grype, snyk test, "
        "npm audit, pip-audit, or osv-scanner. Publish results so "
        "vulnerabilities surface before deployment."
    ),
    docs_note=(
        "Without a vulnerability scanning step, known-vulnerable "
        "dependencies ship to production undetected. The check "
        "recognises trivy, grype, snyk, npm audit, yarn audit, "
        "safety check, pip-audit, osv-scanner, and govulncheck."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    passed = has_vuln_scanning([jf.text])
    desc = (
        "Pipeline invokes a vulnerability scanner (trivy / grype / "
        "snyk / npm audit / pip-audit / osv-scanner)."
        if passed else
        "Pipeline does not invoke any vulnerability scanning tool. "
        "Known-vulnerable dependencies may ship to production "
        "undetected."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
