"""BK-012, pipeline should run a vulnerability scan."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_vuln_scanning
from ...rule import Rule

RULE = Rule(
    id="BK-012",
    title="No vulnerability scanning step",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-VULN-SCAN",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add a vulnerability scanner, ``trivy fs .`` for source / "
        "filesystem, ``trivy image <ref>`` for container images, "
        "``grype`` and ``snyk`` for either. Add ``npm audit`` / "
        "``pip-audit`` for language-specific dep audits. Fail the "
        "step on findings above a chosen severity so a regression "
        "blocks the merge instead of shipping."
    ),
    docs_note=(
        "Vulnerability scanning sits at a different layer from signing "
        "and SBOM. It answers ``does this artifact ship a known "
        "CVE?`` rather than ``can we verify what it is?``. Detection "
        "uses the shared vuln-scan-token catalog: trivy, grype, "
        "snyk, npm-audit, pip-audit, anchore, dependency-check, "
        "checkov, semgrep."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    passed = has_vuln_scanning(doc)
    desc = (
        "Pipeline runs a vulnerability scanner (trivy / grype / snyk / …)."
        if passed else
        "Pipeline does not invoke any vulnerability scanner, known "
        "CVEs in dependencies or container layers ship to production "
        "without a build-time signal. Add ``trivy``, ``grype``, "
        "``snyk``, ``npm audit``, or ``pip-audit`` to the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
