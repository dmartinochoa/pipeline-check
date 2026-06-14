"""HARNESS-018. Pipeline should run a vulnerability scanner."""
from __future__ import annotations

from ...base import Finding, Severity, has_vuln_scanning
from ...rule import Rule
from ..base import HarnessPipeline

RULE = Rule(
    id="HARNESS-018",
    title="No vulnerability-scan step (trivy / grype / snyk)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-VULN-SCAN",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add a vulnerability-scan step to the build: ``trivy``, ``grype``, "
        "``snyk``, ``npm audit``, or ``pip-audit`` over the image or "
        "dependency tree (or a Harness Security Testing Orchestration "
        "step), and fail the build on findings above your threshold so "
        "known CVEs don't ship to production silently."
    ),
    docs_note=(
        "Detection mirrors GHA-020 / BK-012 / CC-020 / TKN-012 / DR-022, "
        "the shared scanner-token catalog (trivy, grype, snyk, clair, npm "
        "audit, pip-audit, etc.) is searched across every string in the "
        "pipeline document. Fires on any pipeline that runs no scanner (the "
        "build ships without a CVE signal). The Harness analog of BK-012 / "
        "TKN-012."
    ),
)


def check(pipeline: HarnessPipeline) -> Finding:
    passed = has_vuln_scanning(pipeline.data)
    desc = (
        "Pipeline runs a vulnerability scanner (trivy / grype / snyk / ...)."
        if passed else
        "Pipeline does not invoke any vulnerability scanner; known CVEs in "
        "dependencies or container layers ship to production without a "
        "build-time signal. Add trivy, grype, snyk, npm audit, or "
        "pip-audit to the build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
