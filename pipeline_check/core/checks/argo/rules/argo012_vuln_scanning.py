"""ARGO-012. Argo workflow should run a vulnerability scan."""
from __future__ import annotations

from ...base import Finding, Severity, has_vuln_scanning
from ...rule import Rule
from ..base import ArgoContext

RULE = Rule(
    id="ARGO-012",
    title="No vulnerability scanning step",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-VULN-MGMT",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add a vulnerability scanner template. ``trivy fs /workdir`` "
        "for source / filesystem; ``trivy image <ref>`` for "
        "container images. ``grype``, ``snyk``, ``npm audit``, "
        "``pip-audit`` are alternatives. Fail the template on "
        "findings above a chosen severity so a regression blocks "
        "the merge instead of shipping."
    ),
    docs_note=(
        "Vulnerability scanning sits at a different layer from "
        "signing and SBOM. It answers *does this artifact ship a "
        "known CVE?* rather than *can we verify what it is?*. "
        "Detection uses the shared vuln-scan-token catalog: trivy, "
        "grype, snyk, npm-audit, pip-audit, osv-scanner, "
        "govulncheck, codeql-action, semgrep, bandit, "
        "checkov, tfsec. Walks every Argo document and passes if "
        "any document includes a scanner reference."
    ),
)


def check(ctx: ArgoContext) -> Finding:
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = any(has_vuln_scanning(d.data) for d in ctx.docs)
    desc = (
        "At least one Argo document invokes a vulnerability scanner."
        if passed else
        "No Argo document invokes any vulnerability scanner, known "
        "CVEs in dependencies or container layers ship to production "
        "without a build-time signal."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
