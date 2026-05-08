"""TKN-012 — Tekton Task should run a vulnerability scan."""
from __future__ import annotations

from ...base import Finding, Severity, has_vuln_scanning
from ...rule import Rule
from ..base import TektonContext

RULE = Rule(
    id="TKN-012",
    title="No vulnerability scanning step",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-VULN-MGMT",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add a vulnerability scanner step. ``trivy fs "
        "$(workspaces.src.path)`` for source / filesystem; ``trivy "
        "image <ref>`` for container images. The official Tekton "
        "catalog ships ``trivy-scanner`` and ``grype-scanner`` Tasks "
        "if you'd rather reference one. Fail the step on findings "
        "above a chosen severity so a regression blocks the merge "
        "instead of shipping."
    ),
    docs_note=(
        "Vulnerability scanning sits at a different layer from "
        "signing and SBOM — it answers *does this artifact ship a "
        "known CVE?* rather than *can we verify what it is?*. "
        "Detection uses the shared vuln-scan-token catalog: trivy, "
        "grype, snyk, npm-audit, pip-audit, osv-scanner, "
        "govulncheck, anchore, codeql-action, semgrep, bandit, "
        "checkov, tfsec, dependency-check. Walks every Task / "
        "Pipeline / *Run document; passes if any document includes "
        "a scanner reference."
    ),
)


def check(ctx: TektonContext) -> Finding:
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Tekton documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = any(has_vuln_scanning(d.data) for d in ctx.docs)
    desc = (
        "At least one Tekton document invokes a vulnerability "
        "scanner (trivy / grype / snyk / …)."
        if passed else
        "No Tekton document invokes any vulnerability scanner — "
        "known CVEs in dependencies or container layers ship to "
        "production without a build-time signal."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
