"""GCB-008 — No vulnerability scanning step anywhere in the pipeline.

Reuses the cross-provider ``has_vuln_scanning`` helper so the
scanner-name catalogue (trivy / grype / snyk / osv-scanner / pip-audit
/ npm audit / govulncheck) stays in sync across GHA-020 / GL-019 /
BB-019 / ADO-019 / CC-020 / JF-020.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_vuln_scanning
from ...rule import Rule

RULE = Rule(
    id="GCB-008",
    title="No vulnerability scanning step in Cloud Build pipeline",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VULN-SCAN",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add a step that runs a vulnerability scanner — trivy, grype, "
        "snyk test, npm audit, pip-audit, osv-scanner, or govulncheck. "
        "In Cloud Build this typically looks like a step with "
        "``name: aquasec/trivy`` or an ``entrypoint: bash`` step that "
        "invokes ``trivy image`` / ``grype <ref>`` on the built image."
    ),
    docs_note=(
        "The detector matches tool names anywhere in the document — "
        "step images, ``args``, or ``entrypoint`` strings. Container "
        "Analysis API scanning configured at the project level counts "
        "as compensating control but is out of scope for this YAML-only "
        "check; if you rely on it, suppress this rule via ``--checks``."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    passed = has_vuln_scanning(doc)
    desc = (
        "Pipeline invokes a vulnerability scanner (trivy / grype / "
        "snyk / pip-audit / osv-scanner)."
        if passed else
        "No vulnerability scanner (trivy / grype / snyk / npm audit / "
        "pip-audit / osv-scanner / govulncheck) is invoked by any step."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
