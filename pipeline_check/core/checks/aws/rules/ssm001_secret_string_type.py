"""SSM-001 — SSM parameter with secret-like name stored as String (not SecureString)."""
from __future__ import annotations

from ..._patterns import SECRET_NAME_RE
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="SSM-001",
    title="SSM Parameter with secret-like name is not a SecureString",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-312",),
    recommendation=(
        "Recreate the parameter with ``Type=SecureString`` and migrate "
        "consumers to the new name if needed. Plain ``String`` parameters "
        "are visible via ``ssm:GetParameter`` without any KMS authorization."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for param in catalog.ssm_parameters():
        name = param.get("Name", "<unnamed>")
        ptype = param.get("Type", "")
        if ptype == "SecureString":
            continue
        if not SECRET_NAME_RE.search(name):
            continue
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name,
            description=(
                f"Parameter '{name}' has a secret-like name but is stored "
                f"as {ptype or 'String'}, not SecureString."
            ),
            recommendation=RULE.recommendation, passed=False,
        ))
    return findings
