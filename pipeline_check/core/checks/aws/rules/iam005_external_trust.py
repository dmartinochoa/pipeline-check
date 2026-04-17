"""IAM-005 — CI/CD role trust allows external AWS principal w/o sts:ExternalId."""
from __future__ import annotations

import json

from ..._iam_policy import iter_allow
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="IAM-005",
    title="CI/CD role trust policy missing sts:ExternalId",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-441",),
    recommendation=(
        "Add a Condition requiring sts:ExternalId for external principals."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for role in catalog.cicd_roles():
        role_name = role.get("RoleName", "<unnamed>")
        doc = role.get("AssumeRolePolicyDocument", {})
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except json.JSONDecodeError:
                doc = {}
        bad: list[str] = []
        for idx, stmt in enumerate(iter_allow(doc)):
            principal = stmt.get("Principal", {}) or {}
            if not (isinstance(principal, dict) and principal.get("AWS")):
                continue
            conditions = stmt.get("Condition", {}) or {}
            has_external_id = any(
                "sts:ExternalId" in (inner or {})
                for inner in conditions.values()
                if isinstance(inner, dict)
            )
            if not has_external_id:
                bad.append(f"stmt[{idx}]")
        passed = not bad
        desc = (
            f"Trust policy on '{role_name}' has no external AWS principal, or "
            f"every external principal requires sts:ExternalId."
            if passed else
            f"Trust policy on '{role_name}' allows assumption by an AWS "
            f"principal in {bad} without sts:ExternalId (confused-deputy risk)."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=role_name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
