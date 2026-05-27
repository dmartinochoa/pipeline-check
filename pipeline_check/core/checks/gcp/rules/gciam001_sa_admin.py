"""GCIAM-001. Service account has Owner or Editor role on project."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCIAM-001",
    title="Service account has Owner or Editor role on project",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-250",),
    recommendation=(
        "Replace the Owner/Editor binding with a scoped predefined "
        "or custom role that grants only the permissions the service "
        "account needs. roles/owner and roles/editor grant full or "
        "near-full access to every resource in the project."
    ),
    docs_note=(
        "The basic roles (Owner, Editor) predate IAM and grant "
        "extremely broad access. A compromised service account with "
        "roles/owner can modify IAM policies, delete resources, and "
        "exfiltrate data across the entire project."
    ),
    exploit_example=(
        "An attacker obtains a service account key from a leaked CI "
        "environment variable. The SA holds roles/editor, allowing "
        "the attacker to deploy a crypto-miner on Compute Engine and "
        "exfiltrate Cloud Storage data."
    ),
)

_ADMIN_ROLES = frozenset({
    "roles/owner",
    "roles/editor",
})


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    policy = catalog.project_iam_policy()
    if not policy:
        return findings
    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        if role not in _ADMIN_ROLES:
            continue
        for member in binding.get("members", []):
            if not member.startswith("serviceAccount:"):
                continue
            sa_email = member.split(":", 1)[1]
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=sa_email,
                description=(
                    f"Service account {sa_email} is bound to "
                    f"'{role}' on the project. This grants near-full "
                    "administrative access."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
