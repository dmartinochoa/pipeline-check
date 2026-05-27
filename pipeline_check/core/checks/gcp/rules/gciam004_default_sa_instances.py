"""GCIAM-004. Compute instance uses default service account."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCIAM-004",
    title="Compute instance uses default service account",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-250",),
    recommendation=(
        "Create a dedicated service account with minimum required "
        "permissions for each workload. Replace the default compute "
        "service account on every instance."
    ),
    docs_note=(
        "The Compute Engine default service account "
        "(*-compute@developer.gserviceaccount.com) is automatically "
        "granted the Editor role on the project. Any workload running "
        "under it inherits near-full access to every resource."
    ),
    exploit_example=(
        "An attacker gains shell on a VM via an SSRF vulnerability. "
        "The instance runs under the default compute SA with Editor "
        "access, allowing the attacker to create new SA keys, read "
        "secrets, and pivot across the project."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for inst in catalog.compute_instances():
        name = inst.get("name", "<unnamed>")
        sa_emails = inst.get("service_accounts", [])
        uses_default = any(
            email.endswith("-compute@developer.gserviceaccount.com")
            for email in sa_emails
        )
        if uses_default:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Instance '{name}' uses the default compute "
                    "service account, which typically has Editor-level "
                    "access to the project."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Instance '{name}' uses a custom service account."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
