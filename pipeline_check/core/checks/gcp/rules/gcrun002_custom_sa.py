"""GCRUN-002. Cloud Run service or function uses default compute SA."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCRUN-002",
    title="Cloud Run service or function uses default compute SA",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-250",),
    recommendation=(
        "Assign a dedicated service account with minimum required "
        "permissions to every Cloud Run service and Cloud Function. "
        "The default compute SA typically has the Editor role."
    ),
    docs_note=(
        "Cloud Run services and Cloud Functions default to the "
        "Compute Engine default service account, which usually "
        "holds the Editor role. A compromised function running "
        "under this SA can access nearly every resource in the "
        "project."
    ),
    exploit_example=(
        "An attacker exploits a deserialization vulnerability in "
        "a Cloud Function running under the default compute SA. "
        "They use the SA's Editor-level token to create new SA keys "
        "and establish persistent access to the project."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    # Check Cloud Run services
    for svc in catalog.cloud_run_services():
        name = svc.get("name", "<unnamed>")
        template = svc.get("template", {})
        sa = template.get("service_account", "")
        uses_default = (
            not sa
            or sa.endswith("-compute@developer.gserviceaccount.com")
        )
        if uses_default:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud Run service '{name}' uses the default "
                    "compute service account."
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
                    f"Cloud Run service '{name}' uses a custom "
                    f"service account: {sa}."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    # Check Cloud Functions
    for fn in catalog.cloud_functions():
        name = fn.get("name", "<unnamed>")
        svc_config = fn.get("service_config", {})
        sa = svc_config.get("service_account_email", "")
        uses_default = (
            not sa
            or sa.endswith("-compute@developer.gserviceaccount.com")
        )
        if uses_default:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud Function '{name}' uses the default "
                    "compute service account."
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
                    f"Cloud Function '{name}' uses a custom "
                    f"service account: {sa}."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
