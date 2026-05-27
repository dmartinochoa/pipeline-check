"""GCLOG-001. Cloud Audit Logs not enabled for all services."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCLOG-001",
    title="Cloud Audit Logs not enabled for all services",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Configure the project IAM policy's auditConfigs to enable "
        "Data Access audit logs for allServices. At minimum, enable "
        "ADMIN_READ and DATA_WRITE log types."
    ),
    docs_note=(
        "Admin Activity logs are always on, but Data Access logs "
        "(reads and writes to user data) must be explicitly enabled. "
        "Without them, access to Cloud Storage objects, BigQuery "
        "datasets, and other data resources is invisible."
    ),
    exploit_example=(
        "An attacker uses stolen credentials to exfiltrate Cloud "
        "Storage objects. Without Data Access audit logs, the "
        "exfiltration is invisible in Cloud Logging."
    ),
)

_REQUIRED_LOG_TYPES = {1, 2, 3}


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    policy = catalog.project_iam_policy()
    if not policy:
        return findings
    audit_configs = policy.get("audit_configs", [])
    has_all_services = False
    for ac in audit_configs:
        if ac.get("service") == "allServices":
            has_all_services = True
            log_types = {
                lc.get("log_type") for lc in ac.get("audit_log_configs", [])
            }
            missing = _REQUIRED_LOG_TYPES - log_types
            if missing:
                findings.append(Finding(
                    check_id=RULE.id,
                    title=RULE.title,
                    severity=RULE.severity,
                    resource=f"projects/{catalog.session.project_id}",
                    description=(
                        "allServices audit config exists but is missing "
                        f"log types: {sorted(missing)}. All three types "
                        "(ADMIN_READ=1, DATA_WRITE=2, DATA_READ=3) "
                        "should be enabled."
                    ),
                    recommendation=RULE.recommendation,
                    passed=False,
                ))
            else:
                findings.append(Finding(
                    check_id=RULE.id,
                    title=RULE.title,
                    severity=RULE.severity,
                    resource=f"projects/{catalog.session.project_id}",
                    description=(
                        "allServices audit config is enabled with all "
                        "required log types."
                    ),
                    recommendation=RULE.recommendation,
                    passed=True,
                ))
            break
    if not has_all_services:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=f"projects/{catalog.session.project_id}",
            description=(
                "No allServices audit config found. Data Access "
                "audit logs are not globally enabled."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
