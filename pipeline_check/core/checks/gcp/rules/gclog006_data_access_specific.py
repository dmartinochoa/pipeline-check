"""GCLOG-006. Critical service missing specific Data Access audit logs."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCLOG-006",
    title="Critical service missing Data Access audit log types",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Configure per-service audit log configs for "
        "storage.googleapis.com, iam.googleapis.com, and "
        "compute.googleapis.com to include all three log types: "
        "ADMIN_READ (1), DATA_WRITE (2), and DATA_READ (3)."
    ),
    docs_note=(
        "While enabling allServices audit logging is a good baseline, "
        "critical services like Storage, IAM, and Compute should "
        "have explicit per-service audit configs to ensure visibility "
        "is not accidentally removed by a broad policy change."
    ),
)

_CRITICAL_SERVICES = frozenset({
    "storage.googleapis.com",
    "iam.googleapis.com",
    "compute.googleapis.com",
})

_REQUIRED_LOG_TYPES = {1, 2, 3}


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    policy = catalog.project_iam_policy()
    if not policy:
        return findings
    audit_configs = policy.get("audit_configs", [])
    configured: dict[str, set[int]] = {}
    for ac in audit_configs:
        svc = ac.get("service", "")
        if svc in _CRITICAL_SERVICES or svc == "allServices":
            log_types = {
                lc.get("log_type")
                for lc in ac.get("audit_log_configs", [])
            }
            if svc == "allServices":
                for cs in _CRITICAL_SERVICES:
                    configured.setdefault(cs, set()).update(log_types)
            else:
                configured.setdefault(svc, set()).update(log_types)
    resource = f"projects/{catalog.session.project_id}"
    for svc in sorted(_CRITICAL_SERVICES):
        types_found = configured.get(svc, set())
        missing = _REQUIRED_LOG_TYPES - types_found
        if missing:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=resource,
                description=(
                    f"Service {svc} is missing audit log types: "
                    f"{sorted(missing)} (ADMIN_READ=1, DATA_WRITE=2, "
                    "DATA_READ=3)."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=resource,
                description=(
                    f"Service {svc} has all required audit log types "
                    "configured."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
