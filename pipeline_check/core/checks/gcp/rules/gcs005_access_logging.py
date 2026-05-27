"""GCS-005. Cloud Storage bucket access logging not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCS-005",
    title="Cloud Storage bucket access logging not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Enable access logging on the bucket by setting a log bucket "
        "destination. Access logs record every read and write, "
        "supporting forensic analysis and compliance audits."
    ),
    docs_note=(
        "Cloud Storage access logs capture object-level operations "
        "that Cloud Audit Logs may not cover in detail. Without "
        "access logging, it is difficult to determine who accessed "
        "or modified specific objects after a security incident."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for bucket in catalog.storage_buckets():
        name = bucket.get("name", "<unnamed>")
        logging_cfg = bucket.get("logging")
        has_logging = (
            logging_cfg is not None
            and bool(logging_cfg.get("log_bucket"))
        )
        if has_logging:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Bucket '{name}' has access logging enabled "
                    f"(log bucket: {logging_cfg.get('log_bucket') if logging_cfg else 'unknown'})."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Bucket '{name}' does not have access logging "
                    "enabled."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
