"""CP-002 — CodePipeline artifact store uses default S3 SSE, not a CMK."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CP-002",
    title="Artifact store not encrypted with customer-managed KMS key",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Configure a customer-managed AWS KMS key as the encryptionKey for "
        "each artifact store. This enables key rotation, fine-grained access "
        "policies, and CloudTrail auditing of decrypt operations."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for pipeline in catalog.codepipeline_pipelines():
        name = pipeline.get("name", "<unnamed>")
        stores: list[dict] = []
        if "artifactStore" in pipeline:
            stores.append(pipeline["artifactStore"])
        stores.extend((pipeline.get("artifactStores") or {}).values())
        unencrypted = [
            s.get("location", "unknown")
            for s in stores
            if "encryptionKey" not in s
        ]
        passed = not unencrypted
        if passed:
            desc = "All artifact stores use a customer-managed KMS encryption key."
        else:
            desc = (
                f"Artifact store(s) {unencrypted} rely on default S3 SSE (AWS-managed "
                f"key) rather than a customer-managed KMS key. This reduces auditability "
                f"and control over who can decrypt pipeline artifacts."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
