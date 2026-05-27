"""GCS-001. Cloud Storage bucket is publicly accessible."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCS-001",
    title="Cloud Storage bucket is publicly accessible",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Remove allUsers and allAuthenticatedUsers members from the "
        "bucket's IAM policy. Use signed URLs or IAM-authenticated "
        "access for legitimate public-facing content."
    ),
    docs_note=(
        "A bucket with allUsers or allAuthenticatedUsers in its IAM "
        "policy is accessible to the internet. Build artifacts, "
        "Terraform state files, and deployment manifests stored in "
        "public buckets are trivially discoverable."
    ),
    exploit_example=(
        "An attacker enumerates project bucket names and finds a "
        "publicly readable bucket containing Terraform state with "
        "embedded database credentials."
    ),
)

_PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for bucket in catalog.storage_buckets():
        name = bucket.get("name", "<unnamed>")
        iam_policy = bucket.get("iam_policy", [])
        public_roles: list[str] = []
        for binding in iam_policy:
            members = set(binding.get("members", []))
            if members & _PUBLIC_MEMBERS:
                public_roles.append(binding.get("role", "<unknown>"))
        passed = len(public_roles) == 0
        if passed:
            desc = f"Bucket '{name}' has no public IAM bindings."
        else:
            desc = (
                f"Bucket '{name}' is publicly accessible via "
                f"role(s): {', '.join(public_roles)}."
            )
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=name,
            description=desc,
            recommendation=RULE.recommendation,
            passed=passed,
        ))
    return findings
