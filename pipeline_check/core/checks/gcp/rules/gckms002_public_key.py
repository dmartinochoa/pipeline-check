"""GCKMS-002. KMS key IAM policy grants allUsers or allAuthenticatedUsers."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCKMS-002",
    title="KMS key IAM policy grants public access",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Remove allUsers and allAuthenticatedUsers from the key's "
        "IAM policy. KMS keys should only be accessible to service "
        "accounts that need them."
    ),
    docs_note=(
        "A KMS key with allUsers access allows anyone on the "
        "internet to encrypt, decrypt, or sign data with the key, "
        "depending on the granted role."
    ),
    exploit_example=(
        "A KMS CryptoKey grants roles/cloudkms.cryptoKeyDecrypter to "
        "allUsers. Anyone on the internet who knows the key's resource "
        "name calls kms.decrypt on ciphertext they've exfiltrated (an "
        "encrypted backup, a sealed secret), recovering the plaintext "
        "without ever touching the project's IAM."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    policy = catalog.project_iam_policy()
    if not policy:
        return findings
    public_members = {"allUsers", "allAuthenticatedUsers"}
    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        if "cloudkms" not in role:
            continue
        members = set(binding.get("members", []))
        public = members & public_members
        if public:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=role,
                description=(
                    f"KMS role '{role}' is granted to "
                    f"{', '.join(sorted(public))} at the project level."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
