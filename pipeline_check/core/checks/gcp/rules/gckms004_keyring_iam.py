"""GCKMS-004. KMS key ring IAM has overly broad bindings."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCKMS-004",
    title="KMS key ring IAM has overly broad bindings",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Remove allUsers and allAuthenticatedUsers from KMS key ring "
        "IAM policies. Restrict key access to specific service accounts "
        "that need encrypt/decrypt/sign operations."
    ),
    docs_note=(
        "KMS key ring IAM policies govern access to every key in "
        "the ring. An overly broad binding (allUsers, "
        "allAuthenticatedUsers) grants the entire internet access "
        "to encrypt, decrypt, or manage keys."
    ),
    exploit_example=(
        "An attacker discovers that allAuthenticatedUsers has "
        "roles/cloudkms.cryptoKeyDecrypter on a key ring. They "
        "decrypt every secret envelope in the project using their "
        "own Google account."
    ),
)

_OVERLY_BROAD_MEMBERS = frozenset({
    "allUsers",
    "allAuthenticatedUsers",
})


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for ring in catalog.kms_key_rings():
        name = ring.get("name", "<unnamed>")
        iam_policy = ring.get("iam_policy", [])
        broad_bindings: list[str] = []
        for binding in iam_policy:
            role = binding.get("role", "")
            members = set(binding.get("members", []))
            broad = members & _OVERLY_BROAD_MEMBERS
            if broad:
                broad_bindings.append(
                    f"{role} -> {', '.join(sorted(broad))}"
                )
        if broad_bindings:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Key ring '{name}' has overly broad IAM "
                    f"bindings: {'; '.join(broad_bindings)}."
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
                    f"Key ring '{name}' has no overly broad IAM "
                    "bindings."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
