"""AZVM-005. Virtual machine does not use a managed identity."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZVM-005",
    title="Virtual machine does not use a managed identity",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-287",),
    recommendation=(
        "Assign a system-assigned or user-assigned managed identity "
        "to the virtual machine. Managed identities eliminate the "
        "need to store credentials on the VM for accessing Azure "
        "resources."
    ),
    docs_note=(
        "Build agent VMs without managed identities must store "
        "service principal credentials, storage keys, or connection "
        "strings locally. These static credentials can be extracted "
        "from the VM's file system, environment variables, or "
        "metadata service if compromised."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for vm in catalog.virtual_machines():
        name = getattr(vm, "name", "<unnamed>")
        identity = getattr(vm, "identity", None)
        identity_type = str(
            getattr(identity, "type", "None"),
        ).lower() if identity else "none"
        passed = identity_type != "none" and identity is not None
        if passed:
            desc = (
                f"VM '{name}' has a managed identity configured "
                f"(type: {identity_type})."
            )
        else:
            desc = (
                f"VM '{name}' does not have a managed identity. "
                "The VM must store credentials explicitly to access "
                "Azure resources."
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
