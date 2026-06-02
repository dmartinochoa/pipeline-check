"""AZVM-003. Virtual machine does not have JIT network access configured."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZVM-003",
    title="Virtual machine does not have JIT network access",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Enable Just-in-Time (JIT) VM access through Microsoft "
        "Defender for Cloud. JIT locks down inbound ports and opens "
        "them only when an authorized user requests access, for a "
        "limited time and from a specific IP."
    ),
    docs_note=(
        "JIT access reduces the VM's attack surface by closing "
        "management ports (SSH, RDP) until they are explicitly "
        "requested. Without JIT, these ports remain open "
        "continuously even when no administrator needs access."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for vm in catalog.virtual_machines():
        name = getattr(vm, "name", "<unnamed>")
        # JIT status is tracked via Defender for Cloud / Security
        # Center. The VM object itself does not expose JIT directly.
        # We check resource tags for a JIT-related marker.
        # NOTE: security_profile controls Trusted Launch / Secure Boot /
        # vTPM (the default for Gen2 VMs) and is unrelated to JIT access,
        # so it must NOT be used as a JIT indicator.
        tags = getattr(vm, "tags", {}) or {}
        has_jit = "jit" in str(tags).lower()
        passed = has_jit
        if passed:
            desc = (
                f"VM '{name}' has JIT network access indicators "
                "present."
            )
        else:
            desc = (
                f"VM '{name}' does not have JIT network access "
                "configured. Management ports remain open "
                "continuously."
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
