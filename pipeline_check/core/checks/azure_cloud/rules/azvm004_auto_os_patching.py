"""AZVM-004. Virtual machine does not have automatic OS patching enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZVM-004",
    title="Virtual machine automatic OS patching not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-1395",),
    recommendation=(
        "Enable automatic OS patching on the virtual machine. For "
        "Windows VMs, enable 'EnableAutomaticUpdates'. For Linux "
        "VMs, set the patch mode to 'AutomaticByPlatform' and "
        "enable automatic assessment."
    ),
    docs_note=(
        "Build agent VMs and pipeline infrastructure without "
        "automatic patching accumulate unpatched vulnerabilities. "
        "An unpatched OS is the most common entry point for "
        "privilege escalation after initial access."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for vm in catalog.virtual_machines():
        name = getattr(vm, "name", "<unnamed>")
        os_profile = getattr(vm, "os_profile", None)
        auto_patch = False

        if os_profile:
            # Windows VM check.
            win_config = getattr(os_profile, "windows_configuration", None)
            if win_config:
                auto_updates = getattr(
                    win_config, "enable_automatic_updates", False,
                )
                if auto_updates:
                    auto_patch = True

            # Linux VM check.
            linux_config = getattr(os_profile, "linux_configuration", None)
            if linux_config:
                patch_settings = getattr(
                    linux_config, "patch_settings", None,
                )
                if patch_settings:
                    patch_mode = str(
                        getattr(patch_settings, "patch_mode", ""),
                    ).lower()
                    if patch_mode == "automaticbyplatform":
                        auto_patch = True

        passed = auto_patch
        if passed:
            desc = (
                f"VM '{name}' has automatic OS patching enabled."
            )
        else:
            desc = (
                f"VM '{name}' does not have automatic OS patching "
                "enabled. The VM may accumulate unpatched "
                "vulnerabilities."
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
