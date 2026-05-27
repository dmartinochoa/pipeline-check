"""GCCE-003. Compute instance has serial port access enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCCE-003",
    title="Compute instance has serial port access enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Set the metadata key 'serial-port-enable' to 'false' (or "
        "remove it) on every instance. Use the Cloud Console or "
        "gcloud SSH instead for debugging."
    ),
    docs_note=(
        "Enabling the interactive serial console (serial-port-enable) "
        "allows anyone with the compute.instances.getSerialPortOutput "
        "permission to read console output, which may contain boot "
        "logs, kernel messages, or application secrets."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for inst in catalog.compute_instances():
        name = inst.get("name", "<unnamed>")
        metadata = inst.get("metadata", {})
        serial_port = metadata.get("serial-port-enable", "").lower()
        if serial_port == "true":
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Instance '{name}' has serial port access "
                    "enabled. Console output may expose sensitive "
                    "information."
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
                    f"Instance '{name}' does not have serial port "
                    "access enabled."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
