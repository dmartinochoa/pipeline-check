"""GCCE-005. Instance does not block project-wide SSH keys."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCCE-005",
    title="Instance does not block project-wide SSH keys",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "Set the metadata key 'block-project-ssh-keys' to 'TRUE' on "
        "instances that should not accept project-level SSH keys. "
        "This limits SSH access to keys defined on the instance "
        "itself or via OS Login."
    ),
    docs_note=(
        "Project-wide SSH keys are propagated to every instance that "
        "does not explicitly block them. An attacker who can edit "
        "project metadata can inject an SSH key and access all "
        "instances that accept project keys."
    ),
    exploit_example=(
        "A Compute Engine instance leaves block-project-ssh-keys "
        "unset, so it honors every SSH key published in project "
        "metadata. An attacker who lands a credential carrying "
        "compute.projects.setCommonInstanceMetadata injects their own "
        "public key once at the project level and immediately gains "
        "SSH on this instance, and on every other instance in the "
        "project that has not opted out, turning a single "
        "metadata-write permission into shell across the fleet."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for inst in catalog.compute_instances():
        name = inst.get("name", "<unnamed>")
        metadata = inst.get("metadata", {})
        blocked = metadata.get(
            "block-project-ssh-keys", "",
        ).upper() == "TRUE"
        if blocked:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Instance '{name}' blocks project-wide SSH keys."
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
                    f"Instance '{name}' accepts project-wide SSH keys. "
                    "Any key in project metadata grants access."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
