"""ACR-002. Container registry allows public network access."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ACR-002",
    title="Container registry allows public network access",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Disable public network access on the container registry and "
        "use private endpoints or service endpoints for access from "
        "CI/CD pipelines and deployment targets."
    ),
    docs_note=(
        "A publicly accessible registry exposes the authentication "
        "endpoint to brute-force attempts and the image catalog to "
        "enumeration. Private endpoints restrict access to the VNet."
    ),
    exploit_example=(
        "The registry's authentication endpoint is reachable from the "
        "internet. An attacker enumerates the image catalog to map the "
        "deployment, then brute-forces the registry credentials; on "
        "success they push a backdoored tag that the next deployment "
        "pulls and runs."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for registry in catalog.container_registries():
        name = getattr(registry, "name", "<unnamed>")
        public_access = getattr(registry, "public_network_access", "Enabled")
        # A registry that keeps public access "Enabled" but sets a
        # network_rule_set default_action of "Deny" (with explicit
        # allow-listed IPs/VNets) is a restricted deployment, not
        # internet-open (mirrors how AKV-003 reads the default action).
        nrs = getattr(registry, "network_rule_set", None)
        default_action = (
            str(getattr(nrs, "default_action", "")).lower() if nrs else ""
        )
        passed = (
            str(public_access).lower() == "disabled"
            or default_action == "deny"
        )
        if passed:
            desc = (
                f"Container registry '{name}' has public network "
                "access disabled."
            )
        else:
            desc = (
                f"Container registry '{name}' allows public network "
                "access. The registry endpoint is reachable from the "
                "internet."
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
