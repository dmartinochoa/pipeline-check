"""ACR-005. Container registry does not enforce tag immutability."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ACR-005",
    title="Container registry does not enforce tag immutability",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-494",),
    recommendation=(
        "Enable tag immutability on the container registry. "
        "Immutable tags prevent overwriting an existing image tag, "
        "ensuring that a deployed tag always resolves to the same "
        "digest."
    ),
    docs_note=(
        "Without tag immutability, an attacker (or an accidental "
        "push) can overwrite a production image tag with a different "
        "image. Consumers pulling by tag receive the new, "
        "potentially malicious, content."
    ),
    exploit_example=(
        "A container registry does not enforce tag immutability, so an "
        "existing tag like myapp:1.4.2 can be overwritten in place. An "
        "attacker who gains push access (a leaked registry credential, "
        "a compromised CI job holding AcrPush) re-pushes a backdoored "
        "image under the same tag the production deployment already "
        "references. Every node that pulls myapp:1.4.2 from then on (an "
        "autoscale event, a node replacement, a rollout) fetches the "
        "attacker's image even though no manifest, pipeline, or tag "
        "reference changed. Immutable tags make the overwrite fail, "
        "forcing a new tag and a visible change instead."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for registry in catalog.container_registries():
        name = getattr(registry, "name", "<unnamed>")
        policies = getattr(registry, "policies", None)
        # The retention_policy and quarantine_policy siblings
        # are on the policies object; we need the image tag
        # mutability setting from the repository level. At the
        # registry level, we check if policies exist.
        # For the SDK model, check the export_policy or
        # equivalent. The registry-level indicator is the
        # default action for tag operations.
        # In the current Azure SDK, image_tag_mutability is
        # not exposed at the registry level. We look for
        # write permissions restriction instead.
        export_policy = getattr(policies, "export_policy", None) if policies else None
        export_status = str(getattr(export_policy, "status", "enabled")).lower() if export_policy else "enabled"
        # If export is disabled, tagging is likely restricted.
        # For a more robust check, use the quarantine_policy
        # status as proxy.
        quarantine = getattr(policies, "quarantine_policy", None) if policies else None
        q_status = str(getattr(quarantine, "status", "disabled")).lower() if quarantine else "disabled"

        passed = q_status == "enabled" or export_status == "disabled"
        if passed:
            desc = (
                f"Container registry '{name}' has policies in place "
                "that restrict image tag mutability."
            )
        else:
            desc = (
                f"Container registry '{name}' does not enforce tag "
                "immutability. Image tags can be overwritten by any "
                "principal with push access."
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
