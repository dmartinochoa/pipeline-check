"""ACR-005. Container registry does not enforce tag immutability."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ACR-005",
    title="Container registry tag immutability (verify per-repository locking)",
    severity=Severity.INFO,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-494",),
    recommendation=(
        "Azure Container Registry has no registry-level tag-immutability "
        "toggle. Immutability is enforced per repository / tag by "
        "write-locking: ``az acr repository update --image "
        "<repo>:<tag> --write-enabled false`` (or ``--repository "
        "<repo>``) prevents an existing tag from being overwritten. "
        "Lock critical production tags, and/or reference images by "
        "digest (``@sha256:...``) so a deployment always resolves to "
        "the same content regardless of tag mutability."
    ),
    docs_note=(
        "Advisory (INFO), always passes. Unlike ECR's registry-level "
        "``imageTagMutability``, ACR exposes no tag-immutability setting "
        "on the registry; immutability is a per-repository / per-tag "
        "``writeEnabled=false`` lock applied through the data plane. A "
        "registry-level posture scan cannot enumerate those locks "
        "(it would need data-plane auth and a per-repository walk), so "
        "this rule does not assert a pass/fail verdict. It surfaces the "
        "recommendation, lock critical tags and pin by digest, as a "
        "reminder. (The prior MEDIUM check inferred immutability from "
        "the quarantine / export policy, an unrelated proxy that both "
        "false-positived on default registries and false-negatived on "
        "mutable ones.)"
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
    # Advisory only. ACR has no registry-level tag-immutability setting to
    # read (it's a per-repository / per-tag ``writeEnabled=false`` lock in
    # the data plane), so this emits an informational, always-passing
    # finding per registry that carries the recommendation rather than a
    # verdict inferred from an unrelated policy. See the rule's docs_note.
    findings: list[Finding] = []
    for registry in catalog.container_registries():
        name = getattr(registry, "name", "<unnamed>")
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=name,
            description=(
                f"Container registry '{name}': tag immutability is not a "
                "registry-level setting in ACR. Verify that critical "
                "production tags are write-locked "
                "(``writeEnabled=false``) and/or referenced by digest; a "
                "registry-level scan cannot enumerate per-repository locks."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        ))
    return findings
