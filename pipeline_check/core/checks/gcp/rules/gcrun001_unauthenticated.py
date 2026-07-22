"""GCRUN-001. Cloud Run service allows unauthenticated access."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCRUN-001",
    title="Cloud Run service allows unauthenticated access",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Remove the ``allUsers`` / ``allAuthenticatedUsers`` binding "
        "from the service's ``roles/run.invoker`` grant so only named "
        "identities can invoke it "
        "(``gcloud run services remove-iam-policy-binding <svc> "
        "--member=allUsers --role=roles/run.invoker``). If the service "
        "is genuinely meant to be public, front it with a load balancer "
        "plus IAP or API Gateway that enforces authentication, rather "
        "than exposing the run.invoker endpoint directly."
    ),
    docs_note=(
        "Reads the service's IAM policy and fires when "
        "``roles/run.invoker`` is granted to ``allUsers`` or "
        "``allAuthenticatedUsers`` — the bindings that let anyone (or "
        "any Google account) invoke the service without service-"
        "specific authorization. Ingress settings are a separate "
        "network-exposure control and are NOT what this rule checks: an "
        "``INGRESS_TRAFFIC_ALL`` service that still requires IAM auth is "
        "not unauthenticated. When the IAM policy can't be read (the "
        "token lacks ``run.services.getIamPolicy``) the service is not "
        "flagged."
    ),
    exploit_example=(
        "An attacker discovers a Cloud Run service URL. The service has "
        "``roles/run.invoker`` bound to ``allUsers``, so the request is "
        "accepted with no credentials, and the service exposes an "
        "internal admin API, letting the attacker read and modify "
        "application data."
    ),
)

#: IAM members that mean "no service-specific authentication".
_PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})
#: The invoke role, with and without the ``roles/`` prefix.
_INVOKER_ROLES = frozenset({"roles/run.invoker", "run.invoker"})


def _public_invokers(bindings: Any) -> list[str]:
    """Return the public members granted the invoker role, if any."""
    out: list[str] = []
    if not isinstance(bindings, list):
        return out
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        if binding.get("role") not in _INVOKER_ROLES:
            continue
        members = binding.get("members")
        if not isinstance(members, list):
            continue
        out.extend(m for m in members if m in _PUBLIC_MEMBERS)
    return out


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for svc in catalog.cloud_run_services():
        name = svc.get("name", "<unnamed>")
        public = _public_invokers(svc.get("iam_policy"))
        if public:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Cloud Run service '{name}' grants roles/run.invoker "
                    f"to {', '.join(sorted(set(public)))}; it accepts "
                    "requests with no service-specific authentication."
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
                    f"Cloud Run service '{name}' requires IAM "
                    "authentication (no allUsers/allAuthenticatedUsers "
                    "run.invoker binding)."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
