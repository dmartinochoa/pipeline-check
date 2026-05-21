"""AC-030. Argo CD anonymous access meets wildcard RBAC.

The two halves of a zero-auth takeover of the Argo CD control plane:

  * ``ARGOCD-009`` — ``argocd-cm`` sets
    ``users.anonymous.enabled: "true"``. The Argo CD UI / API
    answers requests carrying no token, routing them to the
    anonymous principal.
  * ``ARGOCD-004`` — ``argocd-rbac-cm`` carries at least one
    wildcard authority grant: a ``p, <role>, *, *, *, allow`` line,
    an ``applications, *, */*, allow`` policy, or a
    ``g, <subject>, role:admin`` binding.

ARGOCD-009 alone says "anyone can reach the API without auth";
ARGOCD-004 alone says "the RBAC matrix has a hole." The
combination is the takeover primitive, the anonymous principal
inherits whatever the default role + wildcard policy collectively
grant. If ``policy.default: role:admin`` is the active default
(or the wildcard policy targets ``role:readonly``, which anonymous
falls under by default), anonymous holds cluster-admin authority
through Argo CD's sync engine, the manifests it applies, and
every credential the application controllers can read.

This chain doesn't migrate to the ``job_anchors`` intersection
model. ARGOCD-009 and ARGOCD-004 fire on separate ConfigMaps
(``argocd-cm`` vs ``argocd-rbac-cm``) but always against the same
logical resource, the Argo CD instance whose namespace they ship
into. Both rules emit ``resource="argocd"``, so per-resource
co-occurrence IS the reachability claim.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-030",
    title="Argo CD anonymous access meets wildcard RBAC",
    severity=Severity.CRITICAL,
    summary=(
        "``argocd-cm`` enables anonymous access (ARGOCD-009) AND "
        "``argocd-rbac-cm`` carries at least one wildcard or "
        "``role:admin`` grant (ARGOCD-004). The combination collapses "
        "to a zero-auth control-plane takeover, an unauthenticated "
        "caller routes through the anonymous principal into the "
        "broad RBAC grant and drives Argo CD's sync engine, the "
        "manifests it applies, and every credential its application "
        "controllers can read."
    ),
    mitre_attack=(
        "T1190",      # Exploit Public-Facing Application
        "T1078.001",  # Valid Accounts: Default Accounts
        "T1098.003",  # Account Manipulation: Additional Cloud Roles
    ),
    kill_chain_phase=(
        "initial-access -> privilege-escalation -> impact"
    ),
    references=(
        "https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/",
        "https://argo-cd.readthedocs.io/en/stable/operator-manual/"
        "security_considerations/",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-02-Inadequate-Identity-and-Access-Management",
    ),
    recommendation=(
        "Break either leg, both is best:\n"
        "  1. Disable anonymous access (ARGOCD-009). Remove the "
        "``users.anonymous.enabled`` key from ``argocd-cm`` or set "
        "it to ``\"false\"``. With anonymous off, any wildcard grant "
        "in ``argocd-rbac-cm`` still requires an authenticated "
        "subject before it can be exercised.\n"
        "  2. Scope the RBAC policy (ARGOCD-004). Replace ``p, "
        "<role>, *, *, *, allow`` and ``g, <subject>, role:admin`` "
        "with explicit per-resource per-project grants tied to a "
        "named SSO group. Set ``policy.default`` to a deny / "
        "least-privilege role rather than leaving it implicit.\n"
        "If anonymous access is a deliberate design choice (e.g. a "
        "read-only public dashboard), the RBAC matrix MUST hold no "
        "wildcard / admin grants and ``policy.default`` must be the "
        "narrowest role the dashboard's use case allows."
    ),
    providers=("argocd",),
    triggering_check_ids=("ARGOCD-009", "ARGOCD-004"),
)


def match(findings: list[Finding]) -> list[Chain]:
    """Match when both legs fail against the same Argo CD instance.

    Both ``ARGOCD-009`` and ``ARGOCD-004`` emit ``resource="argocd"``
    on the Argo CD instance they scanned; ``group_by_resource``
    yields one ``{ck_map}`` per instance that satisfies both legs.
    A multi-instance scan (one operator overseeing several Argo CD
    deployments) produces one chain per instance.
    """
    grouped = group_by_resource(findings, ["ARGOCD-009", "ARGOCD-004"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        anon = ck_map["ARGOCD-009"]
        rbac = ck_map["ARGOCD-004"]
        triggers = [anon, rbac]
        narrative = (
            f"On Argo CD instance `{resource}`:\n"
            f"  1. ``argocd-cm`` enables anonymous access "
            f"(ARGOCD-009). Any caller reaching the API server "
            f"with no bearer token is routed to the anonymous "
            f"principal; whatever role + policy stack the "
            f"anonymous user resolves to is the authority that "
            f"request runs under.\n"
            f"  2. ``argocd-rbac-cm`` carries at least one "
            f"wildcard or ``role:admin`` grant (ARGOCD-004). The "
            f"RBAC matrix has a path that resolves to broad "
            f"authority, either a ``p, <role>, *, *, *, allow`` "
            f"line, an ``applications, *, */*, allow`` policy, "
            f"or a ``g, <subject>, role:admin`` binding.\n"
            f"  3. Composite: the anonymous principal inherits the "
            f"wildcard grant via the role it lands under "
            f"(``policy.default`` if set to ``role:admin``, "
            f"``role:readonly`` widened by a ``*, *, *, allow`` "
            f"line, or any group binding anonymous traffic "
            f"matches). The result is unauthenticated control-"
            f"plane authority, Argo CD's sync engine can apply "
            f"arbitrary manifests, sync any Application, and read "
            f"every credential the application controller holds. "
            f"Fix either leg to break the chain."
        )
        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=min_confidence(triggers),
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=["ARGOCD-009", "ARGOCD-004"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
