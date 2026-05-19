"""AC-021. Argo default-SA workflow lands in a namespace where the
default SA has a RoleBinding.

Two findings that are each individually wrong but become a concrete
privilege-escalation primitive together:

- **ARGO-003.** The Argo Workflow doesn't set
  ``spec.serviceAccountName``, so it runs under the namespace's
  ``default`` ServiceAccount.

- **K8S-029.** A RoleBinding (or ClusterRoleBinding) grants
  permissions to that ``default`` ServiceAccount. The binding may
  look innocuous in isolation, a CI namespace that reads a
  ConfigMap, an integration namespace that lists Pods, but each
  verb the binding grants becomes part of the workflow's authority.

Combined: anyone who can submit a Workflow (a Git push to the
GitOps repo, a fork PR that triggers an Argo Events sensor, a
direct ``kubectl create`` from a developer with namespace access)
runs code under whatever permissions the default-SA RoleBinding
provides. ARGO-003 alone says "use a custom SA"; K8S-029 alone
says "don't bind perms to the default SA"; the combination is
where the default-SA path becomes a credentials-laundering
shortcut into the cluster API.

The chain fires when both findings appear in the same scan, even
across separate Argo and Kubernetes manifest sets, the cluster
configuration is what matters, not which file declares it.

ResourceAnchor phase 1: prefers a confirmed pairing when the
Workflow's namespace AND the default SA the RoleBinding grants
to are the same ``<namespace>/default``. ARGO-003 emits one
``k8s_sa`` anchor per offending Workflow (the (namespace,
"default") pair the workflow effectively runs as); K8S-029 emits
one ``k8s_sa`` anchor per (namespace, "default") subject the
binding grants. ``group_by_anchor`` on ``k8s_sa`` matches them.
Confirmed → ``confirmed_reachable=True``, ``Confidence.HIGH``,
narrative cites the shared namespace+SA, that pair is the chain
resource. Falls back to scan-level co-occurrence when the
Workflow's namespace doesn't match any namespace where the
default SA has a binding (the chain's broader "any
default-SA workflow + any default-SA binding somewhere" warning
remains useful as a hygiene prompt but doesn't represent a
single-execution-context escalation).
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_anchor, has_failing, min_confidence

RULE = ChainRule(
    id="AC-021",
    title="Argo default-SA workflow lands on a default-SA RoleBinding",
    severity=Severity.HIGH,
    summary=(
        "An Argo Workflow runs as the namespace default ServiceAccount "
        "(ARGO-003) AND a RoleBinding grants permissions to that "
        "default SA (K8S-029). Anyone who can submit a Workflow into "
        "the namespace runs code under whatever verbs the binding "
        "grants, turning ARGO-003 from a hygiene gap into a concrete "
        "privilege-escalation primitive."
    ),
    mitre_attack=(
        "T1078",      # Valid Accounts
        "T1098.003",  # Account Manipulation: Additional Cloud Roles
    ),
    kill_chain_phase="initial-access -> privilege-escalation",
    references=(
        "https://kubernetes.io/docs/concepts/security/rbac-good-practices/#default-service-account",
        "https://argo-workflows.readthedocs.io/en/latest/service-accounts/",
        "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
    ),
    recommendation=(
        "On the Argo side: set ``spec.serviceAccountName: "
        "<workflow-runner>`` on every Workflow / WorkflowTemplate "
        "and bind that SA to a least-privilege Role. On the "
        "Kubernetes side: never grant verbs to ``default``, every "
        "RoleBinding's ``subjects`` should name a workflow-specific "
        "SA. The fix on either side breaks the chain. Best is both: "
        "explicit per-workflow SAs across every namespace, plus "
        "deny rules / OPA policies that block any RoleBinding "
        "subject named ``default`` at admission time."
    ),
    providers=("argo", "kubernetes"),
    triggering_check_ids=("ARGO-003", "K8S-029"),
)


def _base_narrative() -> str:
    return (
        "  1. At least one Argo Workflow / WorkflowTemplate doesn't "
        "set ``spec.serviceAccountName`` (ARGO-003), so every "
        "workflow pod the workflow kicks off authenticates against "
        "the Kubernetes API as the namespace's ``default`` "
        "ServiceAccount.\n"
        "  2. A RoleBinding or ClusterRoleBinding grants verbs to "
        "the ``default`` SA (K8S-029), read Secrets, list Pods, "
        "create deployments, whatever the binding scope is.\n"
    )


def match(findings: list[Finding]) -> list[Chain]:
    # ResourceAnchor phase 1: confirmed pairing when the Workflow's
    # namespace matches a namespace where the default SA has a
    # RoleBinding (k8s_sa identity ``<namespace>/default``).
    # group_by_anchor on k8s_sa intersects ARGO-003 + K8S-029.
    by_sa = group_by_anchor(findings, ["ARGO-003", "K8S-029"], "k8s_sa")
    out: list[Chain] = []
    matched_findings: set[int] = set()
    for sa_identity, ck_map in by_sa.items():
        argo003 = ck_map["ARGO-003"]
        k8s029 = ck_map["K8S-029"]
        triggers = [argo003, k8s029]
        matched_findings.add(id(argo003))
        matched_findings.add(id(k8s029))
        narrative = (
            f"For ServiceAccount `{sa_identity}`:\n"
            + _base_narrative()
            + f"  3. Reachability confirmed: an Argo Workflow runs as "
            f"`{sa_identity}` AND a binding in the same namespace "
            f"grants verbs to that same `default` SA. Whoever can "
            f"submit a Workflow into the namespace runs code under "
            f"those granted verbs in one go, no separate "
            f"authentication step required."
        )
        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=Confidence.HIGH,
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=["ARGO-003", "K8S-029"],
            triggering_findings=triggers,
            resources=[sa_identity],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=True,
            reachability_note=(
                f"Argo Workflow runs as `{sa_identity}`, a "
                f"RoleBinding subject in the same namespace"
            ),
        ))

    # Co-occurrence fallback: ARGO-003 and K8S-029 fire in different
    # namespaces (the workflow's default SA isn't the SA the binding
    # targets). The chain is weaker but still worth surfacing as a
    # hygiene prompt — workflows using the default SA pattern remain
    # a privilege-escalation accident waiting for a future binding.
    if has_failing(findings, "ARGO-003") and has_failing(findings, "K8S-029"):
        unmatched = [
            f for f in findings
            if (not f.passed)
            and f.check_id in {"ARGO-003", "K8S-029"}
            and id(f) not in matched_findings
        ]
        unmatched_legs = {f.check_id for f in unmatched}
        if "ARGO-003" in unmatched_legs and "K8S-029" in unmatched_legs:
            triggers = unmatched
            resources = sorted({f.resource for f in triggers})
            narrative = (
                "In this scan:\n"
                + _base_narrative()
                + "  3. Reachability unconfirmed: the Argo Workflow's "
                "namespace and the namespace(s) where the default SA "
                "has a binding don't overlap. The chain remains a "
                "hygiene prompt — a future binding in the workflow's "
                "namespace, or a future workflow in the binding's "
                "namespace, would close the loop. Fix either side."
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
                triggering_check_ids=["ARGO-003", "K8S-029"],
                triggering_findings=triggers,
                resources=resources,
                references=list(RULE.references),
                recommendation=RULE.recommendation,
                confirmed_reachable=False,
                reachability_note="",
            ))
    return out
