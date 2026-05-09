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
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, has_failing, min_confidence

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


def match(findings: list[Finding]) -> list[Chain]:
    if not has_failing(findings, "ARGO-003"):
        return []
    if not has_failing(findings, "K8S-029"):
        return []
    triggers = [
        f for f in findings
        if (not f.passed) and f.check_id in {"ARGO-003", "K8S-029"}
    ]
    resources = sorted({f.resource for f in triggers})
    narrative = (
        "In this scan:\n"
        "  1. At least one Argo Workflow / WorkflowTemplate doesn't "
        "set ``spec.serviceAccountName`` (ARGO-003), so every "
        "workflow pod the workflow kicks off authenticates against "
        "the Kubernetes API as the namespace's ``default`` "
        "ServiceAccount.\n"
        "  2. A RoleBinding or ClusterRoleBinding grants verbs to "
        "the ``default`` SA (K8S-029), read Secrets, list Pods, "
        "create deployments, whatever the binding scope is.\n"
        "  3. Whoever can submit a Workflow into that namespace, "
        "a Git push to the GitOps repo, a fork-PR-triggered Argo "
        "Events sensor, a developer with ``kubectl create`` rights "
        "— runs code under those granted verbs without an explicit "
        "Workflow-side SA decision. ARGO-003 stops being a hygiene "
        "issue and becomes the authentication leg of a real "
        "privilege escalation. Fix either side: name a custom SA "
        "on the Workflow or remove the RoleBinding's grant to "
        "``default``."
    )
    return [Chain(
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
    )]
