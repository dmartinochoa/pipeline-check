"""AC-011 — Kubernetes Cluster Takeover via hostPath + cluster-admin.

A workload that mounts a hostPath volume escapes to the node
filesystem on every reschedule. Once on the node, kubelet's TLS keys
and the static pod manifests under ``/etc/kubernetes`` are readable
to root processes; mounting ``/`` or ``/var/lib/kubelet`` drops the
attacker squarely on the path to the control plane.

Pair that with a ClusterRoleBinding granting ``cluster-admin`` to a
broad subject (a user group, a default SA, a token) and the attacker
has both the box-level access (hostPath) and the API-level authority
(cluster-admin) to pivot anywhere in the cluster — read every Secret,
mint additional bindings, deploy privileged DaemonSets across nodes,
or impersonate any account.

The chain fires when both K8S-013 (hostPath volume) and K8S-020
(cluster-admin binding) are present in the same manifest set.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, has_failing, min_confidence

RULE = ChainRule(
    id="AC-011",
    title="Kubernetes Cluster Takeover via hostPath + cluster-admin",
    severity=Severity.CRITICAL,
    summary=(
        "A workload mounts a hostPath volume (K8S-013) AND the cluster "
        "carries a ClusterRoleBinding granting cluster-admin (K8S-020). "
        "Together those two settings give an attacker who lands code "
        "in any pod on a poisoned node both an escape to the host "
        "filesystem and the API privileges needed to pivot the entire "
        "cluster — read every Secret, deploy privileged workloads "
        "across all nodes, impersonate any service account."
    ),
    mitre_attack=(
        "T1611",      # Escape to Host
        "T1098.003",  # Account Manipulation: Additional Cloud Roles
        "T1078",      # Valid Accounts
    ),
    kill_chain_phase="initial-access -> privilege-escalation -> lateral-movement",
    references=(
        "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",
        "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
        "https://www.cncf.io/blog/2024/04/29/the-dangerous-cluster-admin/",
    ),
    recommendation=(
        "Replace hostPath volumes with a CSI driver scoped to the "
        "specific subtree the workload needs, or use ConfigMap / "
        "downwardAPI volumes for non-storage cases. Audit "
        "ClusterRoleBindings: cluster-admin should be reserved for a "
        "narrow human-operator group with break-glass access — never "
        "bound to a ServiceAccount or a broad ``Group``. Even with "
        "hostPath in place, removing the cluster-admin grant breaks "
        "the API-pivot leg of this chain."
    ),
    providers=("kubernetes",),
)


def match(findings: list[Finding]) -> list[Chain]:
    if not has_failing(findings, "K8S-013"):
        return []
    if not has_failing(findings, "K8S-020"):
        return []
    triggers = [
        f for f in findings
        if (not f.passed) and f.check_id in {"K8S-013", "K8S-020"}
    ]
    resources = sorted({f.resource for f in triggers})
    narrative = (
        "In this Kubernetes manifest set:\n"
        "  1. At least one workload mounts a ``hostPath`` volume "
        "(K8S-013). On every node where that pod can land, processes "
        "inside the container read and write the node filesystem "
        "directly — kubelet credentials at "
        "``/var/lib/kubelet/pki/``, static pod manifests at "
        "``/etc/kubernetes/manifests/``, the container runtime "
        "socket, all reachable.\n"
        "  2. A ClusterRoleBinding grants ``cluster-admin`` to a "
        "broad subject (K8S-020). Anyone who can authenticate as a "
        "member of that subject — or anyone who can mint a token "
        "from a default ServiceAccount the binding covers — has "
        "unrestricted API access.\n"
        "  3. An attacker who lands code in a pod with the hostPath "
        "and authenticates against the API as the cluster-admin "
        "subject combines node-level escape with cluster-wide "
        "authority. They can plant a backdoor in a static pod "
        "manifest (persistence), enumerate every Secret in every "
        "namespace (credential access), or replace the cluster's "
        "DaemonSets to deploy attacker code on every node (lateral "
        "movement)."
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
        triggering_check_ids=["K8S-013", "K8S-020"],
        triggering_findings=triggers,
        resources=resources,
        references=list(RULE.references),
        recommendation=RULE.recommendation,
    )]
