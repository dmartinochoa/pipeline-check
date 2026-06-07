"""AC-011. Kubernetes Cluster Takeover via hostPath + cluster-admin.

A workload that mounts a hostPath volume escapes to the node
filesystem on every reschedule. Once on the node, kubelet's TLS keys
and the static pod manifests under ``/etc/kubernetes`` are readable
to root processes; mounting ``/`` or ``/var/lib/kubelet`` drops the
attacker squarely on the path to the control plane.

Pair that with a ClusterRoleBinding granting ``cluster-admin`` to a
broad subject (a user group, a default SA, a token) and the attacker
has both the box-level access (hostPath) and the API-level authority
(cluster-admin) to pivot anywhere in the cluster, read every Secret,
mint additional bindings, deploy privileged DaemonSets across nodes,
or impersonate any account.

The chain fires when both K8S-013 (hostPath volume) and K8S-020
(cluster-admin binding) are present in the same manifest set.

ResourceAnchor phase 1: prefers a confirmed pairing when the
hostPath-mounting pod's effective ``serviceAccountName`` IS the
ServiceAccount subject of a cluster-admin binding (same
``<namespace>/<name>``). K8S-013 emits one ``k8s_sa`` anchor per
offending workload (``serviceAccountName`` falls back to the
namespace's ``default`` SA, matching kubelet semantics); K8S-020
emits one ``k8s_sa`` anchor per cluster-admin binding's
ServiceAccount subject. ``group_by_anchor`` on ``k8s_sa`` matches
them. Each matched SA composes ONE confirmed chain with
``confirmed_reachable=True``, ``Confidence.HIGH``, narrative citing
the shared SA, and that SA identity as the chain resource. Falls
back to scan-level co-occurrence when no anchor matches (the
hostPath pod runs as one SA, the cluster-admin binding targets a
different one) so the "any node-escape + any cluster-admin
binding" signal — still meaningful even without the SA pairing —
survives.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_anchor, has_failing, min_confidence

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
        "cluster, read every Secret, deploy privileged workloads "
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
        "narrow human-operator group with break-glass access, never "
        "bound to a ServiceAccount or a broad ``Group``. Even with "
        "hostPath in place, removing the cluster-admin grant breaks "
        "the API-pivot leg of this chain."
    ),
    providers=("kubernetes",),
    triggering_check_ids=("K8S-013", "K8S-020"),
)


def _base_narrative() -> str:
    return (
        "  1. At least one workload mounts a ``hostPath`` volume "
        "(K8S-013). On every node where that pod can land, processes "
        "inside the container read and write the node filesystem "
        "directly, kubelet credentials at "
        "``/var/lib/kubelet/pki/``, static pod manifests at "
        "``/etc/kubernetes/manifests/``, the container runtime "
        "socket, all reachable.\n"
        "  2. A ClusterRoleBinding grants ``cluster-admin`` to a "
        "broad subject (K8S-020). Anyone who can authenticate as a "
        "member of that subject, or anyone who can mint a token "
        "from a default ServiceAccount the binding covers, has "
        "unrestricted API access.\n"
    )


def match(findings: list[Finding]) -> list[Chain]:
    # ResourceAnchor phase 1: confirmed pairing when the hostPath
    # workload's effective SA IS a subject of the cluster-admin
    # binding. group_by_anchor on k8s_sa intersects K8S-013's
    # workload-SA anchors with K8S-020's subject-SA anchors.
    by_sa = group_by_anchor(findings, ["K8S-013", "K8S-020"], "k8s_sa")
    out: list[Chain] = []
    matched_findings: set[int] = set()
    for sa_identity, ck_map in by_sa.items():
        k8s013 = ck_map["K8S-013"]
        k8s020 = ck_map["K8S-020"]
        triggers = [k8s013, k8s020]
        matched_findings.add(id(k8s013))
        matched_findings.add(id(k8s020))
        narrative = (
            f"For ServiceAccount `{sa_identity}`:\n"
            + _base_narrative()
            + f"  3. Reachability confirmed: the hostPath-mounting "
            f"workload runs as `{sa_identity}`, which is also a "
            f"subject of a cluster-admin ClusterRoleBinding. The "
            f"compromised pod's projected token already authenticates "
            f"as cluster-admin, so node escape and cluster-API takeover "
            f"are a single execution context, no separate token-theft "
            f"step required."
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
            triggering_check_ids=["K8S-013", "K8S-020"],
            triggering_findings=triggers,
            resources=[sa_identity],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=True,
            via_structural=True,
            reachability_note=(
                f"hostPath workload runs as cluster-admin-bound SA "
                f"`{sa_identity}`"
            ),
        ))

    # Co-occurrence fallback: the hostPath workload runs as a
    # different SA than the binding targets (or one of the legs
    # didn't emit anchors — Group/User subjects on K8S-020, missing
    # podspec, etc.). The original "any node-escape + any
    # cluster-admin grant" signal still applies because the attacker
    # who escapes the node has alternative paths to cluster-admin
    # credentials (kubelet credentials, other pods' projected tokens,
    # static pod manifests).
    if has_failing(findings, "K8S-013") and has_failing(findings, "K8S-020"):
        unmatched = [
            f for f in findings
            if (not f.passed)
            and f.check_id in {"K8S-013", "K8S-020"}
            and id(f) not in matched_findings
        ]
        unmatched_legs = {f.check_id for f in unmatched}
        if "K8S-013" in unmatched_legs and "K8S-020" in unmatched_legs:
            triggers = unmatched
            resources = sorted({f.resource for f in triggers})
            narrative = (
                "In this Kubernetes manifest set:\n"
                + _base_narrative()
                + "  3. Reachability unconfirmed: the hostPath workload "
                "and the cluster-admin binding don't share a "
                "ServiceAccount subject in this manifest set. The "
                "attacker who escapes the node still has alternative "
                "paths to cluster-admin (reading other pods' "
                "projected tokens off the node filesystem, harvesting "
                "kubelet credentials), so the chain remains a "
                "co-occurrence signal worth surfacing."
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
                triggering_check_ids=["K8S-013", "K8S-020"],
                triggering_findings=triggers,
                resources=resources,
                references=list(RULE.references),
                recommendation=RULE.recommendation,
                confirmed_reachable=False,
                reachability_note="",
            ))
    return out
