"""AC-020. Tekton Task with hostPath meets cluster-admin RBAC.

Tekton TaskRuns execute inside the cluster. When a Task mounts a
``hostPath`` volume (TKN-004), every step in that Task can read /
write the node filesystem, kubelet TLS keys at
``/var/lib/kubelet/pki/``, the container runtime socket, static
pod manifests under ``/etc/kubernetes/manifests/``.

When the same cluster also carries a ``ClusterRoleBinding``
granting ``cluster-admin`` to a broad subject (K8S-020), a
service account, a default group, a token, the build pipeline
has both legs of cluster takeover: node-level filesystem access
through the hostPath escape AND the API authority to impersonate
any account, read every Secret, replace DaemonSets across nodes,
or plant a backdoor in a static pod manifest for persistence.

This is the Tekton-layer mirror of AC-011 (which fires on plain
``Pod`` / ``Deployment`` workloads with the same two legs). The
shape is the same, but the entry point shifts from "any pod that
runs in the cluster" to "any TaskRun the build pipeline kicks
off", a much more frequently changing surface that ships with
every PR.

ResourceAnchor phase 1: prefers a confirmed pairing when the
Task explicitly pins ``spec.podTemplate.serviceAccountName`` to a
ServiceAccount that's also a subject of a cluster-admin
ClusterRoleBinding (same ``<namespace>/<name>`` via the
``k8s_sa`` canonicalizer). TKN-004 emits an anchor only when the
Task pins an SA explicitly — Tekton's runtime SA is normally
chosen by the TaskRun (not visible in the Task manifest), so
guessing ``default`` would over-confirm. Tasks without an
explicit pin fall through to the co-occurrence fallback, which
preserves the original signal ("any node-escape Task + any
cluster-admin binding") since the attacker who escapes the node
has alternative paths to cluster-admin credentials regardless.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_anchor, has_failing, min_confidence

RULE = ChainRule(
    id="AC-020",
    title="Tekton hostPath build workload meets cluster-admin RBAC",
    severity=Severity.CRITICAL,
    summary=(
        "A Tekton Task mounts a hostPath volume or shares host "
        "namespaces (TKN-004) AND the cluster carries a "
        "ClusterRoleBinding granting cluster-admin (K8S-020). "
        "Anyone who can land code in a TaskRun has both an escape "
        "to the host filesystem and the API privileges needed to "
        "pivot the entire cluster, read every Secret, deploy "
        "privileged workloads across all nodes, impersonate any "
        "service account."
    ),
    mitre_attack=(
        "T1611",      # Escape to Host
        "T1098.003",  # Account Manipulation: Additional Cloud Roles
        "T1078",      # Valid Accounts
    ),
    kill_chain_phase="initial-access -> privilege-escalation -> lateral-movement",
    references=(
        "https://tekton.dev/docs/pipelines/tasks/#configuring-volumes",
        "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
        "https://tekton.dev/docs/pipelines/auth/",
    ),
    recommendation=(
        "Replace the Task's ``hostPath`` volume with a Workspace "
        "(``workspaces`` declaration + per-TaskRun ``persistentVolumeClaim`` "
        "/ ``emptyDir`` binding). Tekton's native shape for sharing "
        "files between steps without exposing the node filesystem. "
        "Audit cluster ``ClusterRoleBindings``: cluster-admin should "
        "be reserved for a narrow human-operator group with break-"
        "glass access, never bound to a ServiceAccount or a broad "
        "Group. Even with hostPath in place, removing the cluster-"
        "admin grant breaks the API-pivot leg of this chain."
    ),
    providers=("tekton", "kubernetes"),
    triggering_check_ids=("TKN-004", "K8S-020"),
)


def _base_narrative() -> str:
    return (
        "  1. A Tekton Task mounts a hostPath volume or shares a "
        "host namespace (TKN-004). Every step in that Task, and "
        "every TaskRun that references it, runs with read/write "
        "access to the node filesystem. ``/var/lib/kubelet/pki/`` "
        "(kubelet TLS keys), ``/etc/kubernetes/manifests/`` (static "
        "pod definitions), and the container runtime socket are "
        "all reachable.\n"
        "  2. A ClusterRoleBinding in the cluster grants cluster-"
        "admin to a broad subject (K8S-020). Anyone authenticating "
        "as a member of that subject, or anyone with a token from "
        "a default ServiceAccount the binding covers, has "
        "unrestricted API access.\n"
    )


def match(findings: list[Finding]) -> list[Chain]:
    # ResourceAnchor phase 1: confirmed pairing when the Task pins
    # serviceAccountName to a ServiceAccount that's also a subject
    # of a cluster-admin binding. Only Tasks with an explicit
    # podTemplate.serviceAccountName carry anchors (Tekton's runtime
    # SA is normally TaskRun-determined); unanchored Tasks fall
    # through to co-occurrence.
    by_sa = group_by_anchor(findings, ["TKN-004", "K8S-020"], "k8s_sa")
    out: list[Chain] = []
    matched_findings: set[int] = set()
    for sa_identity, ck_map in by_sa.items():
        tkn004 = ck_map["TKN-004"]
        k8s020 = ck_map["K8S-020"]
        triggers = [tkn004, k8s020]
        matched_findings.add(id(tkn004))
        matched_findings.add(id(k8s020))
        narrative = (
            f"For ServiceAccount `{sa_identity}`:\n"
            + _base_narrative()
            + f"  3. Reachability confirmed: the Tekton Task pins "
            f"``podTemplate.serviceAccountName`` to `{sa_identity}`, "
            f"which is also a subject of a cluster-admin "
            f"ClusterRoleBinding. The TaskRun's pod runs with "
            f"node-filesystem access AND cluster-admin API authority "
            f"in one execution context."
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
            triggering_check_ids=["TKN-004", "K8S-020"],
            triggering_findings=triggers,
            resources=[sa_identity],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=True,
            via_structural=True,
            reachability_note=(
                f"Tekton Task pins SA `{sa_identity}`, a cluster-admin "
                f"binding subject"
            ),
        ))

    # Co-occurrence fallback: TKN-004's Task didn't pin an SA (the
    # common case — Tekton TaskRuns choose the SA), or the binding's
    # subject SA differs from the Task's pin. The original "any
    # hostPath Task + any cluster-admin binding" signal still
    # applies because an attacker who lands a malicious Task spec
    # gets node escape regardless of the runtime SA, and credentials
    # for cluster-admin are sitting on the node in other pods'
    # projected tokens.
    if has_failing(findings, "TKN-004") and has_failing(findings, "K8S-020"):
        unmatched = [
            f for f in findings
            if (not f.passed)
            and f.check_id in {"TKN-004", "K8S-020"}
            and id(f) not in matched_findings
        ]
        unmatched_legs = {f.check_id for f in unmatched}
        if "TKN-004" in unmatched_legs and "K8S-020" in unmatched_legs:
            triggers = unmatched
            resources = sorted({f.resource for f in triggers})
            narrative = (
                "In this scan:\n"
                + _base_narrative()
                + "  3. Reachability unconfirmed: the Tekton Task "
                "doesn't pin a podTemplate.serviceAccountName (or "
                "its pin differs from the cluster-admin binding's "
                "subject). The runtime SA comes from the TaskRun, "
                "which isn't visible in the manifest set. An attacker "
                "who lands a malicious Task spec still escapes the "
                "node, and node escape opens alternative paths to "
                "cluster-admin credentials regardless of the TaskRun's "
                "configured SA, so the chain remains a co-occurrence "
                "signal worth surfacing."
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
                triggering_check_ids=["TKN-004", "K8S-020"],
                triggering_findings=triggers,
                resources=resources,
                references=list(RULE.references),
                recommendation=RULE.recommendation,
                confirmed_reachable=False,
                reachability_note="",
            ))
    return out
