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

Reachability-model note: this chain stays on manifest-set
co-occurrence. Confirming the bound subject (cluster-admin SA)
matches the Task's effective ``serviceAccountName`` requires the
``k8s_sa`` canonicalizer from ``ResourceAnchor`` phase 1; the
``job_anchors`` intersection pattern doesn't fit because the two
legs are independent K8s resources rather than steps in one CI
job. Defer to the cross-provider reachability work.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, has_failing, min_confidence

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


def match(findings: list[Finding]) -> list[Chain]:
    if not has_failing(findings, "TKN-004"):
        return []
    if not has_failing(findings, "K8S-020"):
        return []
    triggers = [
        f for f in findings
        if (not f.passed) and f.check_id in {"TKN-004", "K8S-020"}
    ]
    resources = sorted({f.resource for f in triggers})
    narrative = (
        "In this scan:\n"
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
        "  3. An attacker who lands a malicious Task spec (a "
        "compromised Git push, a fork PR that triggers a "
        "PipelineRun, a poisoned ClusterTask) reaches both legs at "
        "once: node-level filesystem access for persistence "
        "(static-pod backdoor, runtime-socket access) plus cluster-"
        "wide API authority for credential harvesting and lateral "
        "movement. Either fix breaks the chain."
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
        triggering_check_ids=["TKN-004", "K8S-020"],
        triggering_findings=triggers,
        resources=resources,
        references=list(RULE.references),
        recommendation=RULE.recommendation,
    )]
