"""CIS Kubernetes Benchmark v1.10, subset covering manifest-evidenceable controls.

The benchmark spans control-plane components (Sections 1-3),
worker-node configuration (Section 4), and policies (Section 5).
Sections 1-4 require kubelet / API-server / etcd configuration that
isn't visible from manifests alone. Those are out of scope for a
posture-from-YAML scanner. Section 5 (Policies) is where workload
posture lives, and it's where the K8s rule pack lands.

Sections covered here:

  - **5.1 RBAC and Service Accounts**, cluster-admin minimization,
    wildcard verbs, default-SA bindings, token automount.
  - **5.2 Pod Security Standards**, privileged, hostNamespaces,
    allowPrivilegeEscalation, runAsNonRoot, readOnlyRootFilesystem,
    capabilities, seccomp, hostPath.
  - **5.3 Network Policies and CNI**, default-deny, allow-list
    enforcement.
  - **5.4 Secrets Management**, env-mounted credentials, plaintext
    Secret data.
  - **5.7 General Policies**, namespace separation, default-namespace
    avoidance, securityContext applied broadly.

Out of scope (require non-manifest evidence):

  - 5.1.6 (system:masters group). RBAC subjects detail.
  - 5.2.10 (allowed-capabilities allowlist), admission controller
    config.
  - 5.5.x (extensible admission control), controller config.
  - 5.6.x (multi-tenancy), namespace policies + admission.

A pipeline_check finding that maps here is necessary but not
sufficient for CIS K8s alignment. The benchmark also requires
documented runbooks, audit-log retention, and ongoing review that
live outside the manifest substrate. Passing all mapped checks
identifies the configuration gaps a CIS audit would flag at
"manual investigation" prompts.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="cis_kubernetes",
    title="CIS Kubernetes Benchmark",
    version="1.10",
    url="https://www.cisecurity.org/benchmark/kubernetes",
    controls={
        # ── 5.1 RBAC and Service Accounts ────────────────────────
        "5.1.1": "Ensure that the cluster-admin role is only used where required",
        "5.1.2": "Minimize access to secrets",
        "5.1.3": "Minimize wildcard use in Roles and ClusterRoles",
        "5.1.4": "Minimize access to create pods",
        "5.1.5": "Ensure that default service accounts are not actively used",
        "5.1.6": "Ensure that Service Account Tokens are only mounted where necessary",
        "5.1.8": "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster",
        # ── 5.2 Pod Security Standards (Pod Security policy / PSA) ─
        "5.2.2": "Minimize the admission of privileged containers",
        "5.2.3": "Minimize the admission of containers wishing to share the host process ID namespace",
        "5.2.4": "Minimize the admission of containers wishing to share the host IPC namespace",
        "5.2.5": "Minimize the admission of containers wishing to share the host network namespace",
        "5.2.6": "Minimize the admission of containers with allowPrivilegeEscalation",
        "5.2.7": "Minimize the admission of root containers",
        "5.2.8": "Minimize the admission of containers with the NET_RAW capability",
        "5.2.9": "Minimize the admission of containers with added capabilities",
        "5.2.12": "Minimize the admission of HostPath volumes",
        "5.2.13": "Minimize the admission of containers which use HostPorts",
        # ── 5.3 Network Policies and CNI ─────────────────────────
        "5.3.2": "Ensure that all Namespaces have NetworkPolicies defined",
        # ── 5.4 Secrets Management ───────────────────────────────
        "5.4.1": "Prefer using Secrets as files over Secrets as environment variables",
        "5.4.2": "Consider external secret storage",
        # ── 5.7 General Policies ─────────────────────────────────
        "5.7.1": "Create administrative boundaries between resources using namespaces",
        "5.7.2": "Ensure that the seccomp profile is set to docker/default in your Pod definitions",
        "5.7.3": "Apply SecurityContext to your Pods and Containers",
        "5.7.4": "The default namespace should not be used",
    },
    mappings={
        # ── 5.1 RBAC and Service Accounts ────────────────────────
        "K8S-011":  ["5.1.5"],                                   # default ServiceAccount in workload
        "K8S-012":  ["5.1.6"],                                   # automountServiceAccountToken
        # cluster-admin = wildcard at every verb incl. pods + bind/impersonate
        "K8S-020":  ["5.1.1", "5.1.3", "5.1.4", "5.1.8"],
        # wildcard verbs sweep secrets, pod-create, bind/impersonate/escalate
        "K8S-021":  ["5.1.2", "5.1.3", "5.1.4", "5.1.8"],
        "K8S-029":  ["5.1.5"],                                   # default-SA RoleBinding
        "K8S-034":  ["5.1.6"],                                   # SA-side automount default
        "K8S-036":  ["5.1.6"],                                   # SA imagePullSecret resolves
        "K8S-042":  ["5.1.1", "5.1.2", "5.1.3", "5.1.4", "5.1.8"],  # anonymous binding = unauthenticated wildcard
        # K8S-018 / K8S-037 cover credential exposure paths that
        # implicitly bypass the "minimize access to secrets" intent —
        # if every Secret is in git or a ConfigMap holds credentials,
        # the access boundary collapses regardless of RBAC.
        "K8S-018":  ["5.1.2", "5.4.2"],                          # Secret literal in manifest
        "K8S-037":  ["5.1.2", "5.4.2"],                          # ConfigMap credential
        # ── 5.2 Pod Security Standards ───────────────────────────
        "K8S-005":  ["5.2.2", "5.7.3"],                          # privileged container (securityContext field)
        "K8S-003":  ["5.2.3"],                                   # hostPID
        "K8S-004":  ["5.2.4"],                                   # hostIPC
        "K8S-002":  ["5.2.5"],                                   # hostNetwork
        "K8S-006":  ["5.2.6", "5.7.3"],                          # allowPrivilegeEscalation (securityContext field)
        "K8S-007":  ["5.2.7", "5.7.3"],                          # runAsNonRoot (securityContext field)
        "K8S-035":  ["5.2.7", "5.7.3"],                          # runAsUser: 0 (securityContext field)
        # capabilities (NET_RAW + added caps, securityContext field)
        "K8S-009":  ["5.2.8", "5.2.9", "5.7.3"],
        "K8S-013":  ["5.2.12"],                                  # hostPath
        "K8S-014":  ["5.2.12"],                                  # sensitive hostPath
        "K8S-028":  ["5.2.13"],                                  # host port
        "K8S-022":  ["5.2.13"],                                  # SSH service host port
        # ── 5.3 NetworkPolicies ──────────────────────────────────
        "K8S-032":  ["5.3.2"],                                   # default-deny missing
        "K8S-038":  ["5.3.2"],                                   # allow-all rule (no peers)
        # ── 5.4 Secrets Management ───────────────────────────────
        # env-credential literal: env-mounted AND skips external storage
        "K8S-017":  ["5.4.1", "5.4.2"],
        # ── 5.7 General Policies ─────────────────────────────────
        "K8S-019":  ["5.7.1", "5.7.4"],                          # default namespace = no admin boundary
        "K8S-023":  ["5.7.1", "5.7.3"],                          # PSA enforce missing = no admission boundary
        "K8S-031":  ["5.7.1", "5.7.3"],                          # PSA warn missing
        "K8S-025":  ["5.7.1"],                                   # system priority class outside kube-system
        "K8S-030":  ["5.7.1"],                                   # schedules onto control-plane node
        "K8S-033":  ["5.7.1"],                                   # namespace without ResourceQuota/LimitRange
        "K8S-008":  ["5.7.3"],                                   # readOnlyRootFilesystem
        "K8S-010":  ["5.7.2", "5.7.3"],                          # seccompProfile not docker/default
        "K8S-039":  ["5.7.3"],                                   # shareProcessNamespace
        "K8S-040":  ["5.7.3"],                                   # procMount: Unmasked
    },
)
