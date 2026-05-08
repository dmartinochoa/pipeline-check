# CIS Kubernetes Benchmark (Section 5 subset)

- **Version:** 1.10
- **URL:** https://www.cisecurity.org/benchmark/kubernetes
- **Scope:** Section 5 (Policies) — workload-manifest controls
  evidenceable from `Deployment` / `Pod` / `RoleBinding` /
  `NetworkPolicy` / `Secret` / `ServiceAccount` / `ConfigMap` YAML.
  Sections 1–4 (control-plane components, etcd, control-plane
  configuration, worker-node kubelet config) require live cluster
  inspection and are intentionally out of scope for a posture-from-
  YAML scanner.
- **Source of truth:** `pipeline_check/core/standards/data/cis_kubernetes.py`

The benchmark's "manual investigation" prompts under Section 5 are
the gaps this scanner closes — passing every mapped check satisfies
the configuration substrate that a CIS K8s audit expects to see.
The audit additionally requires documented runbooks and review
processes that live outside the manifest layer.

## Controls evidenced

### 5.1 RBAC and Service Accounts

| ID    | Title                                                                                |
|-------|--------------------------------------------------------------------------------------|
| 5.1.1 | Ensure that the cluster-admin role is only used where required                       |
| 5.1.2 | Minimize access to secrets                                                           |
| 5.1.3 | Minimize wildcard use in Roles and ClusterRoles                                      |
| 5.1.4 | Minimize access to create pods                                                       |
| 5.1.5 | Ensure that default service accounts are not actively used                           |
| 5.1.6 | Ensure that Service Account Tokens are only mounted where necessary                  |
| 5.1.8 | Limit use of the Bind, Impersonate and Escalate permissions                          |

### 5.2 Pod Security Standards

| ID     | Title                                                                                |
|--------|--------------------------------------------------------------------------------------|
| 5.2.2  | Minimize the admission of privileged containers                                      |
| 5.2.3  | Minimize containers wishing to share the host process ID namespace                   |
| 5.2.4  | Minimize containers wishing to share the host IPC namespace                          |
| 5.2.5  | Minimize containers wishing to share the host network namespace                      |
| 5.2.6  | Minimize containers with allowPrivilegeEscalation                                    |
| 5.2.7  | Minimize the admission of root containers                                            |
| 5.2.8  | Minimize containers with the NET_RAW capability                                      |
| 5.2.9  | Minimize containers with added capabilities                                          |
| 5.2.12 | Minimize the admission of HostPath volumes                                           |
| 5.2.13 | Minimize the admission of containers which use HostPorts                             |

### 5.3 Network Policies and CNI

| ID    | Title                                                                                |
|-------|--------------------------------------------------------------------------------------|
| 5.3.2 | Ensure that all Namespaces have NetworkPolicies defined                              |

### 5.4 Secrets Management

| ID    | Title                                                                                |
|-------|--------------------------------------------------------------------------------------|
| 5.4.1 | Prefer using Secrets as files over Secrets as environment variables                  |
| 5.4.2 | Consider external secret storage                                                     |

### 5.7 General Policies

| ID    | Title                                                                                |
|-------|--------------------------------------------------------------------------------------|
| 5.7.1 | Create administrative boundaries between resources using namespaces                  |
| 5.7.2 | Ensure that the seccomp profile is set to docker/default                             |
| 5.7.3 | Apply SecurityContext to your Pods, Containers, and volumes                          |
| 5.7.4 | The default namespace should not be used                                             |

## Mapped checks

Every check below evidences one or more controls in the table
above. The mapping is in `pipeline_check/core/standards/data/cis_kubernetes.py`
— add a new row when you add or revise a K8s rule.

| Check    | Evidenced controls          |
|----------|-----------------------------|
| K8S-002  | 5.2.5                       |
| K8S-003  | 5.2.3                       |
| K8S-004  | 5.2.4                       |
| K8S-005  | 5.2.2                       |
| K8S-006  | 5.2.6                       |
| K8S-007  | 5.2.7                       |
| K8S-008  | 5.7.3                       |
| K8S-009  | 5.2.8, 5.2.9                |
| K8S-010  | 5.7.2                       |
| K8S-011  | 5.1.5                       |
| K8S-012  | 5.1.6                       |
| K8S-013  | 5.2.12                      |
| K8S-014  | 5.2.12                      |
| K8S-017  | 5.4.1                       |
| K8S-018  | 5.1.2, 5.4.2                |
| K8S-019  | 5.7.4                       |
| K8S-020  | 5.1.1, 5.1.8                |
| K8S-021  | 5.1.3                       |
| K8S-022  | 5.2.13                      |
| K8S-023  | 5.7.3                       |
| K8S-028  | 5.2.13                      |
| K8S-029  | 5.1.5                       |
| K8S-031  | 5.7.3                       |
| K8S-032  | 5.3.2                       |
| K8S-034  | 5.1.6                       |
| K8S-035  | 5.2.7                       |
| K8S-036  | 5.1.6                       |
| K8S-037  | 5.1.2, 5.4.2                |
| K8S-038  | 5.3.2                       |
| K8S-039  | 5.7.3                       |
| K8S-040  | 5.7.3                       |

## Out of scope

These benchmark sections require live-cluster evidence the scanner
can't collect from manifests:

- **5.1.6** (system:masters group) — RBAC subjects need API-server
  introspection.
- **5.2.10** (allowed-capabilities allowlist) — admission-controller
  policy, not workload spec.
- **5.5.x** (extensible admission control) — controller config.
- **5.6.x** (multi-tenancy beyond namespace) — admission policies +
  RBAC subjects.
- **All of Sections 1–4** — kubelet, API server, etcd, scheduler.

Run the benchmark's official `kube-bench` to evidence those at the
node level.
