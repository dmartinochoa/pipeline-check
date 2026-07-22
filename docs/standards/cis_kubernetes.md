# CIS Kubernetes Benchmark

- **Version:** 1.10
- **URL:** <https://www.cisecurity.org/benchmark/kubernetes>
- **Source of truth:** `pipeline_check/core/standards/data/cis_kubernetes.py`

CIS Kubernetes Benchmark, Section 5 (Policies). Workload security
context, RBAC blast radius, NetworkPolicy posture, Secret hygiene,
and namespace separation, anything the
[Kubernetes provider](../providers/kubernetes.md) can score from
manifests on disk. The Section 1-4 control plane / node / etcd
controls require live cluster access and are out of scope.

## At a glance

- **Controls in this standard:** 24
- **Controls evidenced by at least one check:** 24 / 24
- **Distinct checks evidencing this standard:** 47
- **Of those, autofixable with `--fix`:** 13

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`5.1.1`](#ctrl-5-1-1) | Ensure that the cluster-admin role is only used where required | 2 | 2C |
| [`5.1.2`](#ctrl-5-1-2) | Minimize access to secrets | 5 | 3C · 2H |
| [`5.1.3`](#ctrl-5-1-3) | Minimize wildcard use in Roles and ClusterRoles | 3 | 2C · 1H |
| [`5.1.4`](#ctrl-5-1-4) | Minimize access to create pods | 3 | 2C · 1H |
| [`5.1.5`](#ctrl-5-1-5) | Ensure that default service accounts are not actively used | 5 | 1C · 1H · 3M |
| [`5.1.6`](#ctrl-5-1-6) | Ensure that Service Account Tokens are only mounted where necessary | 4 | 4M |
| [`5.1.8`](#ctrl-5-1-8) | Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster | 3 | 2C · 1H |
| [`5.2.2`](#ctrl-5-2-2) | Minimize the admission of privileged containers | 4 | 1C · 3H |
| [`5.2.3`](#ctrl-5-2-3) | Minimize the admission of containers wishing to share the host process ID namespace | 1 | 1H |
| [`5.2.4`](#ctrl-5-2-4) | Minimize the admission of containers wishing to share the host IPC namespace | 1 | 1H |
| [`5.2.5`](#ctrl-5-2-5) | Minimize the admission of containers wishing to share the host network namespace | 3 | 2C · 1H |
| [`5.2.6`](#ctrl-5-2-6) | Minimize the admission of containers with allowPrivilegeEscalation | 1 | 1H |
| [`5.2.7`](#ctrl-5-2-7) | Minimize the admission of root containers | 5 | 5H |
| [`5.2.8`](#ctrl-5-2-8) | Minimize the admission of containers with the NET_RAW capability | 1 | 1H |
| [`5.2.9`](#ctrl-5-2-9) | Minimize the admission of containers with added capabilities | 1 | 1H |
| [`5.2.12`](#ctrl-5-2-12) | Minimize the admission of HostPath volumes | 4 | 3C · 1H |
| [`5.2.13`](#ctrl-5-2-13) | Minimize the admission of containers which use HostPorts | 2 | 2M |
| [`5.3.2`](#ctrl-5-3-2) | Ensure that all Namespaces have NetworkPolicies defined | 2 | 2M |
| [`5.4.1`](#ctrl-5-4-1) | Prefer using Secrets as files over Secrets as environment variables | 2 | 2C |
| [`5.4.2`](#ctrl-5-4-2) | Consider external secret storage | 4 | 3C · 1H |
| [`5.7.1`](#ctrl-5-7-1) | Create administrative boundaries between resources using namespaces | 8 | 4H · 1M · 3L |
| [`5.7.2`](#ctrl-5-7-2) | Ensure that the seccomp profile is set to docker/default in your Pod definitions | 1 | 1M |
| [`5.7.3`](#ctrl-5-7-3) | Apply SecurityContext to your Pods and Containers | 14 | 1C · 9H · 3M · 1L |
| [`5.7.4`](#ctrl-5-7-4) | The default namespace should not be used | 1 | 1L |

## Filter at runtime

Restrict a scan to checks that evidence this standard with `--standard cis_kubernetes`:

```bash
# All providers, only checks tied to this standard
pipeline_check --standard cis_kubernetes

# Compose with --pipeline to scope by provider
pipeline_check --pipeline github --standard cis_kubernetes

# Compose with another standard to widen the lens
pipeline_check --pipeline aws --standard cis_kubernetes --standard owasp_cicd_top_10
```

## Controls in scope

### 5.1.1: Ensure that the cluster-admin role is only used where required { #ctrl-5-1-1 }

**Evidenced by 2 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-020`](../providers/kubernetes.md#k8s-020) | ClusterRoleBinding grants cluster-admin, admin, or system:masters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-042`](../providers/kubernetes.md#k8s-042) | RoleBinding grants access to system:anonymous / system:unauthenticated | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.1.2: Minimize access to secrets { #ctrl-5-1-2 }

**Evidenced by 5 checks** across 2 providers (Argo Workflows, Kubernetes).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-006`](../providers/argo.md#argo-006) | Literal secret value in Argo template env or parameter default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-018`](../providers/kubernetes.md#k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-021`](../providers/kubernetes.md#k8s-021) | Role or ClusterRole grants wildcard verbs+resources | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](../providers/kubernetes.md#k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-042`](../providers/kubernetes.md#k8s-042) | RoleBinding grants access to system:anonymous / system:unauthenticated | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.1.3: Minimize wildcard use in Roles and ClusterRoles { #ctrl-5-1-3 }

**Evidenced by 3 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-020`](../providers/kubernetes.md#k8s-020) | ClusterRoleBinding grants cluster-admin, admin, or system:masters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-021`](../providers/kubernetes.md#k8s-021) | Role or ClusterRole grants wildcard verbs+resources | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-042`](../providers/kubernetes.md#k8s-042) | RoleBinding grants access to system:anonymous / system:unauthenticated | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.1.4: Minimize access to create pods { #ctrl-5-1-4 }

**Evidenced by 3 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-020`](../providers/kubernetes.md#k8s-020) | ClusterRoleBinding grants cluster-admin, admin, or system:masters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-021`](../providers/kubernetes.md#k8s-021) | Role or ClusterRole grants wildcard verbs+resources | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-042`](../providers/kubernetes.md#k8s-042) | RoleBinding grants access to system:anonymous / system:unauthenticated | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.1.5: Ensure that default service accounts are not actively used { #ctrl-5-1-5 }

**Evidenced by 5 checks** across 3 providers (Argo Workflows, Kubernetes, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-003`](../providers/argo.md#argo-003) | Argo workflow uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-016`](../providers/argo.md#argo-016) | Workflow bound to a cluster-admin / over-privileged ServiceAccount | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`K8S-011`](../providers/kubernetes.md#k8s-011) | Pod serviceAccountName unset or 'default' | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-029`](../providers/kubernetes.md#k8s-029) | RoleBinding grants permissions to the default ServiceAccount | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TKN-007`](../providers/tekton.md#tkn-007) | Tekton run uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### 5.1.6: Ensure that Service Account Tokens are only mounted where necessary { #ctrl-5-1-6 }

**Evidenced by 4 checks** across 2 providers (Argo Workflows, Kubernetes).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-013`](../providers/argo.md#argo-013) | Argo workflow does not opt out of SA token automount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`K8S-012`](../providers/kubernetes.md#k8s-012) | Pod automountServiceAccountToken not false | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-034`](../providers/kubernetes.md#k8s-034) | ServiceAccount automountServiceAccountToken not explicitly false | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-036`](../providers/kubernetes.md#k8s-036) | ServiceAccount imagePullSecrets references missing Secret | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.1.8: Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster { #ctrl-5-1-8 }

**Evidenced by 3 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-020`](../providers/kubernetes.md#k8s-020) | ClusterRoleBinding grants cluster-admin, admin, or system:masters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-021`](../providers/kubernetes.md#k8s-021) | Role or ClusterRole grants wildcard verbs+resources | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-042`](../providers/kubernetes.md#k8s-042) | RoleBinding grants access to system:anonymous / system:unauthenticated | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.2.2: Minimize the admission of privileged containers { #ctrl-5-2-2 }

**Evidenced by 4 checks** across 3 providers (Argo Workflows, Kubernetes, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-002`](../providers/argo.md#argo-002) | Argo template container runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`K8S-005`](../providers/kubernetes.md#k8s-005) | Container securityContext.privileged: true | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TKN-002`](../providers/tekton.md#tkn-002) | Tekton step runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-013`](../providers/tekton.md#tkn-013) | Tekton sidecar runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### 5.2.3: Minimize the admission of containers wishing to share the host process ID namespace { #ctrl-5-2-3 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-003`](../providers/kubernetes.md#k8s-003) | Pod hostPID: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.2.4: Minimize the admission of containers wishing to share the host IPC namespace { #ctrl-5-2-4 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-004`](../providers/kubernetes.md#k8s-004) | Pod hostIPC: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.2.5: Minimize the admission of containers wishing to share the host network namespace { #ctrl-5-2-5 }

**Evidenced by 3 checks** across 3 providers (Argo Workflows, Kubernetes, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-004`](../providers/argo.md#argo-004) | Argo workflow mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`K8S-002`](../providers/kubernetes.md#k8s-002) | Pod hostNetwork: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TKN-004`](../providers/tekton.md#tkn-004) | Tekton Task mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |

### 5.2.6: Minimize the admission of containers with allowPrivilegeEscalation { #ctrl-5-2-6 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-006`](../providers/kubernetes.md#k8s-006) | Container allowPrivilegeEscalation not explicitly false | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.2.7: Minimize the admission of root containers { #ctrl-5-2-7 }

**Evidenced by 5 checks** across 3 providers (Argo Workflows, Kubernetes, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-002`](../providers/argo.md#argo-002) | Argo template container runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`K8S-007`](../providers/kubernetes.md#k8s-007) | Container runAsNonRoot not true / runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-035`](../providers/kubernetes.md#k8s-035) | Container securityContext.runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`TKN-002`](../providers/tekton.md#tkn-002) | Tekton step runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-013`](../providers/tekton.md#tkn-013) | Tekton sidecar runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### 5.2.8: Minimize the admission of containers with the NET_RAW capability { #ctrl-5-2-8 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-009`](../providers/kubernetes.md#k8s-009) | Container capabilities not dropping ALL / adding dangerous caps | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.2.9: Minimize the admission of containers with added capabilities { #ctrl-5-2-9 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-009`](../providers/kubernetes.md#k8s-009) | Container capabilities not dropping ALL / adding dangerous caps | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.2.12: Minimize the admission of HostPath volumes { #ctrl-5-2-12 }

**Evidenced by 4 checks** across 3 providers (Argo Workflows, Kubernetes, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-004`](../providers/argo.md#argo-004) | Argo workflow mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`K8S-013`](../providers/kubernetes.md#k8s-013) | Pod uses a hostPath volume | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-014`](../providers/kubernetes.md#k8s-014) | Pod hostPath references a sensitive host directory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`TKN-004`](../providers/tekton.md#tkn-004) | Tekton Task mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |

### 5.2.13: Minimize the admission of containers which use HostPorts { #ctrl-5-2-13 }

**Evidenced by 2 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-022`](../providers/kubernetes.md#k8s-022) | Service exposes SSH (port 22) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-028`](../providers/kubernetes.md#k8s-028) | Container declares hostPort | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.3.2: Ensure that all Namespaces have NetworkPolicies defined { #ctrl-5-3-2 }

**Evidenced by 2 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-032`](../providers/kubernetes.md#k8s-032) | Namespace lacks default-deny NetworkPolicy | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-038`](../providers/kubernetes.md#k8s-038) | NetworkPolicy ingress / egress allows all sources or destinations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.4.1: Prefer using Secrets as files over Secrets as environment variables { #ctrl-5-4-1 }

**Evidenced by 2 checks** across 2 providers (Argo Workflows, Kubernetes).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-006`](../providers/argo.md#argo-006) | Literal secret value in Argo template env or parameter default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-017`](../providers/kubernetes.md#k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.4.2: Consider external secret storage { #ctrl-5-4-2 }

**Evidenced by 4 checks** across 2 providers (Argo Workflows, Kubernetes).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-006`](../providers/argo.md#argo-006) | Literal secret value in Argo template env or parameter default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-017`](../providers/kubernetes.md#k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-018`](../providers/kubernetes.md#k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](../providers/kubernetes.md#k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.7.1: Create administrative boundaries between resources using namespaces { #ctrl-5-7-1 }

**Evidenced by 8 checks** across 2 providers (Helm, Kubernetes).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`HELM-006`](../providers/helm.md#helm-006) | Chart.yaml does not declare a kubeVersion compatibility range | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`K8S-019`](../providers/kubernetes.md#k8s-019) | Workload deployed in the 'default' namespace | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-023`](../providers/kubernetes.md#k8s-023) | Namespace missing Pod Security Admission enforcement label | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-025`](../providers/kubernetes.md#k8s-025) | System priority class used outside kube-system | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-030`](../providers/kubernetes.md#k8s-030) | Workload schedules onto a control-plane node | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-031`](../providers/kubernetes.md#k8s-031) | Namespace missing PSA warn label | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-033`](../providers/kubernetes.md#k8s-033) | Namespace lacks ResourceQuota or LimitRange | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-044`](../providers/kubernetes.md#k8s-044) | Admission webhook fails open or mutates cluster-wide unscoped | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.7.2: Ensure that the seccomp profile is set to docker/default in your Pod definitions { #ctrl-5-7-2 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-010`](../providers/kubernetes.md#k8s-010) | Container seccompProfile not RuntimeDefault or Localhost | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.7.3: Apply SecurityContext to your Pods and Containers { #ctrl-5-7-3 }

**Evidenced by 14 checks** across 3 providers (Argo Workflows, Kubernetes, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-002`](../providers/argo.md#argo-002) | Argo template container runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`K8S-005`](../providers/kubernetes.md#k8s-005) | Container securityContext.privileged: true | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-006`](../providers/kubernetes.md#k8s-006) | Container allowPrivilegeEscalation not explicitly false | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-007`](../providers/kubernetes.md#k8s-007) | Container runAsNonRoot not true / runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-008`](../providers/kubernetes.md#k8s-008) | Container readOnlyRootFilesystem not true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-009`](../providers/kubernetes.md#k8s-009) | Container capabilities not dropping ALL / adding dangerous caps | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-010`](../providers/kubernetes.md#k8s-010) | Container seccompProfile not RuntimeDefault or Localhost | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-023`](../providers/kubernetes.md#k8s-023) | Namespace missing Pod Security Admission enforcement label | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-031`](../providers/kubernetes.md#k8s-031) | Namespace missing PSA warn label | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-035`](../providers/kubernetes.md#k8s-035) | Container securityContext.runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-039`](../providers/kubernetes.md#k8s-039) | Pod uses shareProcessNamespace: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-040`](../providers/kubernetes.md#k8s-040) | Container securityContext.procMount: Unmasked | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-044`](../providers/kubernetes.md#k8s-044) | Admission webhook fails open or mutates cluster-wide unscoped | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`TKN-002`](../providers/tekton.md#tkn-002) | Tekton step runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### 5.7.4: The default namespace should not be used { #ctrl-5-7-4 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-019`](../providers/kubernetes.md#k8s-019) | Workload deployed in the 'default' namespace | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |

---

_This page is generated. Edit `pipeline_check/core/standards/data/cis_kubernetes.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py cis_kubernetes`._
