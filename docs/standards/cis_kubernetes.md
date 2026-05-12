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
- **Controls evidenced by at least one check:** 22 / 24
- **Distinct checks evidencing this standard:** 31
- **Of those, autofixable with `--fix`:** 11

## How to read severity

Every check below ships at a fixed severity level. The scale is the same across providers and standards so a CRITICAL finding in one place means the same thing as a CRITICAL finding anywhere else.

| Level | What it means | Examples |
|-------|---------------|----------|
| <span class="pg-sev pg-sev--critical">CRITICAL</span> | Active exploit primitive in the workflow as written. Treat as P0: a default scan path lands an attacker on a secret, an RCE, or production write access without further effort. | Hardcoded credential literal, branch ref pointing at a known-compromised action, signed-into-an-unverified registry. |
| <span class="pg-sev pg-sev--high">HIGH</span> | Production-impact gap that requires modest attacker effort or a second condition to weaponize. Remediate this sprint; the secondary condition is usually already present in real pipelines. | Action pinned to a floating tag, sensitive permissions on a low-popularity action, mutable container tag in prod. |
| <span class="pg-sev pg-sev--medium">MEDIUM</span> | Significant defense-in-depth gap. Not directly exploitable on its own but disables a control whose absence widens the blast radius of a separate compromise. Backlog with a deadline. | Missing branch protection, container without resource limits, freshly-published dependency consumed before the cooldown window. |
| <span class="pg-sev pg-sev--low">LOW</span> | Hygiene / hardening issue. Not a vulnerability on its own but raises baseline posture and reduces audit friction. | Missing CI logging retention, SBOM without supplier attribution, ECR repo without scan-on-push. |
| <span class="pg-sev pg-sev--info">INFO</span> | Degraded-mode signal. The scanner couldn't reach an API or parse a config and surfaces the gap so the operator knows coverage was incomplete. No finding against the workload itself. | ``CB-000`` CodeBuild API access failed, ``IAM-000`` IAM enumeration failed. |

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`5.1.1`](#ctrl-5-1-1) | Ensure that the cluster-admin role is only used where required | 1 | 1C |
| [`5.1.2`](#ctrl-5-1-2) | Minimize access to secrets | 2 | 1C · 1H |
| [`5.1.3`](#ctrl-5-1-3) | Minimize wildcard use in Roles and ClusterRoles | 1 | 1H |
| [`5.1.4`](#ctrl-5-1-4) | Minimize access to create pods | 0 | — |
| [`5.1.5`](#ctrl-5-1-5) | Ensure that default service accounts are not actively used | 2 | 1H · 1M |
| [`5.1.6`](#ctrl-5-1-6) | Ensure that Service Account Tokens are only mounted where necessary | 3 | 3M |
| [`5.1.8`](#ctrl-5-1-8) | Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster | 1 | 1C |
| [`5.2.2`](#ctrl-5-2-2) | Minimize the admission of privileged containers | 1 | 1C |
| [`5.2.3`](#ctrl-5-2-3) | Minimize the admission of containers wishing to share the host process ID namespace | 1 | 1H |
| [`5.2.4`](#ctrl-5-2-4) | Minimize the admission of containers wishing to share the host IPC namespace | 1 | 1H |
| [`5.2.5`](#ctrl-5-2-5) | Minimize the admission of containers wishing to share the host network namespace | 1 | 1H |
| [`5.2.6`](#ctrl-5-2-6) | Minimize the admission of containers with allowPrivilegeEscalation | 1 | 1H |
| [`5.2.7`](#ctrl-5-2-7) | Minimize the admission of root containers | 2 | 2H |
| [`5.2.8`](#ctrl-5-2-8) | Minimize the admission of containers with the NET_RAW capability | 1 | 1H |
| [`5.2.9`](#ctrl-5-2-9) | Minimize the admission of containers with added capabilities | 1 | 1H |
| [`5.2.12`](#ctrl-5-2-12) | Minimize the admission of HostPath volumes | 2 | 1C · 1H |
| [`5.2.13`](#ctrl-5-2-13) | Minimize the admission of containers which use HostPorts | 2 | 2M |
| [`5.3.2`](#ctrl-5-3-2) | Ensure that all Namespaces have NetworkPolicies defined | 2 | 2M |
| [`5.4.1`](#ctrl-5-4-1) | Prefer using Secrets as files over Secrets as environment variables | 1 | 1C |
| [`5.4.2`](#ctrl-5-4-2) | Consider external secret storage | 2 | 1C · 1H |
| [`5.7.1`](#ctrl-5-7-1) | Create administrative boundaries between resources using namespaces | 0 | — |
| [`5.7.2`](#ctrl-5-7-2) | Ensure that the seccomp profile is set to docker/default in your Pod definitions | 1 | 1M |
| [`5.7.3`](#ctrl-5-7-3) | Apply SecurityContext to your Pods and Containers | 5 | 2H · 2M · 1L |
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

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-020`](#detail-k8s-020) | ClusterRoleBinding grants cluster-admin or system:masters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.1.2: Minimize access to secrets { #ctrl-5-1-2 }

**Evidenced by 2 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-018`](#detail-k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](#detail-k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.1.3: Minimize wildcard use in Roles and ClusterRoles { #ctrl-5-1-3 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-021`](#detail-k8s-021) | Role or ClusterRole grants wildcard verbs+resources | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.1.4: Minimize access to create pods { #ctrl-5-1-4 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### 5.1.5: Ensure that default service accounts are not actively used { #ctrl-5-1-5 }

**Evidenced by 2 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-011`](#detail-k8s-011) | Pod serviceAccountName unset or 'default' | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-029`](#detail-k8s-029) | RoleBinding grants permissions to the default ServiceAccount | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.1.6: Ensure that Service Account Tokens are only mounted where necessary { #ctrl-5-1-6 }

**Evidenced by 3 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-012`](#detail-k8s-012) | Pod automountServiceAccountToken not false | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-034`](#detail-k8s-034) | ServiceAccount automountServiceAccountToken not explicitly false | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-036`](#detail-k8s-036) | ServiceAccount imagePullSecrets references missing Secret | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.1.8: Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster { #ctrl-5-1-8 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-020`](#detail-k8s-020) | ClusterRoleBinding grants cluster-admin or system:masters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.2.2: Minimize the admission of privileged containers { #ctrl-5-2-2 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-005`](#detail-k8s-005) | Container securityContext.privileged: true | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.2.3: Minimize the admission of containers wishing to share the host process ID namespace { #ctrl-5-2-3 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-003`](#detail-k8s-003) | Pod hostPID: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.2.4: Minimize the admission of containers wishing to share the host IPC namespace { #ctrl-5-2-4 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-004`](#detail-k8s-004) | Pod hostIPC: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.2.5: Minimize the admission of containers wishing to share the host network namespace { #ctrl-5-2-5 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-002`](#detail-k8s-002) | Pod hostNetwork: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.2.6: Minimize the admission of containers with allowPrivilegeEscalation { #ctrl-5-2-6 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-006`](#detail-k8s-006) | Container allowPrivilegeEscalation not explicitly false | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.2.7: Minimize the admission of root containers { #ctrl-5-2-7 }

**Evidenced by 2 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-007`](#detail-k8s-007) | Container runAsNonRoot not true / runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-035`](#detail-k8s-035) | Container securityContext.runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.2.8: Minimize the admission of containers with the NET_RAW capability { #ctrl-5-2-8 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-009`](#detail-k8s-009) | Container capabilities not dropping ALL / adding dangerous caps | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.2.9: Minimize the admission of containers with added capabilities { #ctrl-5-2-9 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-009`](#detail-k8s-009) | Container capabilities not dropping ALL / adding dangerous caps | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.2.12: Minimize the admission of HostPath volumes { #ctrl-5-2-12 }

**Evidenced by 2 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-013`](#detail-k8s-013) | Pod uses a hostPath volume | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-014`](#detail-k8s-014) | Pod hostPath references a sensitive host directory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.2.13: Minimize the admission of containers which use HostPorts { #ctrl-5-2-13 }

**Evidenced by 2 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-022`](#detail-k8s-022) | Service exposes SSH (port 22) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-028`](#detail-k8s-028) | Container declares hostPort | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 5.3.2: Ensure that all Namespaces have NetworkPolicies defined { #ctrl-5-3-2 }

**Evidenced by 2 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-032`](#detail-k8s-032) | Namespace lacks default-deny NetworkPolicy | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-038`](#detail-k8s-038) | NetworkPolicy ingress / egress allows all sources or destinations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.4.1: Prefer using Secrets as files over Secrets as environment variables { #ctrl-5-4-1 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-017`](#detail-k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.4.2: Consider external secret storage { #ctrl-5-4-2 }

**Evidenced by 2 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-018`](#detail-k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](#detail-k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.7.1: Create administrative boundaries between resources using namespaces { #ctrl-5-7-1 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### 5.7.2: Ensure that the seccomp profile is set to docker/default in your Pod definitions { #ctrl-5-7-2 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-010`](#detail-k8s-010) | Container seccompProfile not RuntimeDefault or Localhost | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.7.3: Apply SecurityContext to your Pods and Containers { #ctrl-5-7-3 }

**Evidenced by 5 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-008`](#detail-k8s-008) | Container readOnlyRootFilesystem not true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-023`](#detail-k8s-023) | Namespace missing Pod Security Admission enforcement label | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-031`](#detail-k8s-031) | Namespace missing PSA warn label | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-039`](#detail-k8s-039) | Pod uses shareProcessNamespace: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-040`](#detail-k8s-040) | Container securityContext.procMount: Unmasked | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |

### 5.7.4: The default namespace should not be used { #ctrl-5-7-4 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-019`](#detail-k8s-019) | Workload deployed in the 'default' namespace | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |

## Check details

Every check that evidences this standard, rendered once with its detection mechanism, recommendation, and any known false-positive modes or real-world incident references. The per-control tables above link to the matching block here.

#### `K8S-002`: Pod hostNetwork: true <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-002 }

**Evidences:** [`5.2.5`](#ctrl-5-2-5) Minimize the admission of containers wishing to share the host network namespace.

**How this is detected.** Compromised containers on hostNetwork can sniff or interfere with traffic from every other pod on the node. Reserve the flag for system DaemonSets that genuinely require it (CNI agents, ingress data planes); applications never need it.

**Recommendation.** Set ``spec.hostNetwork: false`` (the default) on every workload. ``hostNetwork: true`` puts the pod directly on the node's network namespace, exposing every host-bound listener to the container and bypassing CNI network policies.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-002`](../providers/kubernetes.md#k8s-002) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-003`: Pod hostPID: true <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-003 }

**Evidences:** [`5.2.3`](#ctrl-5-2-3) Minimize the admission of containers wishing to share the host process ID namespace.

**How this is detected.** There is no application use case for hostPID. Only specialised node agents (process exporters, debuggers) legitimately need it, and those are typically deployed via a system DaemonSet with an explicit security review.

**Recommendation.** Set ``spec.hostPID: false`` (the default) on every workload. ``hostPID: true`` makes every host process visible inside the container, and combined with privileged execution allows trivial escape via ``nsenter`` / ``/proc/<pid>/root``.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-003`](../providers/kubernetes.md#k8s-003) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-004`: Pod hostIPC: true <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-004 }

**Evidences:** [`5.2.4`](#ctrl-5-2-4) Minimize the admission of containers wishing to share the host IPC namespace.

**How this is detected.** Modern applications coordinate via gRPC / sockets, never via host IPC. Treat this flag as a strong red flag in code review unless paired with a documented system-level use case.

**Recommendation.** Set ``spec.hostIPC: false`` (the default) on every workload. ``hostIPC: true`` lets the container read and write the host's shared-memory segments and POSIX message queues, exposing data exchanged by every other process on the node.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-004`](../providers/kubernetes.md#k8s-004) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-005`: Container securityContext.privileged: true <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-005 }

**Evidences:** [`5.2.2`](#ctrl-5-2-2) Minimize the admission of privileged containers.

**How this is detected.** ``privileged: true`` is the strongest possible escalation in Kubernetes. It overrides every other securityContext setting and is the single largest cluster-takeover vector after RBAC misconfiguration.

**Recommendation.** Remove ``securityContext.privileged: true`` from every container. A privileged container has full access to the host's devices and capabilities, escape to the node is trivial. If the workload genuinely needs a kernel capability, grant only that capability via ``capabilities.add`` rather than enabling privileged mode.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-005`](../providers/kubernetes.md#k8s-005) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-006`: Container allowPrivilegeEscalation not explicitly false <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-006 }

**Evidences:** [`5.2.6`](#ctrl-5-2-6) Minimize the admission of containers with allowPrivilegeEscalation.

**How this is detected.** The default for non-root containers is True (Pod Security Standard 'baseline' allows this; 'restricted' does not). An explicit ``false`` is required because Kubernetes treats an unset field as a deferral to the cluster admission controller, which may not enforce ``restricted``.

**Recommendation.** Set ``securityContext.allowPrivilegeEscalation: false`` on every container. The Linux ``no_new_privs`` flag stops setuid binaries and capabilities from gaining elevated privileges, without this, a compromised process can escape via setuid utilities still installed in many base images.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-006`](../providers/kubernetes.md#k8s-006) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-007`: Container runAsNonRoot not true / runAsUser is 0 <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-007 }

**Evidences:** [`5.2.7`](#ctrl-5-2-7) Minimize the admission of root containers.

**How this is detected.** A container is considered safe when EITHER its own securityContext OR the pod-level securityContext sets ``runAsNonRoot: true`` and a non-zero ``runAsUser``. An explicit ``runAsUser: 0`` always fails, even if ``runAsNonRoot`` is unset.

**Recommendation.** Set ``securityContext.runAsNonRoot: true`` and ``runAsUser: <non-zero UID>`` on every container, OR set the same fields at pod level so all containers inherit. Running as UID 0 inside a container makes container-escape exploits dramatically more dangerous, the attacker already has root inside the container, so any kernel CVE that matters becomes immediately exploitable.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-007`](../providers/kubernetes.md#k8s-007) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-008`: Container readOnlyRootFilesystem not true <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-008 }

**Evidences:** [`5.7.3`](#ctrl-5-7-3) Apply SecurityContext to your Pods and Containers.

**How this is detected.** Many post-exploitation toolchains (cryptominers, persistence implants, shell-callbacks) assume a writable root. Locking it down forces the attacker to use distroless or runtime tmpfs they can't easily place.

**Recommendation.** Set ``securityContext.readOnlyRootFilesystem: true`` on every container. A read-only root filesystem stops attackers from dropping additional payloads into ``/tmp``, ``/var``, or writable system paths. Mount tmpfs ``emptyDir`` volumes for the directories the application genuinely needs to write to.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-008`](../providers/kubernetes.md#k8s-008) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-009`: Container capabilities not dropping ALL / adding dangerous caps <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-009 }

**Evidences:** [`5.2.8`](#ctrl-5-2-8) Minimize the admission of containers with the NET_RAW capability, [`5.2.9`](#ctrl-5-2-9) Minimize the admission of containers with added capabilities.

**How this is detected.** Fails when the container does NOT drop ``ALL`` *or* when ``capabilities.add`` includes any of: SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE, DAC_READ_SEARCH, DAC_OVERRIDE, SYS_RAWIO, SYS_BOOT, BPF, PERFMON, or the literal ``ALL``.

**Recommendation.** Drop every capability and add back only what the workload actually needs:

    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]   # only if binding <1024

Most stateless services need no capabilities at all. Avoid ``SYS_ADMIN`` (effectively root), ``SYS_PTRACE`` (process snooping), ``NET_ADMIN`` (raw socket access), and ``SYS_MODULE`` (kernel module loading).

**Source:** [`K8S-009`](../providers/kubernetes.md#k8s-009) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-010`: Container seccompProfile not RuntimeDefault or Localhost <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-010 }

**Evidences:** [`5.7.2`](#ctrl-5-7-2) Ensure that the seccomp profile is set to docker/default in your Pod definitions.

**How this is detected.** Pod-level ``securityContext.seccompProfile`` covers all containers in the pod. Either path passes this rule. The default of ``Unconfined`` (or unset, which inherits the node default, usually Unconfined) fails.

**Recommendation.** Set ``securityContext.seccompProfile.type: RuntimeDefault`` (or ``Localhost`` with a path to your tuned profile) at either pod or container level. Without seccomp, every syscall is reachable from the container, modern kernel CVEs (e.g. ``io_uring``) become trivially exploitable.

**Source:** [`K8S-010`](../providers/kubernetes.md#k8s-010) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-011`: Pod serviceAccountName unset or 'default' <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-011 }

**Evidences:** [`5.1.5`](#ctrl-5-1-5) Ensure that default service accounts are not actively used.

**How this is detected.** Both an unset ``serviceAccountName`` (which defaults to ``default``) and an explicit ``serviceAccountName: default`` fail the rule. Pair this with K8S-012 to also disable token auto-mounting where the workload doesn't need API access.

**Recommendation.** Bind every workload to a dedicated, narrow ``ServiceAccount``. The 'default' SA exists in every namespace and tends to accrete RoleBindings over time, using it gives the workload every privilege any other service in the namespace ever needed. Create a per-workload SA with the minimum RBAC needed and reference it via ``spec.serviceAccountName``.

**Source:** [`K8S-011`](../providers/kubernetes.md#k8s-011) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-012`: Pod automountServiceAccountToken not false <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-012 }

**Evidences:** [`5.1.6`](#ctrl-5-1-6) Ensure that Service Account Tokens are only mounted where necessary.

**How this is detected.** An unset value defaults to True in Kubernetes. This rule fails on unset because most application workloads do NOT need API access and the default exposes credentials by accident. Workloads that explicitly call the API should set the field to ``true`` so the choice is visible in code review.

**Recommendation.** Set ``spec.automountServiceAccountToken: false`` on every workload that doesn't need to talk to the Kubernetes API. Auto-mounted SA tokens are a free credential for an attacker who lands a shell, without explicit opt-out the token sits at ``/var/run/secrets/kubernetes.io/serviceaccount/token`` ready to be exfiltrated. If the workload needs API access, leave it true but pair with a tight, dedicated RBAC role.

**Source:** [`K8S-012`](../providers/kubernetes.md#k8s-012) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-013`: Pod uses a hostPath volume <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-013 }

**Evidences:** [`5.2.12`](#ctrl-5-2-12) Minimize the admission of HostPath volumes.

**How this is detected.** Some legitimate system DaemonSets need hostPath (log collectors, CSI node plugins). Those should be deployed with explicit security review and a narrow ``path:``; this rule fires regardless because *application* workloads should never use hostPath.

**Recommendation.** Replace ``hostPath`` volumes with ``configMap``, ``secret``, ``emptyDir``, ``persistentVolumeClaim``, or CSI volumes. ``hostPath`` opens a direct read/write window onto the node's filesystem; combined with even mild container compromise it gives the attacker access to other pods' data, kubelet credentials, and the container runtime.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- [CVE-2021-25741](https://www.cve.org/CVERecord?id=CVE-2021-25741) (Kubernetes subpath symlink escape): a container with ``hostPath`` plus subpath could traverse outside the volume boundary and read or modify arbitrary host files. Exploitable on any cluster permitting hostPath to non-system workloads.
- TeamTNT / Kinsing crypto-jacking campaigns (2020-2022): cluster compromise reports repeatedly traced lateral movement from a single misconfigured pod to the underlying node via hostPath:/, then to kubelet credentials and other tenants. Sysdig and Aqua incident reports document the pattern.

**Proof of exploit.**

# Vulnerable: pod mounts the host's root filesystem.
apiVersion: v1
kind: Pod
metadata:
  name: attacker
spec:
  containers:
    - name: shell
      image: busybox
      command: ["sleep", "infinity"]
      volumeMounts:
        - name: host-root
          mountPath: /host
  volumes:
    - name: host-root
      hostPath:
        path: /            # full node filesystem

# Attack from a shell inside the container:
#
#   # Read kubelet credentials and pivot to API server:
#   cat /host/var/lib/kubelet/kubeconfig
#   cat /host/etc/kubernetes/admin.conf
#
#   # Read service account tokens for every other pod on
#   # the node and impersonate them:
#   ls /host/var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/*/token
#
#   # Drop a setuid binary and pin persistence on the host:
#   cp /bin/busybox /host/usr/local/bin/.bd
#   chmod 4755 /host/usr/local/bin/.bd

# Safe: use scoped volume types that don't bridge to the host.
spec:
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: app-data

**Source:** [`K8S-013`](../providers/kubernetes.md#k8s-013) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-014`: Pod hostPath references a sensitive host directory <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-014 }

**Evidences:** [`5.2.12`](#ctrl-5-2-12) Minimize the admission of HostPath volumes.

**How this is detected.** Stricter than K8S-013: that rule flags any hostPath, this one upgrades to CRITICAL when the path is one of the well-known cluster-escape vectors.

**Recommendation.** Never mount the container runtime socket (``/var/run/docker.sock``, ``containerd.sock``, ``crio.sock``), kubelet credentials (``/var/lib/kubelet``), the cluster config (``/etc/kubernetes``), the host root (``/``), or ``/proc`` / ``/sys`` / ``/etc`` into a workload container. Each of these is a one-line cluster takeover. If a container genuinely needs node-level metrics, use an exporter DaemonSet with a narrowly-scoped read-only mount.

**Source:** [`K8S-014`](../providers/kubernetes.md#k8s-014) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-017`: Container env value carries a credential-shaped literal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-017 }

**Evidences:** [`5.4.1`](#ctrl-5-4-1) Prefer using Secrets as files over Secrets as environment variables.

**How this is detected.** Reuses ``_primitives/secret_shapes``, flags AKIA-prefixed AWS access keys outright, plus credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal. ``valueFrom`` entries are always safe (no inline value).

**Recommendation.** Replace literal ``env[].value`` entries that hold credentials with ``env[].valueFrom.secretKeyRef`` or ``envFrom.secretRef``. A literal env value lives in the manifest YAML. It gets committed to git, surfaced by ``kubectl get pod -o yaml``, and embedded in audit logs. Externalising into a Secret (and ideally a SealedSecret / ExternalSecret / SOPS-encrypted source) keeps the value out of the manifest.

**Source:** [`K8S-017`](../providers/kubernetes.md#k8s-017) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-018`: Secret stringData/data carries a credential-shaped literal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-018 }

**Evidences:** [`5.1.2`](#ctrl-5-1-2) Minimize access to secrets, [`5.4.2`](#ctrl-5-4-2) Consider external secret storage.

**How this is detected.** Walks both ``stringData`` (plain text) and ``data`` (base64). Base64-encoded values are decoded and checked for AKIA-shaped AWS keys. Credential-shaped key NAMES with any non-empty value are flagged regardless of encoding, even if the value is the literal placeholder ``REPLACE_ME``, having the name in the manifest is a maintenance footgun.

**Recommendation.** A ``Kind: Secret`` manifest committed to git defeats every secret-management story Kubernetes claims to provide, the base64 encoding in ``data`` is *not* encryption. Replace with SealedSecrets (Bitnami), ExternalSecrets / ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent injection. If the manifest must remain in git, the only acceptable contents are placeholders that are filled in by an operator at apply time.

**Source:** [`K8S-018`](../providers/kubernetes.md#k8s-018) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-019`: Workload deployed in the 'default' namespace <span class="pg-sev pg-sev--low">LOW</span> { #detail-k8s-019 }

**Evidences:** [`5.7.4`](#ctrl-5-7-4) The default namespace should not be used.

**How this is detected.** Severity is LOW because in a well-curated cluster the default namespace is empty by policy. If your cluster treats default as a sandbox you can suppress this rule via ``.pipelinecheckignore``.

**Recommendation.** Set ``metadata.namespace`` to a dedicated namespace per workload (or per environment). The ``default`` namespace tends to accumulate cluster-wide RoleBindings, NetworkPolicies, and operators that grant broader access than intended; placing application workloads there means every privilege grant in default applies to them. A purpose-built namespace also lets you enforce Pod Security Standards (``pod-security.kubernetes.io/enforce`` label) scoped to that workload.

**Source:** [`K8S-019`](../providers/kubernetes.md#k8s-019) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-020`: ClusterRoleBinding grants cluster-admin or system:masters <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-020 }

**Evidences:** [`5.1.1`](#ctrl-5-1-1) Ensure that the cluster-admin role is only used where required, [`5.1.8`](#ctrl-5-1-8) Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster.

**How this is detected.** The rule fires on a ``ClusterRoleBinding`` whose ``roleRef.name`` is ``cluster-admin``, ``admin``, or ``system:masters``. Subject type does not matter, even binding cluster-admin to a Group is a cluster-takeover risk.

**Recommendation.** Replace cluster-admin / system:masters bindings with narrowly-scoped ClusterRoles or namespace-scoped Roles. Granting cluster-admin to a service account is equivalent to giving every pod that uses it root on every node, credential theft from any such pod becomes immediate cluster takeover. Audit-log every existing cluster-admin binding and replace each with the minimum verbs/resources the consumer actually needs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- [Tesla Kubernetes dashboard compromise](https://redlock.io/cloud-security-trends-october-2018) (RedLock, 2018): an unauthenticated Kubernetes dashboard exposed to the internet held tokens for service accounts bound to cluster-admin. Attackers used the dashboard credentials to deploy crypto-mining workloads with full cluster access. Least-privilege RBAC would have capped the blast radius even after dashboard exposure.
- Argo CD CVE-2022-24348 / CVE-2022-24768 chain (2022): directory traversal plus a default cluster-admin install let any project member exfiltrate cluster-wide secrets. Argo's recommendation post-fix was to scope the controller's RBAC away from cluster-admin so a similar future bug couldn't escalate the same way.

**Source:** [`K8S-020`](../providers/kubernetes.md#k8s-020) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-021`: Role or ClusterRole grants wildcard verbs+resources <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-021 }

**Evidences:** [`5.1.3`](#ctrl-5-1-3) Minimize wildcard use in Roles and ClusterRoles.

**How this is detected.** Fires on any rule entry where BOTH ``verbs`` and ``resources`` contain a literal ``"*"``. A wildcard in only one of the two is still risky but is often a legitimate read-everything pattern (e.g. monitoring); this rule targets the strict superset 'do anything to everything'.

**Recommendation.** Replace ``verbs: ["*"]`` and ``resources: ["*"]`` with explicit lists. Wildcards bypass the principle of least privilege: today they grant `read pods` and tomorrow they grant `delete crds` because a new resource was registered in that apiGroup. Explicit verbs (``get``, ``list``, ``watch``) and explicit resources (``configmaps``, ``services``) keep grants stable across cluster upgrades.

**Source:** [`K8S-021`](../providers/kubernetes.md#k8s-021) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-022`: Service exposes SSH (port 22) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-022 }

**Evidences:** [`5.2.13`](#ctrl-5-2-13) Minimize the admission of containers which use HostPorts.

**How this is detected.** Mirrors DF-013 (``EXPOSE 22`` in a Dockerfile) at the Service level. The check fires on Service ports whose ``port`` or ``targetPort`` is 22, regardless of Service type, a NodePort/LoadBalancer 22 is dramatically worse but a ClusterIP 22 still indicates an sshd container somewhere.

**Recommendation.** Containers should not run sshd. If you need an interactive shell into a running pod, use ``kubectl exec`` (subject to RBAC) or ``kubectl debug``. Removing the port-22 Service removes a pre-auth network surface that's a frequent lateral-movement target after initial cluster compromise.

**Source:** [`K8S-022`](../providers/kubernetes.md#k8s-022) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-023`: Namespace missing Pod Security Admission enforcement label <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-023 }

**Evidences:** [`5.7.3`](#ctrl-5-7-3) Apply SecurityContext to your Pods and Containers.

**How this is detected.** Pod Security Admission (PSA) replaced the deprecated PodSecurityPolicy in 1.25. The three levels are ``privileged``, ``baseline``, and ``restricted``; ``baseline`` is a sensible production default and ``restricted`` matches the spirit of K8S-005..010. ``kube-system`` is exempt by convention since control-plane pods may legitimately need elevated permissions.

**Recommendation.** Set ``metadata.labels.pod-security.kubernetes.io/enforce`` to ``baseline`` or ``restricted`` on every Namespace. Without an enforce label the namespace runs the cluster's default policy, which on most installations is ``privileged`` and silently admits pods that violate every K8S-002..010 rule.

**Known false positives.**

- Single-tenant clusters running only operator-managed workloads may apply PSA via an admission webhook instead. The label-based check can't see that.

**Source:** [`K8S-023`](../providers/kubernetes.md#k8s-023) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-028`: Container declares hostPort <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-028 }

**Evidences:** [`5.2.13`](#ctrl-5-2-13) Minimize the admission of containers which use HostPorts.

**How this is detected.** ``hostPort`` was the pre-Service way to publish a pod's port and survives in legacy manifests. Modern clusters use Services, which integrate with the kube-proxy, ingress controllers, and NetworkPolicies. ``hostPort`` is invisible to all of those, a port-scan from any other pod that knows the node IP reaches the workload directly. If a DaemonSet legitimately needs it (host-agent shape), suppress this rule with a brief ``.pipelinecheckignore`` rationale rather than leaving it open across the catalog.

**Recommendation.** Drop ``hostPort`` from container ports and use a Service (ClusterIP / NodePort / LoadBalancer) to publish the workload. ``hostPort`` binds directly to the node IP, bypasses the cluster's network model, and creates a node-level scheduling constraint that fails replicas with the same port. Workloads that genuinely need node-port binding (some CNI/storage agents) should declare it on a DaemonSet with ``hostNetwork: true`` already approved by review.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-028`](../providers/kubernetes.md#k8s-028) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-029`: RoleBinding grants permissions to the default ServiceAccount <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-029 }

**Evidences:** [`5.1.5`](#ctrl-5-1-5) Ensure that default service accounts are not actively used.

**How this is detected.** Fires when a ``RoleBinding`` or ``ClusterRoleBinding`` lists ``kind: ServiceAccount, name: default`` among its subjects. ``kube-system``, ``kube-public``, and ``kube-node-lease`` are exempt because control-plane bootstrap manifests legitimately grant the default SA there.

**Recommendation.** Bind permissions to a dedicated ServiceAccount, not to ``default``. Every pod that omits ``serviceAccountName`` runs as the namespace's ``default`` SA, so a binding to it grants the same verbs to every untargeted pod in that namespace, including future workloads. Create a purpose-built SA, set ``automountServiceAccountToken: false`` on the default, and bind to the new SA explicitly.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Charts that intentionally re-use the default SA in single-tenant namespaces. Consider creating a named SA anyway. It keeps the audit log unambiguous about which workload made an API call.

**Source:** [`K8S-029`](../providers/kubernetes.md#k8s-029) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-031`: Namespace missing PSA warn label <span class="pg-sev pg-sev--low">LOW</span> { #detail-k8s-031 }

**Evidences:** [`5.7.3`](#ctrl-5-7-3) Apply SecurityContext to your Pods and Containers.

**How this is detected.** Pod Security Admission supports three modes: ``enforce`` (reject), ``audit`` (log to API audit), and ``warn`` (return a kubectl warning). K8S-023 covers ``enforce``; this rule covers ``warn``. The convention from upstream PSA docs is to set ``warn`` to the next-strictest tier above your current ``enforce`` so an upgrade from baseline to restricted is a predictable rollout, not a surprise.

**Recommendation.** Set ``metadata.labels.pod-security.kubernetes.io/warn`` on every Namespace, ideally one tier ahead of the enforce label (e.g. ``enforce: baseline`` + ``warn: restricted``). The warn level surfaces violations as ``kubectl apply`` warnings without rejecting the resource, developers see what would break before an enforcement upgrade lands.

**Known false positives.**

- Single-tenant clusters may set ``warn`` and ``audit`` globally via the AdmissionConfiguration ``defaults:`` block instead of per-namespace labels. The label-based check can't see that.

**Source:** [`K8S-031`](../providers/kubernetes.md#k8s-031) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-032`: Namespace lacks default-deny NetworkPolicy <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-032 }

**Evidences:** [`5.3.2`](#ctrl-5-3-2) Ensure that all Namespaces have NetworkPolicies defined.

**How this is detected.** Kubernetes' default network model is allow-everything: without any NetworkPolicy targeting a namespace, every pod can talk to every other pod across every namespace, and every pod can reach the internet. A default-deny policy flips the default to deny, so the only flows that work are those an explicit allow policy permits. The check fires on namespaces declared in the manifest set that have at least one workload but no default-deny NetworkPolicy covering them. Cross-doc correlation: it walks the full manifest stream to match Namespace/workload/NetworkPolicy across files.

**Recommendation.** Apply a default-deny NetworkPolicy in every namespace that carries workloads. The canonical shape is ``podSelector: {}`` (matches every pod) plus ``policyTypes: [Ingress, Egress]`` with no ``ingress:`` / ``egress:`` rules, every flow is denied unless a more permissive NetworkPolicy in the same namespace explicitly allows it. Pair with per-workload allow-list policies for the flows the application actually needs.

**Known false positives.**

- Mesh-managed clusters (Istio, Linkerd, Cilium ClusterMesh) often delegate L4 default-deny to the mesh's authorization policy. The check only looks at native NetworkPolicy and won't see that.
- kube-system / kube-public / kube-node-lease are exempt, control-plane components frequently need open networking and have their own admission-time guards.

**Source:** [`K8S-032`](../providers/kubernetes.md#k8s-032) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-034`: ServiceAccount automountServiceAccountToken not explicitly false <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-034 }

**Evidences:** [`5.1.6`](#ctrl-5-1-6) Ensure that Service Account Tokens are only mounted where necessary.

**How this is detected.** K8S-012 covers the pod-level ``automountServiceAccountToken`` setting; this rule covers the same control at the ServiceAccount level. The two are complementary: the SA-level default flips the cluster-wide baseline (``true`` -> ``false``), the pod-level override re-enables only where needed. Without the SA-level disable, every pod that doesn't set its own override mounts a token that can call the K8s API as that SA, a useful credential for an attacker who lands code in any pod, regardless of the workload's own intent.

**Recommendation.** Set ``automountServiceAccountToken: false`` at the ServiceAccount level for every SA that doesn't actively need to call the Kubernetes API. The pods that legitimately do (operators, sidecars that read namespaces, controllers) can opt back in per-pod via ``spec.automountServiceAccountToken: true``. The default is mount-everywhere, which is the wrong direction for least privilege.

**Known false positives.**

- Operator / controller workloads (cert-manager, metrics-server, ingress controllers) legitimately need API access from every pod. Their dedicated SAs should keep automount enabled, leave them out of the cluster-wide disable. ``default`` SA in every namespace is the high-fire case worth disabling.

**Source:** [`K8S-034`](../providers/kubernetes.md#k8s-034) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-035`: Container securityContext.runAsUser is 0 <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-035 }

**Evidences:** [`5.2.7`](#ctrl-5-2-7) Minimize the admission of root containers.

**How this is detected.** K8S-007 covers ``runAsNonRoot: false`` (the boolean form). This rule covers the explicit numeric form: a container that sets ``runAsUser: 0`` runs as root regardless of ``runAsNonRoot`` being declared elsewhere. Kubernetes won't reject the spec, it just runs the container as root. The two rules are paired so neither shape slips through alone. The pod-level ``securityContext.runAsUser`` inherits to every container that doesn't override it; this rule fires on the *effective* UID, walking pod-level first then per-container override.

**Recommendation.** Set ``securityContext.runAsUser`` to a non-zero UID (e.g. 1000 or any application-specific value) on every workload container. The corresponding ``runAsGroup`` and ``fsGroup`` should also be non-zero. Root inside a container is not isolation, a kernel CVE, a misconfigured mount, or a mis-applied capability collapses straight into the host.

**Source:** [`K8S-035`](../providers/kubernetes.md#k8s-035) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-036`: ServiceAccount imagePullSecrets references missing Secret <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-036 }

**Evidences:** [`5.1.6`](#ctrl-5-1-6) Ensure that Service Account Tokens are only mounted where necessary.

**How this is detected.** Cross-doc correlation: walks every ServiceAccount's ``imagePullSecrets`` and confirms the named Secret exists in the same namespace within the manifest set. Misses two cases: secrets created out-of-band (Sealed Secrets, External Secrets, or operator-applied ones) and SAs whose namespace is implicit / not declared in the manifest set. For those, the rule passes, false-negative-friendly.

**Recommendation.** Create the missing ``Kind: Secret`` of ``type: kubernetes.io/dockerconfigjson`` (or ``dockercfg``) in the same namespace before applying the ServiceAccount, or fix the ``imagePullSecrets`` reference name. A dangling reference doesn't fail apply, kubelet silently falls back to anonymous registry pulls on every image fetch. Workloads either pull a different image than the operator intended or fail at runtime with ``ImagePullBackOff`` after the registry rate-limits the unauthenticated client.

**Known false positives.**

- Manifests rendered for partial deployment where the secret lives in a parallel manifest set the scanner doesn't see (separate ArgoCD application, Vault-injected, ESO-synced). Add ``# pipeline-check: ignore K8S-036`` or ignore the specific SA name to silence.

**Source:** [`K8S-036`](../providers/kubernetes.md#k8s-036) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-037`: ConfigMap data carries a credential-shaped literal <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-037 }

**Evidences:** [`5.1.2`](#ctrl-5-1-2) Minimize access to secrets, [`5.4.2`](#ctrl-5-4-2) Consider external secret storage.

**How this is detected.** Companion to K8S-018 (which scans Kind: Secret). Walks ConfigMap ``data`` and ``binaryData`` for AKIA-shaped AWS keys and credential-shaped key NAMES. Even when the value is a placeholder, having ``api_key: REPLACE_ME`` in a ConfigMap is a maintenance footgun, someone will fill it in and commit. RBAC scoping for ``configmaps`` is typically much broader than ``secrets``, so any credential leak via this path reaches a wider audience.

**Recommendation.** Move the value out of the ConfigMap. Secrets belong in ``Kind: Secret`` (better: SealedSecrets, ExternalSecrets / ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent injection). ConfigMaps are intended for non-sensitive config and are mounted into pods without the access controls Secrets carry, the ``RoleBinding`` for ``configmaps:get`` is typically far broader than the one for ``secrets:get``. A credential in a ConfigMap is effectively unprotected once any pod can read the namespace's config.

**Known false positives.**

- ConfigMaps that legitimately carry placeholder names (``DEBUG_TOKEN_FORMAT``, ``LICENSE_KEY_HEADER``) where the VALUE is a format hint rather than a credential. Rename the key to avoid the credential-shaped name.

**Source:** [`K8S-037`](../providers/kubernetes.md#k8s-037) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-038`: NetworkPolicy ingress / egress allows all sources or destinations <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-038 }

**Evidences:** [`5.3.2`](#ctrl-5-3-2) Ensure that all Namespaces have NetworkPolicies defined.

**How this is detected.** K8S-032 covers the absence of a default-deny NetworkPolicy. This rule covers the inverse: a NetworkPolicy that exists but contains an ``ingress:`` rule with no ``from:`` (allow from all) or no ``ports:`` filter, or an ``egress:`` rule with no ``to:`` filter. The ``from: []`` / ``to: []`` shorthand is the canonical mistake. A rule that lists specific peers via ``podSelector`` / ``namespaceSelector`` / ``ipBlock`` passes.

**Recommendation.** Replace the empty ``from: []`` / ``to: []`` rule with an explicit ``from: [{podSelector: {matchLabels: {…}}}]`` or ``from: [{namespaceSelector: {matchLabels: {…}}}]`` that names the legitimate peer. An empty ``from`` / ``to`` peers list means *every* source / destination, every pod in every namespace, plus every external IP. This is indistinguishable from having no NetworkPolicy at all for the targeted pod, but visually appears to enforce a policy (the false-sense-of-security failure mode is worse than no policy).

**Known false positives.**

- Policies intentionally allowing world traffic to a public ingress controller pod ({app: nginx-ingress, public: true}). Add ``# pipeline-check: ignore K8S-038`` on the specific NetworkPolicy if the wide-open shape is deliberate.

**Source:** [`K8S-038`](../providers/kubernetes.md#k8s-038) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-039`: Pod uses shareProcessNamespace: true <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-039 }

**Evidences:** [`5.7.3`](#ctrl-5-7-3) Apply SecurityContext to your Pods and Containers.

**How this is detected.** ``shareProcessNamespace: true`` makes every container in the pod share a single PID namespace. Any container can then enumerate every other container's processes (``ps``), read their environment variables and CLI args from ``/proc/<pid>/``, send them signals, and (with the right capabilities) ``ptrace`` them. A compromised sidecar, debug shell, logging agent, observability exporter, gets a free pivot into every primary container's secrets. The default is ``false``; setting it explicitly to ``true`` is the failing shape.

**Recommendation.** Drop ``spec.shareProcessNamespace: true`` from the pod spec. Containers in the pod will go back to having isolated PID namespaces, each sees only its own processes, can't ``ptrace`` neighbors, and can't read their ``/proc/<pid>/environ`` for env-var-leaked secrets. If the requirement is sidecar-style log collection or process-level cooperation, prefer a sidecar pattern that exchanges data through a shared volume rather than collapsing the namespace.

**Known false positives.**

- Debug pods that explicitly need ``ps`` / ``strace`` across container boundaries, but those are typically ephemeralContainers attached to a running pod, not long-lived pod specs in a manifest. If a permanent workload genuinely requires it, ignore the rule with a documented justification.

**Source:** [`K8S-039`](../providers/kubernetes.md#k8s-039) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-040`: Container securityContext.procMount: Unmasked <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-040 }

**Evidences:** [`5.7.3`](#ctrl-5-7-3) Apply SecurityContext to your Pods and Containers.

**How this is detected.** ``procMount: Unmasked`` is rarely needed in practice. It exists for nested-container / KubeVirt scenarios where the container itself runs an inner container runtime that needs to set up its own ``/proc`` masking. For an ordinary application container, ``Unmasked`` is a runtime-isolation regression that exposes kernel-information paths and writable ``/proc/sys`` entries to the workload. Pod Security Standards classify ``Unmasked`` as 'restricted'-violating; the rule fires when any container (``containers``, ``initContainers``, ``ephemeralContainers``) explicitly sets ``procMount: Unmasked``.

**Recommendation.** Remove ``securityContext.procMount: Unmasked`` (or set it explicitly to ``Default``). The default ``Default`` procMount type masks several kernel- and node-information paths under ``/proc`` (``/proc/asound``, ``/proc/acpi``, ``/proc/kcore``, ``/proc/keys``, ``/proc/latency_stats``, ``/proc/timer_list``, ``/proc/timer_stats``, ``/proc/sched_debug``, ``/proc/scsi``) and remounts ``/proc/sys`` as read-only. These maskings are what stop a container from reading the host's kernel structures or writing to ``/proc/sys`` and breaking the kernel out of namespace isolation. ``Unmasked`` undoes all of that.

**Source:** [`K8S-040`](../providers/kubernetes.md#k8s-040) in the [Kubernetes provider](../providers/kubernetes.md).

---

_This page is generated. Edit `pipeline_check/core/standards/data/cis_kubernetes.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py cis_kubernetes`._
