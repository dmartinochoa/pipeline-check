# Kubernetes manifest provider

Parses Kubernetes API documents (`apiVersion:` + `kind:`) from `.yaml`
/ `.yml` files on disk, text-only static analysis. No `kubectl`, no
cluster access, no Helm or Kustomize rendering. Multi-document YAML
(`---`-separated) is fully supported; each document is parsed into
its own `Manifest` record.

Helm chart values, kustomization base files, and other YAML that
doesn't carry the canonical `apiVersion` + `kind` shape are silently
skipped, so a directory mixing manifests with `Chart.yaml` /
`values.yaml` / `kustomization.yaml` won't trip the loader.

## Producer workflow

```bash
# --k8s-path is auto-detected when ./kubernetes/, ./k8s/, or
# ./manifests/ exist at cwd.
pipeline_check --pipeline kubernetes

# …or pass it explicitly (file or directory).
pipeline_check --pipeline kubernetes --k8s-path k8s/

# A single multi-document manifest works too.
pipeline_check --pipeline kubernetes --k8s-path deploy.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Workload coverage

The walker recognizes every kind that carries a pod spec:

- `Pod`, pod spec at `spec`
- `Deployment` / `StatefulSet` / `DaemonSet` / `ReplicaSet` / `Job`
 , pod spec at `spec.template.spec`
- `CronJob`, pod spec at `spec.jobTemplate.spec.template.spec`

Container-level rules walk all three container lists (`containers`,
`initContainers`, `ephemeralContainers`), so init-time and ephemeral
debug containers are covered along with the long-lived workload.

### RBAC and Service rules

Four rules target non-workload kinds:

- **K8S-018**, `Kind: Secret` carrying credential-shaped literals
  in `stringData` or `data`. Base64 values in `data:` are decoded
  and re-checked for AKIA-shaped AWS keys.
- **K8S-020**, `ClusterRoleBinding` to `cluster-admin`, `admin`,
  or `system:masters`.
- **K8S-021**, `Role` / `ClusterRole` granting wildcard verbs+
  resources (both `verbs: ["*"]` and `resources: ["*"]`).
- **K8S-022**, `Service` exposing port 22 (SSH).

## What it covers

43 checks · 13 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [K8S-001](#k8s-001) | Container image not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-002](#k8s-002) | Pod hostNetwork: true | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-003](#k8s-003) | Pod hostPID: true | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-004](#k8s-004) | Pod hostIPC: true | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-005](#k8s-005) | Container securityContext.privileged: true | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-006](#k8s-006) | Container allowPrivilegeEscalation not explicitly false | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-007](#k8s-007) | Container runAsNonRoot not true / runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-008](#k8s-008) | Container readOnlyRootFilesystem not true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-009](#k8s-009) | Container capabilities not dropping ALL / adding dangerous caps | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [K8S-010](#k8s-010) | Container seccompProfile not RuntimeDefault or Localhost | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-011](#k8s-011) | Pod serviceAccountName unset or 'default' | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-012](#k8s-012) | Pod automountServiceAccountToken not false | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-013](#k8s-013) | Pod uses a hostPath volume | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-014](#k8s-014) | Pod hostPath references a sensitive host directory | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [K8S-015](#k8s-015) | Container missing resources.limits.memory | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-016](#k8s-016) | Container missing resources.limits.cpu | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [K8S-017](#k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [K8S-018](#k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [K8S-019](#k8s-019) | Workload deployed in the 'default' namespace | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [K8S-020](#k8s-020) | ClusterRoleBinding grants cluster-admin or system:masters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-021](#k8s-021) | Role or ClusterRole grants wildcard verbs+resources | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [K8S-022](#k8s-022) | Service exposes SSH (port 22) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-023](#k8s-023) | Namespace missing Pod Security Admission enforcement label | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [K8S-024](#k8s-024) | Container missing both livenessProbe and readinessProbe | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-025](#k8s-025) | System priority class used outside kube-system | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [K8S-026](#k8s-026) | LoadBalancer Service has no loadBalancerSourceRanges | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [K8S-027](#k8s-027) | Ingress has no TLS configuration | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-028](#k8s-028) | Container declares hostPort | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-029](#k8s-029) | RoleBinding grants permissions to the default ServiceAccount | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-030](#k8s-030) | Workload schedules onto a control-plane node | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [K8S-031](#k8s-031) | Namespace missing PSA warn label | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [K8S-032](#k8s-032) | Namespace lacks default-deny NetworkPolicy | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-033](#k8s-033) | Namespace lacks ResourceQuota or LimitRange | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-034](#k8s-034) | ServiceAccount automountServiceAccountToken not explicitly false | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-035](#k8s-035) | Container securityContext.runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [K8S-036](#k8s-036) | ServiceAccount imagePullSecrets references missing Secret | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-037](#k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [K8S-038](#k8s-038) | NetworkPolicy ingress / egress allows all sources or destinations | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-039](#k8s-039) | Pod uses shareProcessNamespace: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [K8S-040](#k8s-040) | Container securityContext.procMount: Unmasked | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [K8S-041](#k8s-041) | Service.externalIPs allows traffic interception (CVE-2020-8554) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [K8S-042](#k8s-042) | RoleBinding grants access to system:anonymous / system:unauthenticated | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [K8S-043](#k8s-043) | Ingress rule has wildcard or missing host (catch-all) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## K8S-001: Container image not pinned by sha256 digest { #k8s-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reuses ``_primitives.image_pinning.classify`` so the floating-tag semantics match DF-001 / GL-001 / JF-009 / ADO-009 / CC-003. Even a ``PINNED_TAG`` like ``nginx:1.25.4`` is treated as unpinned, only an explicit ``@sha256:`` survives, since a tag is mutable on the registry side and Kubernetes will happily pull the new content on a node restart.

<div class="pg-rule__rec" markdown>

**Recommended action**

Resolve every workload container image to its current digest (``crane digest <ref>`` or ``docker buildx imagetools inspect``) and pin via ``image: repo@sha256:<digest>``. Floating tags (``:latest``, ``:3``, no tag) silently swap the running image on the next rollout, breaking provenance and reproducibility.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-002: Pod hostNetwork: true { #k8s-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-ISOLATION</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

Compromised containers on hostNetwork can sniff or interfere with traffic from every other pod on the node. Reserve the flag for system DaemonSets that genuinely require it (CNI agents, ingress data planes); applications never need it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``spec.hostNetwork: false`` (the default) on every workload. ``hostNetwork: true`` puts the pod directly on the node's network namespace, exposing every host-bound listener to the container and bypassing CNI network policies.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-003: Pod hostPID: true { #k8s-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-ISOLATION</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

There is no application use case for hostPID. Only specialized node agents (process exporters, debuggers) legitimately need it, and those are typically deployed via a system DaemonSet with an explicit security review.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``spec.hostPID: false`` (the default) on every workload. ``hostPID: true`` makes every host process visible inside the container, and combined with privileged execution allows trivial escape via ``nsenter`` / ``/proc/<pid>/root``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-004: Pod hostIPC: true { #k8s-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-ISOLATION</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

Modern applications coordinate via gRPC / sockets, never via host IPC. Treat this flag as a strong red flag in code review unless paired with a documented system-level use case.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``spec.hostIPC: false`` (the default) on every workload. ``hostIPC: true`` lets the container read and write the host's shared-memory segments and POSIX message queues, exposing data exchanged by every other process on the node.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## K8S-005: Container securityContext.privileged: true { #k8s-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

``privileged: true`` is the strongest possible escalation in Kubernetes. It overrides every other securityContext setting and is the single largest cluster-takeover vector after RBAC misconfiguration.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``securityContext.privileged: true`` from every container. A privileged container has full access to the host's devices and capabilities, escape to the node is trivial. If the workload genuinely needs a kernel capability, grant only that capability via ``capabilities.add`` rather than enabling privileged mode.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-006: Container allowPrivilegeEscalation not explicitly false { #k8s-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

The default for non-root containers is True (Pod Security Standard 'baseline' allows this; 'restricted' does not). An explicit ``false`` is required because Kubernetes treats an unset field as a deferral to the cluster admission controller, which may not enforce ``restricted``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``securityContext.allowPrivilegeEscalation: false`` on every container. The Linux ``no_new_privs`` flag stops setuid binaries and capabilities from gaining elevated privileges, without this, a compromised process can escape via setuid utilities still installed in many base images.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-007: Container runAsNonRoot not true / runAsUser is 0 { #k8s-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

A container is considered safe when EITHER its own securityContext OR the pod-level securityContext sets ``runAsNonRoot: true`` and a non-zero ``runAsUser``. An explicit ``runAsUser: 0`` always fails, even if ``runAsNonRoot`` is unset.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``securityContext.runAsNonRoot: true`` and ``runAsUser: <non-zero UID>`` on every container, OR set the same fields at pod level so all containers inherit. Running as UID 0 inside a container makes container-escape exploits dramatically more dangerous, the attacker already has root inside the container, so any kernel CVE that matters becomes immediately exploitable.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-008: Container readOnlyRootFilesystem not true { #k8s-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Many post-exploitation toolchains (cryptominers, persistence implants, shell-callbacks) assume a writable root. Locking it down forces the attacker to use distroless or runtime tmpfs they can't easily place.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``securityContext.readOnlyRootFilesystem: true`` on every container. A read-only root filesystem stops attackers from dropping additional payloads into ``/tmp``, ``/var``, or writable system paths. Mount tmpfs ``emptyDir`` volumes for the directories the application genuinely needs to write to.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-009: Container capabilities not dropping ALL / adding dangerous caps { #k8s-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-272</span>
</div>

Fails when the container does NOT drop ``ALL`` *or* when ``capabilities.add`` includes any of: SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE, DAC_READ_SEARCH, DAC_OVERRIDE, SYS_RAWIO, SYS_BOOT, BPF, PERFMON, or the literal ``ALL``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop every capability and add back only what the workload actually needs:

    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]   # only if binding <1024

Most stateless services need no capabilities at all. Avoid ``SYS_ADMIN`` (effectively root), ``SYS_PTRACE`` (process snooping), ``NET_ADMIN`` (raw socket access), and ``SYS_MODULE`` (kernel module loading).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-010: Container seccompProfile not RuntimeDefault or Localhost { #k8s-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Pod-level ``securityContext.seccompProfile`` covers all containers in the pod. Either path passes this rule. The default of ``Unconfined`` (or unset, which inherits the node default, usually Unconfined) fails.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``securityContext.seccompProfile.type: RuntimeDefault`` (or ``Localhost`` with a path to your tuned profile) at either pod or container level. Without seccomp, every syscall is reachable from the container, modern kernel CVEs (e.g. ``io_uring``) become trivially exploitable.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-011: Pod serviceAccountName unset or 'default' { #k8s-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Both an unset ``serviceAccountName`` (which defaults to ``default``) and an explicit ``serviceAccountName: default`` fail the rule. Pair this with K8S-012 to also disable token auto-mounting where the workload doesn't need API access.

<div class="pg-rule__rec" markdown>

**Recommended action**

Bind every workload to a dedicated, narrow ``ServiceAccount``. The 'default' SA exists in every namespace and tends to accrete RoleBindings over time, using it gives the workload every privilege any other service in the namespace ever needed. Create a per-workload SA with the minimum RBAC needed and reference it via ``spec.serviceAccountName``.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-012: Pod automountServiceAccountToken not false { #k8s-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

An unset value defaults to True in Kubernetes. This rule fails on unset because most application workloads do NOT need API access and the default exposes credentials by accident. Workloads that explicitly call the API should set the field to ``true`` so the choice is visible in code review.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``spec.automountServiceAccountToken: false`` on every workload that doesn't need to talk to the Kubernetes API. Auto-mounted SA tokens are a free credential for an attacker who lands a shell, without explicit opt-out the token sits at ``/var/run/secrets/kubernetes.io/serviceaccount/token`` ready to be exfiltrated. If the workload needs API access, leave it true but pair with a tight, dedicated RBAC role.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-013: Pod uses a hostPath volume { #k8s-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-ISOLATION</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Some legitimate system DaemonSets need hostPath (log collectors, CSI node plugins). Those should be deployed with explicit security review and a narrow ``path:``; this rule fires regardless because *application* workloads should never use hostPath.

**Seen in the wild**

- [CVE-2021-25741](https://www.cve.org/CVERecord?id=CVE-2021-25741) (Kubernetes subPath volume traversal): a container could craft a ``subPath`` on a volume mount to access files outside the volume boundary. The bug affected multiple volume kinds; ``hostPath`` makes the blast radius worse because the volume already references host paths, so escaping the subpath lands directly on the node filesystem with the kubelet's privileges in scope.
- TeamTNT / Kinsing crypto-jacking campaigns (2020-2022): cluster compromise reports repeatedly traced lateral movement from a single misconfigured pod to the underlying node via hostPath:/, then to kubelet credentials and other tenants. Sysdig and Aqua incident reports document the pattern.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``hostPath`` volumes with ``configMap``, ``secret``, ``emptyDir``, ``persistentVolumeClaim``, or CSI volumes. ``hostPath`` opens a direct read/write window onto the node's filesystem; combined with even mild container compromise it gives the attacker access to other pods' data, kubelet credentials, and the container runtime.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## K8S-014: Pod hostPath references a sensitive host directory { #k8s-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-ISOLATION</span> <span class="pg-tag pg-tag--cwe">CWE-552</span>
</div>

Stricter than K8S-013: that rule flags any hostPath, this one upgrades to CRITICAL when the path is one of the well-known cluster-escape vectors.

<div class="pg-rule__rec" markdown>

**Recommended action**

Never mount the container runtime socket (``/var/run/docker.sock``, ``containerd.sock``, ``crio.sock``), kubelet credentials (``/var/lib/kubelet``), the cluster config (``/etc/kubernetes``), the host root (``/``), or ``/proc`` / ``/sys`` / ``/etc`` into a workload container. Each of these is a one-line cluster takeover. If a container genuinely needs node-level metrics, use an exporter DaemonSet with a narrowly-scoped read-only mount.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-015: Container missing resources.limits.memory { #k8s-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-770</span>
</div>

Init containers and ephemeral containers are also checked: a leaking init container holds a slot on the node until it completes and can crowd out other pods just as readily as an application container.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``resources.limits.memory`` on every container. Without a memory limit, a leaking or compromised container can consume the node's RAM until the kernel OOM-kills neighbouring pods, taking down workloads that share the node. Pair the limit with a ``requests.memory`` to inform the scheduler.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## K8S-016: Container missing resources.limits.cpu { #k8s-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-770</span>
</div>

Lower severity than K8S-015 because CPU throttling is self-healing (workloads slow down rather than die) and some controllers (e.g. SchedulerProfile, LimitRange) supply a cluster-default cpu limit transparently.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``resources.limits.cpu`` on every container. CPU throttling is the kernel's defense against a neighbour consuming all node cycles, without a limit, a compromised container can stall everything else on the node, including the kubelet. Pair the limit with a ``requests.cpu`` for scheduling.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## K8S-017: Container env value carries a credential-shaped literal { #k8s-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Reuses ``_primitives/secret_shapes``, flags AKIA-prefixed AWS access keys outright, plus credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal. ``valueFrom`` entries are always safe (no inline value).

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace literal ``env[].value`` entries that hold credentials with ``env[].valueFrom.secretKeyRef`` or ``envFrom.secretRef``. A literal env value lives in the manifest YAML. It gets committed to git, surfaced by ``kubectl get pod -o yaml``, and embedded in audit logs. Externalising into a Secret (and ideally a SealedSecret / ExternalSecret / SOPS-encrypted source) keeps the value out of the manifest.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## K8S-018: Secret stringData/data carries a credential-shaped literal { #k8s-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Walks both ``stringData`` (plain text) and ``data`` (base64). Base64-encoded values are decoded and checked for AKIA-shaped AWS keys. Credential-shaped key NAMES with any non-empty value are flagged regardless of encoding, even if the value is the literal placeholder ``REPLACE_ME``, having the name in the manifest is a maintenance footgun.

<div class="pg-rule__rec" markdown>

**Recommended action**

A ``Kind: Secret`` manifest committed to git defeats every secret-management story Kubernetes claims to provide, the base64 encoding in ``data`` is *not* encryption. Replace with SealedSecrets (Bitnami), ExternalSecrets / ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent injection. If the manifest must remain in git, the only acceptable contents are placeholders that are filled in by an operator at apply time.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## K8S-019: Workload deployed in the 'default' namespace { #k8s-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Severity is LOW because in a well-curated cluster the default namespace is empty by policy. If your cluster treats default as a sandbox you can suppress this rule via ``.pipelinecheckignore``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``metadata.namespace`` to a dedicated namespace per workload (or per environment). The ``default`` namespace tends to accumulate cluster-wide RoleBindings, NetworkPolicies, and operators that grant broader access than intended; placing application workloads there means every privilege grant in default applies to them. A purpose-built namespace also lets you enforce Pod Security Standards (``pod-security.kubernetes.io/enforce`` label) scoped to that workload.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## K8S-020: ClusterRoleBinding grants cluster-admin or system:masters { #k8s-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

The rule fires on a ``ClusterRoleBinding`` whose ``roleRef.name`` is ``cluster-admin``, ``admin``, or ``system:masters``. Subject type does not matter, even binding cluster-admin to a Group is a cluster-takeover risk.

**Seen in the wild**

- [Tesla Kubernetes dashboard compromise](https://redlock.io/cloud-security-trends-october-2018) (RedLock, 2018): an unauthenticated Kubernetes dashboard exposed to the internet held tokens for service accounts bound to cluster-admin. Attackers used the dashboard credentials to deploy crypto-mining workloads with full cluster access. Least-privilege RBAC would have capped the blast radius even after dashboard exposure.
- Argo CD [CVE-2022-24348](https://www.cve.org/CVERecord?id=CVE-2022-24348) (2022): a Helm path-traversal bug let a project member read other applications' YAML, exposing credentials. Combined with the default cluster-admin RBAC install, the recovered tokens were a direct cluster takeover. Argo's recommendation post-fix was to scope the controller's RBAC away from cluster-admin so a similar future bug couldn't escalate the same way.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace cluster-admin / system:masters bindings with narrowly-scoped ClusterRoles or namespace-scoped Roles. Granting cluster-admin to a service account is equivalent to giving every pod that uses it root on every node, credential theft from any such pod becomes immediate cluster takeover. Audit-log every existing cluster-admin binding and replace each with the minimum verbs/resources the consumer actually needs.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-021: Role or ClusterRole grants wildcard verbs+resources { #k8s-021 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Fires on any rule entry where BOTH ``verbs`` and ``resources`` contain a literal ``"*"``. A wildcard in only one of the two is still risky but is often a legitimate read-everything pattern (e.g. monitoring); this rule targets the strict superset 'do anything to everything'.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``verbs: ["*"]`` and ``resources: ["*"]`` with explicit lists. Wildcards bypass the principle of least privilege: today they grant `read pods` and tomorrow they grant `delete crds` because a new resource was registered in that apiGroup. Explicit verbs (``get``, ``list``, ``watch``) and explicit resources (``configmaps``, ``services``) keep grants stable across cluster upgrades.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-022: Service exposes SSH (port 22) { #k8s-022 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

Mirrors DF-013 (``EXPOSE 22`` in a Dockerfile) at the Service level. The check fires on Service ports whose ``port`` or ``targetPort`` is 22, regardless of Service type, a NodePort/LoadBalancer 22 is dramatically worse but a ClusterIP 22 still indicates an sshd container somewhere.

<div class="pg-rule__rec" markdown>

**Recommended action**

Containers should not run sshd. If you need an interactive shell into a running pod, use ``kubectl exec`` (subject to RBAC) or ``kubectl debug``. Removing the port-22 Service removes a pre-auth network surface that's a frequent lateral-movement target after initial cluster compromise.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-023: Namespace missing Pod Security Admission enforcement label { #k8s-023 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-NETWORK-SEG</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Pod Security Admission (PSA) replaced the deprecated PodSecurityPolicy in 1.25. The three levels are ``privileged``, ``baseline``, and ``restricted``; ``baseline`` is a sensible production default and ``restricted`` matches the spirit of K8S-005..010. ``kube-system`` is exempt by convention since control-plane pods may legitimately need elevated permissions.

**Known false-positive modes**

- Single-tenant clusters running only operator-managed workloads may apply PSA via an admission webhook instead. The label-based check can't see that.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``metadata.labels.pod-security.kubernetes.io/enforce`` to ``baseline`` or ``restricted`` on every Namespace. Without an enforce label the namespace runs the cluster's default policy, which on most installations is ``privileged`` and silently admits pods that violate every K8S-002..010 rule.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-024: Container missing both livenessProbe and readinessProbe { #k8s-024 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-MONITOR</span> <span class="pg-tag pg-tag--cwe">CWE-754</span>
</div>

Init containers and ephemeral debug containers are exempt, neither makes sense to probe. Jobs and CronJobs are also exempt because Kubernetes treats them as one-shot work; completion is the lifecycle signal, not health.

<div class="pg-rule__rec" markdown>

**Recommended action**

Define at least one of ``livenessProbe`` or ``readinessProbe`` on every long-running container. Without probes, a wedged pod stays listed as ``Running`` and keeps receiving traffic, which masks incidents and amplifies the blast radius of a single faulty replica.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-025: System priority class used outside kube-system { #k8s-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

The kubelet reserves the two ``system-*`` priority classes for its own pods (kube-proxy, CNI agents). Granting them to a user workload also grants the right to preempt and evict anything below 2000000000, which is every non-system pod on the cluster. Outside kube-system this is almost always a misconfiguration copy-pasted from a control-plane manifest.

<div class="pg-rule__rec" markdown>

**Recommended action**

Reserve ``system-cluster-critical`` and ``system-node-critical`` priority classes for control-plane workloads in ``kube-system``. Application pods that adopt them gain the right to evict normal workloads under resource pressure, which is a quiet path to a cluster-wide outage if the application has a bug or the attacker has any control over its spec.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-026: LoadBalancer Service has no loadBalancerSourceRanges { #k8s-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-NETWORK-SEG</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Internal-only services should use ``type: ClusterIP`` (and an Ingress for HTTP) or set the cloud-provider-specific internal-LB annotation. ``loadBalancerSourceRanges`` is the Kubernetes-native, cloud-portable way to scope an external LB; cloud-specific firewalls (AWS security groups, GCP firewall rules) are equivalent at the L4 level but invisible to a manifest scanner.

<div class="pg-rule__rec" markdown>

**Recommended action**

Restrict every ``Service`` of ``type: LoadBalancer`` with ``spec.loadBalancerSourceRanges``. The default behavior is to provision an internet-facing load balancer that accepts traffic from 0.0.0.0/0, which exposes whatever the Service fronts to the entire internet. A short list of CIDRs scoped to known clients (office IPs, a NAT gateway, peered VPCs) removes the pre-auth attack surface entirely.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-027: Ingress has no TLS configuration { #k8s-027 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-NETWORK-SEG</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

An Ingress with no ``spec.tls`` (or an empty list) terminates HTTP at the load balancer and proxies plaintext upstream. Ingress controllers will respect ``ssl-redirect`` annotations, but those are advisory until ``tls:`` is populated. If the Ingress is intentionally HTTP-only (e.g. an ACME challenge endpoint or an internal-only path served behind a network policy), suppress via ``.pipelinecheckignore`` with a short rationale rather than leaving it open.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``spec.tls`` block to every Ingress that fronts an HTTP backend. Each entry pairs one or more hostnames with a Secret holding the certificate / key, the canonical pattern is to provision the Secret via cert-manager and a ClusterIssuer pointing at Let's Encrypt or an internal CA. Plaintext-only Ingress lets a network attacker downgrade the connection and read or rewrite request bodies, which matters for any path carrying credentials, session cookies, or PII.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-028: Container declares hostPort { #k8s-028 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-NETWORK-SEG</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

``hostPort`` was the pre-Service way to publish a pod's port and survives in legacy manifests. Modern clusters use Services, which integrate with the kube-proxy, ingress controllers, and NetworkPolicies. ``hostPort`` is invisible to all of those, a port-scan from any other pod that knows the node IP reaches the workload directly. If a DaemonSet legitimately needs it (host-agent shape), suppress this rule with a brief ``.pipelinecheckignore`` rationale rather than leaving it open across the catalog.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``hostPort`` from container ports and use a Service (ClusterIP / NodePort / LoadBalancer) to publish the workload. ``hostPort`` binds directly to the node IP, bypasses the cluster's network model, and creates a node-level scheduling constraint that fails replicas with the same port. Workloads that genuinely need node-port binding (some CNI/storage agents) should declare it on a DaemonSet with ``hostNetwork: true`` already approved by review.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-029: RoleBinding grants permissions to the default ServiceAccount { #k8s-029 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Fires when a ``RoleBinding`` or ``ClusterRoleBinding`` lists ``kind: ServiceAccount, name: default`` among its subjects. ``kube-system``, ``kube-public``, and ``kube-node-lease`` are exempt because control-plane bootstrap manifests legitimately grant the default SA there.

**Known false-positive modes**

- Charts that intentionally re-use the default SA in single-tenant namespaces. Consider creating a named SA anyway. It keeps the audit log unambiguous about which workload made an API call.

<div class="pg-rule__rec" markdown>

**Recommended action**

Bind permissions to a dedicated ServiceAccount, not to ``default``. Every pod that omits ``serviceAccountName`` runs as the namespace's ``default`` SA, so a binding to it grants the same verbs to every untargeted pod in that namespace, including future workloads. Create a purpose-built SA, set ``automountServiceAccountToken: false`` on the default, and bind to the new SA explicitly.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-030: Workload schedules onto a control-plane node { #k8s-030 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-ISOLATION</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Fires on a non-system workload whose ``spec.nodeSelector`` contains a control-plane role label, OR whose ``spec.tolerations`` carries an entry with a control-plane taint key. Either condition is sufficient to land the pod on the control plane (the toleration is what survives the node taint; the nodeSelector picks the node).

**Known false-positive modes**

- Audit/log shippers and CNI agents in kube-system are exempt by namespace. A workload that legitimately needs to run on the control plane outside kube-system is rare enough to warrant an explicit ``.pipelinecheckignore`` rationale.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop the ``nodeSelector`` and ``tolerations`` entries that target ``node-role.kubernetes.io/control-plane`` (or the legacy ``master`` spelling) from non-system workloads. A pod scheduled on a control-plane node shares the kernel with the API server, etcd, and kubelet credentials, credential theft from any such pod yields cluster-wide takeover. Application workloads belong on dedicated worker nodes; system add-ons that legitimately need control-plane scheduling should run as a DaemonSet in ``kube-system``.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## K8S-031: Namespace missing PSA warn label { #k8s-031 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Pod Security Admission supports three modes: ``enforce`` (reject), ``audit`` (log to API audit), and ``warn`` (return a kubectl warning). K8S-023 covers ``enforce``; this rule covers ``warn``. The convention from upstream PSA docs is to set ``warn`` to the next-strictest tier above your current ``enforce`` so an upgrade from baseline to restricted is a predictable rollout, not a surprise.

**Known false-positive modes**

- Single-tenant clusters may set ``warn`` and ``audit`` globally via the AdmissionConfiguration ``defaults:`` block instead of per-namespace labels. The label-based check can't see that.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``metadata.labels.pod-security.kubernetes.io/warn`` on every Namespace, ideally one tier ahead of the enforce label (e.g. ``enforce: baseline`` + ``warn: restricted``). The warn level surfaces violations as ``kubectl apply`` warnings without rejecting the resource, developers see what would break before an enforcement upgrade lands.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-032: Namespace lacks default-deny NetworkPolicy { #k8s-032 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-NETWORK-SEG</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

Kubernetes' default network model is allow-everything: without any NetworkPolicy targeting a namespace, every pod can talk to every other pod across every namespace, and every pod can reach the internet. A default-deny policy flips the default to deny, so the only flows that work are those an explicit allow policy permits. The check fires on namespaces declared in the manifest set that have at least one workload but no default-deny NetworkPolicy covering them. Cross-doc correlation: it walks the full manifest stream to match Namespace/workload/NetworkPolicy across files.

**Known false-positive modes**

- Mesh-managed clusters (Istio, Linkerd, Cilium ClusterMesh) often delegate L4 default-deny to the mesh's authorization policy. The check only looks at native NetworkPolicy and won't see that.
- kube-system / kube-public / kube-node-lease are exempt, control-plane components frequently need open networking and have their own admission-time guards.

<div class="pg-rule__rec" markdown>

**Recommended action**

Apply a default-deny NetworkPolicy in every namespace that carries workloads. The canonical shape is ``podSelector: {}`` (matches every pod) plus ``policyTypes: [Ingress, Egress]`` with no ``ingress:`` / ``egress:`` rules, every flow is denied unless a more permissive NetworkPolicy in the same namespace explicitly allows it. Pair with per-workload allow-list policies for the flows the application actually needs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-033: Namespace lacks ResourceQuota or LimitRange { #k8s-033 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-770</span>
</div>

Without a ResourceQuota, a single namespace can consume the cluster's entire scheduling capacity, a fork bomb in a CronJob, a memory leak in a Deployment, or a cryptominer that landed via a fork-PR build can starve every other tenant. Without a LimitRange, individual pods without explicit ``resources:`` requests get a default of zero, the scheduler treats them as best-effort and packs them on any node, including ones already at memory pressure. The two work together: quota caps the aggregate, range caps the per-workload baseline. Cross-doc correlation: walks the manifest stream to match Namespace / workload / ResourceQuota / LimitRange across files.

<div class="pg-rule__rec" markdown>

**Recommended action**

Apply a ``ResourceQuota`` *and* a ``LimitRange`` to every namespace that hosts application workloads. ResourceQuota caps the namespace's total CPU / memory / pod / object consumption; LimitRange enforces per-pod request / limit defaults so a workload that forgets to declare its own doesn't get unbounded scheduling. Together they bound the blast radius of a runaway, leaky, or attacker-driven pod explosion to a single namespace.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-034: ServiceAccount automountServiceAccountToken not explicitly false { #k8s-034 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

K8S-012 covers the pod-level ``automountServiceAccountToken`` setting; this rule covers the same control at the ServiceAccount level. The two are complementary: the SA-level default flips the cluster-wide baseline (``true`` -> ``false``), the pod-level override re-enables only where needed. Without the SA-level disable, every pod that doesn't set its own override mounts a token that can call the K8s API as that SA, a useful credential for an attacker who lands code in any pod, regardless of the workload's own intent.

**Known false-positive modes**

- Operator / controller workloads (cert-manager, metrics-server, ingress controllers) legitimately need API access from every pod. Their dedicated SAs should keep automount enabled, leave them out of the cluster-wide disable. ``default`` SA in every namespace is the high-fire case worth disabling.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``automountServiceAccountToken: false`` at the ServiceAccount level for every SA that doesn't actively need to call the Kubernetes API. The pods that legitimately do (operators, sidecars that read namespaces, controllers) can opt back in per-pod via ``spec.automountServiceAccountToken: true``. The default is mount-everywhere, which is the wrong direction for least privilege.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-035: Container securityContext.runAsUser is 0 { #k8s-035 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

K8S-007 covers ``runAsNonRoot: false`` (the boolean form). This rule covers the explicit numeric form: a container that sets ``runAsUser: 0`` runs as root regardless of ``runAsNonRoot`` being declared elsewhere. Kubernetes won't reject the spec, it just runs the container as root. The two rules are paired so neither shape slips through alone. The pod-level ``securityContext.runAsUser`` inherits to every container that doesn't override it; this rule fires on the *effective* UID, walking pod-level first then per-container override.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``securityContext.runAsUser`` to a non-zero UID (e.g. 1000 or any application-specific value) on every workload container. The corresponding ``runAsGroup`` and ``fsGroup`` should also be non-zero. Root inside a container is not isolation, a kernel CVE, a misconfigured mount, or a mis-applied capability collapses straight into the host.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-036: ServiceAccount imagePullSecrets references missing Secret { #k8s-036 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-1188</span>
</div>

Cross-doc correlation: walks every ServiceAccount's ``imagePullSecrets`` and confirms the named Secret exists in the same namespace within the manifest set. Misses two cases: secrets created out-of-band (Sealed Secrets, External Secrets, or operator-applied ones) and SAs whose namespace is implicit / not declared in the manifest set. For those, the rule passes, false-negative-friendly.

**Known false-positive modes**

- Manifests rendered for partial deployment where the secret lives in a parallel manifest set the scanner doesn't see (separate ArgoCD application, Vault-injected, ESO-synced). Add ``# pipeline-check: ignore K8S-036`` or ignore the specific SA name to silence.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create the missing ``Kind: Secret`` of ``type: kubernetes.io/dockerconfigjson`` (or ``dockercfg``) in the same namespace before applying the ServiceAccount, or fix the ``imagePullSecrets`` reference name. A dangling reference doesn't fail apply, kubelet silently falls back to anonymous registry pulls on every image fetch. Workloads either pull a different image than the operator intended or fail at runtime with ``ImagePullBackOff`` after the registry rate-limits the unauthenticated client.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-037: ConfigMap data carries a credential-shaped literal { #k8s-037 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Companion to K8S-018 (which scans Kind: Secret). Walks ConfigMap ``data`` and ``binaryData`` for AKIA-shaped AWS keys and credential-shaped key NAMES. Even when the value is a placeholder, having ``api_key: REPLACE_ME`` in a ConfigMap is a maintenance footgun, someone will fill it in and commit. RBAC scoping for ``configmaps`` is typically much broader than ``secrets``, so any credential leak via this path reaches a wider audience.

**Known false-positive modes**

- ConfigMaps that legitimately carry placeholder names (``DEBUG_TOKEN_FORMAT``, ``LICENSE_KEY_HEADER``) where the VALUE is a format hint rather than a credential. Rename the key to avoid the credential-shaped name.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the value out of the ConfigMap. Secrets belong in ``Kind: Secret`` (better: SealedSecrets, ExternalSecrets / ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent injection). ConfigMaps are intended for non-sensitive config and are mounted into pods without the access controls Secrets carry, the ``RoleBinding`` for ``configmaps:get`` is typically far broader than the one for ``secrets:get``. A credential in a ConfigMap is effectively unprotected once any pod can read the namespace's config.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-038: NetworkPolicy ingress / egress allows all sources or destinations { #k8s-038 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-NETWORK-SEG</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

K8S-032 covers the absence of a default-deny NetworkPolicy. This rule covers the inverse: a NetworkPolicy that exists but contains an ``ingress:`` rule with no ``from:`` (allow from all) or no ``ports:`` filter, or an ``egress:`` rule with no ``to:`` filter. The ``from: []`` / ``to: []`` shorthand is the canonical mistake. A rule that lists specific peers via ``podSelector`` / ``namespaceSelector`` / ``ipBlock`` passes.

**Known false-positive modes**

- Policies intentionally allowing world traffic to a public ingress controller pod ({app: nginx-ingress, public: true}). Add ``# pipeline-check: ignore K8S-038`` on the specific NetworkPolicy if the wide-open shape is deliberate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the empty ``from: []`` / ``to: []`` rule with an explicit ``from: [{podSelector: {matchLabels: {…}}}]`` or ``from: [{namespaceSelector: {matchLabels: {…}}}]`` that names the legitimate peer. An empty ``from`` / ``to`` peers list means *every* source / destination, every pod in every namespace, plus every external IP. This is indistinguishable from having no NetworkPolicy at all for the targeted pod, but visually appears to enforce a policy (the false-sense-of-security failure mode is worse than no policy).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-039: Pod uses shareProcessNamespace: true { #k8s-039 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

``shareProcessNamespace: true`` makes every container in the pod share a single PID namespace. Any container can then enumerate every other container's processes (``ps``), read their environment variables and CLI args from ``/proc/<pid>/``, send them signals, and (with the right capabilities) ``ptrace`` them. A compromised sidecar, debug shell, logging agent, observability exporter, gets a free pivot into every primary container's secrets. The default is ``false``; setting it explicitly to ``true`` is the failing shape.

**Known false-positive modes**

- Debug pods that explicitly need ``ps`` / ``strace`` across container boundaries, but those are typically ephemeralContainers attached to a running pod, not long-lived pod specs in a manifest. If a permanent workload genuinely requires it, ignore the rule with a documented justification.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``spec.shareProcessNamespace: true`` from the pod spec. Containers in the pod will go back to having isolated PID namespaces, each sees only its own processes, can't ``ptrace`` neighbors, and can't read their ``/proc/<pid>/environ`` for env-var-leaked secrets. If the requirement is sidecar-style log collection or process-level cooperation, prefer a sidecar pattern that exchanges data through a shared volume rather than collapsing the namespace.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-040: Container securityContext.procMount: Unmasked { #k8s-040 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

``procMount: Unmasked`` is rarely needed in practice. It exists for nested-container / KubeVirt scenarios where the container itself runs an inner container runtime that needs to set up its own ``/proc`` masking. For an ordinary application container, ``Unmasked`` is a runtime-isolation regression that exposes kernel-information paths and writable ``/proc/sys`` entries to the workload. Pod Security Standards classify ``Unmasked`` as 'restricted'-violating; the rule fires when any container (``containers``, ``initContainers``, ``ephemeralContainers``) explicitly sets ``procMount: Unmasked``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``securityContext.procMount: Unmasked`` (or set it explicitly to ``Default``). The default ``Default`` procMount type masks several kernel- and node-information paths under ``/proc`` (``/proc/asound``, ``/proc/acpi``, ``/proc/kcore``, ``/proc/keys``, ``/proc/latency_stats``, ``/proc/timer_list``, ``/proc/timer_stats``, ``/proc/sched_debug``, ``/proc/scsi``) and remounts ``/proc/sys`` as read-only. These maskings are what stop a container from reading the host's kernel structures or writing to ``/proc/sys`` and breaking the kernel out of namespace isolation. ``Unmasked`` undoes all of that.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## K8S-041: Service.externalIPs allows traffic interception (CVE-2020-8554) { #k8s-041 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-NETWORK-SEG</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

CVE-2020-8554 is a design-level Kubernetes weakness rather than a code bug: any namespace user with ``services`` create permission can declare ``spec.externalIPs: [<arbitrary IP>]`` on a Service, and kube-proxy installs DNAT rules that intercept traffic destined for that IP on every node. The attacker primitive is to MITM in-cluster traffic to public endpoints, metadata services, or other tenants' workloads. Kubernetes upstream's remediation is admission-time enforcement (see the ``DenyServiceExternalIPs`` admission plugin and the RBAC pattern in the official guidance) rather than a runtime fix. This rule flags any non-empty ``externalIPs`` list so the team can confirm the field is gone from manifests before the admission policy is rolled out.

**Seen in the wild**

- CVE-2020-8554 (Kubernetes, 2020): documented MITM-via-externalIPs design flaw. Kubernetes' upstream advisory recommends restricting externalIPs via admission control.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``spec.externalIPs`` from the Service. The field has no legitimate use in most clusters and any namespace user with ``services.create`` can claim any IP, including the cluster's own kube-apiserver, metrics-server, or an external service IP, and the kube-proxy iptables rules will redirect matching traffic to their pods. Enforce the absence cluster-wide with an admission policy (Gatekeeper / Kyverno / ValidatingAdmissionPolicy) that rejects Services with a non-empty ``externalIPs`` list.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## K8S-042: RoleBinding grants access to system:anonymous / system:unauthenticated { #k8s-042 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

Kubernetes resolves authentication failures into the ``system:anonymous`` user (member of ``system:unauthenticated`` group) rather than rejecting the request outright, so any RBAC subject naming either of those values applies to requests with no Authorization header. The rule fires on both ``RoleBinding`` (namespace-scoped) and ``ClusterRoleBinding`` (cluster-scoped) subjects. Pairs with K8S-020: cluster-admin bound to a named SA is bad; cluster-admin bound to ``system:anonymous`` is cluster takeover by anyone with TCP/443 to the apiserver.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the binding's subject entry for ``system:anonymous`` or ``system:unauthenticated``. Anything bound to either subject is reachable without an authentication token, anyone who can hit the apiserver, including from inside an untrusted pod or from the public internet on an exposed apiserver, gets the bound verbs. If the workload genuinely needs unauthenticated read access (rare, usually only for OIDC discovery or the deprecated ``system:public-info-viewer`` shape), audit the bound ClusterRole's verbs+resources and confirm no write or secret-read verb is included.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## K8S-043: Ingress rule has wildcard or missing host (catch-all) { #k8s-043 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-NETWORK-SEG</span> <span class="pg-tag pg-tag--cwe">CWE-441</span>
</div>

An Ingress rule with no ``host:`` matches every Host header the controller receives; a rule with ``host: '*'`` is the explicit form of the same behavior. Both shape choices collapse the controller's hostname-based routing into a pure path-based match, which means anyone who can present any hostname (HTTP/1.1 Host header rewrite, malicious CNAME, controller hairpin) reaches this backend. The rule also fires on apex wildcards like ``host: '*.example.com'`` since they accept subdomains the cluster operator never intended to register. A backend that's intentionally wildcard-routed (a tenant-per-subdomain SaaS) should suppress with a rationale rather than disabling the check.

**Known false-positive modes**

- TLS terminators that intentionally use a single Ingress with a wildcard host to front many tenant subdomains are legitimate; suppress the finding for that Ingress specifically rather than disabling the rule.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every Ingress rule to an explicit hostname. ``host: api.example.com`` (not ``host: '*'``, ``host: '*.example.com'``, and not an omitted ``host:``). A catch-all host binding means any request to the ingress controller's external address, regardless of HTTP Host header, can route to this backend; an attacker with control over an arbitrary hostname pointing at the same controller (a parked domain, a typo'd CNAME, a cluster-internal name on a shared controller) reaches paths that should have been host-scoped.

</div>

</div>

---

## Adding a new Kubernetes check

1. Create a new module at
   `pipeline_check/core/checks/kubernetes/rules/k8sNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/kubernetes/K8S-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py kubernetes
   ```
