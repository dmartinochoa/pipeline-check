# Kubernetes manifest provider

Parses Kubernetes API documents (`apiVersion:` + `kind:`) from `.yaml`
/ `.yml` files on disk — text-only static analysis. No `kubectl`, no
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

The walker recognises every kind that carries a pod spec:

- `Pod` — pod spec at `spec`
- `Deployment` / `StatefulSet` / `DaemonSet` / `ReplicaSet` / `Job`
  — pod spec at `spec.template.spec`
- `CronJob` — pod spec at `spec.jobTemplate.spec.template.spec`

Container-level rules walk all three container lists (`containers`,
`initContainers`, `ephemeralContainers`), so init-time and ephemeral
debug containers are covered along with the long-lived workload.

### RBAC and Service rules

Four rules target non-workload kinds:

- **K8S-018** — `Kind: Secret` carrying credential-shaped literals
  in `stringData` or `data`. Base64 values in `data:` are decoded
  and re-checked for AKIA-shaped AWS keys.
- **K8S-020** — `ClusterRoleBinding` to `cluster-admin`, `admin`,
  or `system:masters`.
- **K8S-021** — `Role` / `ClusterRole` granting wildcard verbs+
  resources (both `verbs: ["*"]` and `resources: ["*"]`).
- **K8S-022** — `Service` exposing port 22 (SSH).

## What it covers

| Check | Title | Severity |
|-------|-------|----------|
| K8S-001 | Container image not pinned by sha256 digest | HIGH |
| K8S-002 | Pod hostNetwork: true | HIGH |
| K8S-003 | Pod hostPID: true | HIGH |
| K8S-004 | Pod hostIPC: true | HIGH |
| K8S-005 | Container securityContext.privileged: true | CRITICAL |
| K8S-006 | Container allowPrivilegeEscalation not explicitly false | HIGH |
| K8S-007 | Container runAsNonRoot not true / runAsUser is 0 | HIGH |
| K8S-008 | Container readOnlyRootFilesystem not true | MEDIUM |
| K8S-009 | Container capabilities not dropping ALL / adding dangerous caps | HIGH |
| K8S-010 | Container seccompProfile not RuntimeDefault or Localhost | MEDIUM |
| K8S-011 | Pod serviceAccountName unset or 'default' | MEDIUM |
| K8S-012 | Pod automountServiceAccountToken not false | MEDIUM |
| K8S-013 | Pod uses a hostPath volume | HIGH |
| K8S-014 | Pod hostPath references a sensitive host directory | CRITICAL |
| K8S-015 | Container missing resources.limits.memory | MEDIUM |
| K8S-016 | Container missing resources.limits.cpu | LOW |
| K8S-017 | Container env value carries a credential-shaped literal | CRITICAL |
| K8S-018 | Secret stringData/data carries a credential-shaped literal | CRITICAL |
| K8S-019 | Workload deployed in the 'default' namespace | LOW |
| K8S-020 | ClusterRoleBinding grants cluster-admin or system:masters | CRITICAL |
| K8S-021 | Role or ClusterRole grants wildcard verbs+resources | HIGH |
| K8S-022 | Service exposes SSH (port 22) | MEDIUM |
| K8S-023 | Namespace missing Pod Security Admission enforcement label | HIGH |
| K8S-024 | Container missing both livenessProbe and readinessProbe | MEDIUM |
| K8S-025 | System priority class used outside kube-system | HIGH |
| K8S-026 | LoadBalancer Service has no loadBalancerSourceRanges | HIGH |

---

## K8S-001 — Container image not pinned by sha256 digest
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-IMMUTABLE, ESF-S-VERIFY-DEPS

Reuses ``_primitives.image_pinning.classify`` so the floating-tag semantics match DF-001 / GL-001 / JF-009 / ADO-009 / CC-003. Even a ``PINNED_TAG`` like ``nginx:1.25.4`` is treated as unpinned — only an explicit ``@sha256:`` survives, since a tag is mutable on the registry side and Kubernetes will happily pull the new content on a node restart.

**Recommended action**

Resolve every workload container image to its current digest (``crane digest <ref>`` or ``docker buildx imagetools inspect``) and pin via ``image: repo@sha256:<digest>``. Floating tags (``:latest``, ``:3``, no tag) silently swap the running image on the next rollout, breaking provenance and reproducibility.

## K8S-002 — Pod hostNetwork: true
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV, ESF-D-ISOLATION

Compromised containers on hostNetwork can sniff or interfere with traffic from every other pod on the node. Reserve the flag for system DaemonSets that genuinely require it (CNI agents, ingress data planes); applications never need it.

**Recommended action**

Set ``spec.hostNetwork: false`` (the default) on every workload. ``hostNetwork: true`` puts the pod directly on the node's network namespace, exposing every host-bound listener to the container and bypassing CNI network policies.

## K8S-003 — Pod hostPID: true
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV, ESF-D-ISOLATION

There is no application use case for hostPID. Only specialised node agents (process exporters, debuggers) legitimately need it, and those are typically deployed via a system DaemonSet with an explicit security review.

**Recommended action**

Set ``spec.hostPID: false`` (the default) on every workload. ``hostPID: true`` makes every host process visible inside the container, and combined with privileged execution allows trivial escape via ``nsenter`` / ``/proc/<pid>/root``.

## K8S-004 — Pod hostIPC: true
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV, ESF-D-ISOLATION

Modern applications coordinate via gRPC / sockets, never via host IPC. Treat this flag as a strong red flag in code review unless paired with a documented system-level use case.

**Recommended action**

Set ``spec.hostIPC: false`` (the default) on every workload. ``hostIPC: true`` lets the container read and write the host's shared-memory segments and POSIX message queues, exposing data exchanged by every other process on the node.

## K8S-005 — Container securityContext.privileged: true
**Severity:** CRITICAL · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV

``privileged: true`` is the strongest possible escalation in Kubernetes. It overrides every other securityContext setting and is the single largest cluster-takeover vector after RBAC misconfiguration.

**Recommended action**

Remove ``securityContext.privileged: true`` from every container. A privileged container has full access to the host's devices and capabilities — escape to the node is trivial. If the workload genuinely needs a kernel capability, grant only that capability via ``capabilities.add`` rather than enabling privileged mode.

## K8S-006 — Container allowPrivilegeEscalation not explicitly false
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV

The default for non-root containers is True (Pod Security Standard 'baseline' allows this; 'restricted' does not). An explicit ``false`` is required because Kubernetes treats an unset field as a deferral to the cluster admission controller, which may not enforce ``restricted``.

**Recommended action**

Set ``securityContext.allowPrivilegeEscalation: false`` on every container. The Linux ``no_new_privs`` flag stops setuid binaries and capabilities from gaining elevated privileges — without this, a compromised process can escape via setuid utilities still installed in many base images.

## K8S-007 — Container runAsNonRoot not true / runAsUser is 0
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV

A container is considered safe when EITHER its own securityContext OR the pod-level securityContext sets ``runAsNonRoot: true`` and a non-zero ``runAsUser``. An explicit ``runAsUser: 0`` always fails, even if ``runAsNonRoot`` is unset.

**Recommended action**

Set ``securityContext.runAsNonRoot: true`` and ``runAsUser: <non-zero UID>`` on every container, OR set the same fields at pod level so all containers inherit. Running as UID 0 inside a container makes container-escape exploits dramatically more dangerous — the attacker already has root inside the container, so any kernel CVE that matters becomes immediately exploitable.

## K8S-008 — Container readOnlyRootFilesystem not true
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV

Many post-exploitation toolchains (cryptominers, persistence implants, shell-callbacks) assume a writable root. Locking it down forces the attacker to use distroless or runtime tmpfs they can't easily place.

**Recommended action**

Set ``securityContext.readOnlyRootFilesystem: true`` on every container. A read-only root filesystem stops attackers from dropping additional payloads into ``/tmp``, ``/var``, or writable system paths. Mount tmpfs ``emptyDir`` volumes for the directories the application genuinely needs to write to.

## K8S-009 — Container capabilities not dropping ALL / adding dangerous caps
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV

Fails when the container does NOT drop ``ALL`` *or* when ``capabilities.add`` includes any of: SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE, DAC_READ_SEARCH, DAC_OVERRIDE, SYS_RAWIO, SYS_BOOT, BPF, PERFMON, or the literal ``ALL``.

**Recommended action**

Drop every capability and add back only what the workload actually needs:

    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]   # only if binding <1024

Most stateless services need no capabilities at all. Avoid ``SYS_ADMIN`` (effectively root), ``SYS_PTRACE`` (process snooping), ``NET_ADMIN`` (raw socket access), and ``SYS_MODULE`` (kernel module loading).

## K8S-010 — Container seccompProfile not RuntimeDefault or Localhost
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV

Pod-level ``securityContext.seccompProfile`` covers all containers in the pod. Either path passes this rule. The default of ``Unconfined`` (or unset, which inherits the node default — usually Unconfined) fails.

**Recommended action**

Set ``securityContext.seccompProfile.type: RuntimeDefault`` (or ``Localhost`` with a path to your tuned profile) at either pod or container level. Without seccomp, every syscall is reachable from the container — modern kernel CVEs (e.g. ``io_uring``) become trivially exploitable.

## K8S-011 — Pod serviceAccountName unset or 'default'
**Severity:** MEDIUM · OWASP CICD-SEC-2 · ESF ESF-D-LEAST-PRIV

Both an unset ``serviceAccountName`` (which defaults to ``default``) and an explicit ``serviceAccountName: default`` fail the rule. Pair this with K8S-012 to also disable token auto-mounting where the workload doesn't need API access.

**Recommended action**

Bind every workload to a dedicated, narrow ``ServiceAccount``. The 'default' SA exists in every namespace and tends to accrete RoleBindings over time — using it gives the workload every privilege any other service in the namespace ever needed. Create a per-workload SA with the minimum RBAC needed and reference it via ``spec.serviceAccountName``.

## K8S-012 — Pod automountServiceAccountToken not false
**Severity:** MEDIUM · OWASP CICD-SEC-2, CICD-SEC-6 · ESF ESF-D-LEAST-PRIV

An unset value defaults to True in Kubernetes — this rule fails on unset because most application workloads do NOT need API access and the default exposes credentials by accident. Workloads that explicitly call the API should set the field to ``true`` so the choice is visible in code review.

**Recommended action**

Set ``spec.automountServiceAccountToken: false`` on every workload that doesn't need to talk to the Kubernetes API. Auto-mounted SA tokens are a free credential for an attacker who lands a shell — without explicit opt-out the token sits at ``/var/run/secrets/kubernetes.io/serviceaccount/token`` ready to be exfiltrated. If the workload needs API access, leave it true but pair with a tight, dedicated RBAC role.

## K8S-013 — Pod uses a hostPath volume
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV, ESF-D-ISOLATION

Some legitimate system DaemonSets need hostPath (log collectors, CSI node plugins). Those should be deployed with explicit security review and a narrow ``path:``; this rule fires regardless because *application* workloads should never use hostPath.

**Recommended action**

Replace ``hostPath`` volumes with ``configMap``, ``secret``, ``emptyDir``, ``persistentVolumeClaim``, or CSI volumes. ``hostPath`` opens a direct read/write window onto the node's filesystem; combined with even mild container compromise it gives the attacker access to other pods' data, kubelet credentials, and the container runtime.

## K8S-014 — Pod hostPath references a sensitive host directory
**Severity:** CRITICAL · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV, ESF-D-ISOLATION

Stricter than K8S-013: that rule flags any hostPath, this one upgrades to CRITICAL when the path is one of the well-known cluster-escape vectors.

**Recommended action**

Never mount the container runtime socket (``/var/run/docker.sock``, ``containerd.sock``, ``crio.sock``), kubelet credentials (``/var/lib/kubelet``), the cluster config (``/etc/kubernetes``), the host root (``/``), or ``/proc`` / ``/sys`` / ``/etc`` into a workload container. Each of these is a one-line cluster takeover. If a container genuinely needs node-level metrics, use an exporter DaemonSet with a narrowly-scoped read-only mount.

## K8S-015 — Container missing resources.limits.memory
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV

Init containers and ephemeral containers are also checked: a leaking init container holds a slot on the node until it completes and can crowd out other pods just as readily as an application container.

**Recommended action**

Set ``resources.limits.memory`` on every container. Without a memory limit, a leaking or compromised container can consume the node's RAM until the kernel OOM-kills neighbouring pods, taking down workloads that share the node. Pair the limit with a ``requests.memory`` to inform the scheduler.

## K8S-016 — Container missing resources.limits.cpu
**Severity:** LOW · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV

Lower severity than K8S-015 because CPU throttling is self-healing (workloads slow down rather than die) and some controllers (e.g. SchedulerProfile, LimitRange) supply a cluster-default cpu limit transparently.

**Recommended action**

Set ``resources.limits.cpu`` on every container. CPU throttling is the kernel's defense against a neighbour consuming all node cycles — without a limit, a compromised container can stall everything else on the node, including the kubelet. Pair the limit with a ``requests.cpu`` for scheduling.

## K8S-017 — Container env value carries a credential-shaped literal
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Reuses ``_primitives/secret_shapes`` — flags AKIA-prefixed AWS access keys outright, plus credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal. ``valueFrom`` entries are always safe (no inline value).

**Recommended action**

Replace literal ``env[].value`` entries that hold credentials with ``env[].valueFrom.secretKeyRef`` or ``envFrom.secretRef``. A literal env value lives in the manifest YAML — it gets committed to git, surfaced by ``kubectl get pod -o yaml``, and embedded in audit logs. Externalising into a Secret (and ideally a SealedSecret / ExternalSecret / SOPS-encrypted source) keeps the value out of the manifest.

## K8S-018 — Secret stringData/data carries a credential-shaped literal
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Walks both ``stringData`` (plain text) and ``data`` (base64). Base64-encoded values are decoded and checked for AKIA-shaped AWS keys. Credential-shaped key NAMES with any non-empty value are flagged regardless of encoding — even if the value is the literal placeholder ``REPLACE_ME``, having the name in the manifest is a maintenance footgun.

**Recommended action**

A ``Kind: Secret`` manifest committed to git defeats every secret-management story Kubernetes claims to provide — the base64 encoding in ``data`` is *not* encryption. Replace with SealedSecrets (Bitnami), ExternalSecrets / ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent injection. If the manifest must remain in git, the only acceptable contents are placeholders that are filled in by an operator at apply time.

## K8S-019 — Workload deployed in the 'default' namespace
**Severity:** LOW · OWASP CICD-SEC-2 · ESF ESF-D-LEAST-PRIV

Severity is LOW because in a well-curated cluster the default namespace is empty by policy. If your cluster treats default as a sandbox you can suppress this rule via ``.pipelinecheckignore``.

**Recommended action**

Set ``metadata.namespace`` to a dedicated namespace per workload (or per environment). The ``default`` namespace tends to accumulate cluster-wide RoleBindings, NetworkPolicies, and operators that grant broader access than intended; placing application workloads there means every privilege grant in default applies to them. A purpose-built namespace also lets you enforce Pod Security Standards (``pod-security.kubernetes.io/enforce`` label) scoped to that workload.

## K8S-020 — ClusterRoleBinding grants cluster-admin or system:masters
**Severity:** CRITICAL · OWASP CICD-SEC-2, CICD-SEC-5 · ESF ESF-D-LEAST-PRIV

The rule fires on a ``ClusterRoleBinding`` whose ``roleRef.name`` is ``cluster-admin``, ``admin``, or ``system:masters``. Subject type does not matter — even binding cluster-admin to a Group is a cluster-takeover risk.

**Recommended action**

Replace cluster-admin / system:masters bindings with narrowly-scoped ClusterRoles or namespace-scoped Roles. Granting cluster-admin to a service account is equivalent to giving every pod that uses it root on every node — credential theft from any such pod becomes immediate cluster takeover. Audit-log every existing cluster-admin binding and replace each with the minimum verbs/resources the consumer actually needs.

## K8S-021 — Role or ClusterRole grants wildcard verbs+resources
**Severity:** HIGH · OWASP CICD-SEC-2, CICD-SEC-5 · ESF ESF-D-LEAST-PRIV

Fires on any rule entry where BOTH ``verbs`` and ``resources`` contain a literal ``"*"``. A wildcard in only one of the two is still risky but is often a legitimate read-everything pattern (e.g. monitoring); this rule targets the strict superset 'do anything to everything'.

**Recommended action**

Replace ``verbs: ["*"]`` and ``resources: ["*"]`` with explicit lists. Wildcards bypass the principle of least privilege: today they grant `read pods` and tomorrow they grant `delete crds` because a new resource was registered in that apiGroup. Explicit verbs (``get``, ``list``, ``watch``) and explicit resources (``configmaps``, ``services``) keep grants stable across cluster upgrades.

## K8S-022 — Service exposes SSH (port 22)
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV

Mirrors DF-013 (``EXPOSE 22`` in a Dockerfile) at the Service level. The check fires on Service ports whose ``port`` or ``targetPort`` is 22, regardless of Service type — a NodePort/LoadBalancer 22 is dramatically worse but a ClusterIP 22 still indicates an sshd container somewhere.

**Recommended action**

Containers should not run sshd. If you need an interactive shell into a running pod, use ``kubectl exec`` (subject to RBAC) or ``kubectl debug``. Removing the port-22 Service removes a pre-auth network surface that's a frequent lateral-movement target after initial cluster compromise.

## K8S-023 — Namespace missing Pod Security Admission enforcement label
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV, ESF-D-NETWORK-SEG

Pod Security Admission (PSA) replaced the deprecated PodSecurityPolicy in 1.25. The three levels are ``privileged``, ``baseline``, and ``restricted``; ``baseline`` is a sensible production default and ``restricted`` matches the spirit of K8S-005..010. ``kube-system`` is exempt by convention since control-plane pods may legitimately need elevated permissions.

**Recommended action**

Set ``metadata.labels.pod-security.kubernetes.io/enforce`` to ``baseline`` or ``restricted`` on every Namespace. Without an enforce label the namespace runs the cluster's default policy, which on most installations is ``privileged`` and silently admits pods that violate every K8S-002..010 rule.

## K8S-024 — Container missing both livenessProbe and readinessProbe
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-MONITOR

Init containers and ephemeral debug containers are exempt — neither makes sense to probe. Jobs and CronJobs are also exempt because Kubernetes treats them as one-shot work; completion is the lifecycle signal, not health.

**Recommended action**

Define at least one of ``livenessProbe`` or ``readinessProbe`` on every long-running container. Without probes, a wedged pod stays listed as ``Running`` and keeps receiving traffic, which masks incidents and amplifies the blast radius of a single faulty replica.

## K8S-025 — System priority class used outside kube-system
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-LEAST-PRIV

The kubelet reserves the two ``system-*`` priority classes for its own pods (kube-proxy, CNI agents). Granting them to a user workload also grants the right to preempt and evict anything below 2000000000, which is every non-system pod on the cluster. Outside kube-system this is almost always a misconfiguration copy-pasted from a control-plane manifest.

**Recommended action**

Reserve ``system-cluster-critical`` and ``system-node-critical`` priority classes for control-plane workloads in ``kube-system``. Application pods that adopt them gain the right to evict normal workloads under resource pressure, which is a quiet path to a cluster-wide outage if the application has a bug or the attacker has any control over its spec.

## K8S-026 — LoadBalancer Service has no loadBalancerSourceRanges
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-NETWORK-SEG

Internal-only services should use ``type: ClusterIP`` (and an Ingress for HTTP) or set the cloud-provider-specific internal-LB annotation. ``loadBalancerSourceRanges`` is the Kubernetes-native, cloud-portable way to scope an external LB; cloud-specific firewalls (AWS security groups, GCP firewall rules) are equivalent at the L4 level but invisible to a manifest scanner.

**Recommended action**

Restrict every ``Service`` of ``type: LoadBalancer`` with ``spec.loadBalancerSourceRanges``. The default behavior is to provision an internet-facing load balancer that accepts traffic from 0.0.0.0/0, which exposes whatever the Service fronts to the entire internet. A short list of CIDRs scoped to known clients (office IPs, a NAT gateway, peered VPCs) removes the pre-auth attack surface entirely.

---

## Adding a new Kubernetes check

1. Create a new module at
   `pipeline_check/core/checks/kubernetes/rules/k8sNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) ->
   Finding` function. The orchestrator auto-discovers it.
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
