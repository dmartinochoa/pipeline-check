# Tekton provider

Parses Tekton API documents (`apiVersion: tekton.dev/*`) from `.yaml`
/ `.yml` files on disk, text-only static analysis, no `tkn` binary,
no cluster access. Recognized kinds: `Task`, `ClusterTask`,
`Pipeline`, `TaskRun`, `PipelineRun`. Documents that don't carry a
`tekton.dev/*` apiVersion are silently skipped, so a directory mixing
Tekton with plain Kubernetes manifests is safe to point at.

## Producer workflow

```bash
pipeline_check --pipeline tekton --tekton-path tekton/

# A single multi-document file works too.
pipeline_check --pipeline tekton --tekton-path tekton/build-task.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Tekton-specific checks

- **TKN-003**. Tekton substitutes `$(params.X)` *before* the shell
  parses the script, so any unquoted use is a command-injection
  primitive. The safe pattern is to receive the parameter through
  `env:` and reference the env var quoted (`"$NAME"`).
- **TKN-007**, `TaskRun` / `PipelineRun` must set
  `serviceAccountName` to a least-privilege ServiceAccount. The
  default SA inherits whatever cluster-admin or wildcard role
  someone later binds to it.

## What it covers

13 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [TKN-001](#tkn-001) | Tekton step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TKN-002](#tkn-002) | Tekton step runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TKN-003](#tkn-003) | Tekton param interpolated unsafely in step script | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [TKN-004](#tkn-004) | Tekton Task mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [TKN-005](#tkn-005) | Literal secret value in Tekton step env or param default | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [TKN-006](#tkn-006) | Tekton run lacks an explicit timeout | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [TKN-007](#tkn-007) | Tekton run uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [TKN-008](#tkn-008) | Tekton step script pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TKN-009](#tkn-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [TKN-010](#tkn-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [TKN-011](#tkn-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [TKN-012](#tkn-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [TKN-013](#tkn-013) | Tekton sidecar runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## TKN-001: Tekton step image not pinned to a digest { #tkn-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Applies to ``Task`` and ``ClusterTask`` kinds. The image must contain ``@sha256:`` followed by a 64-char hex digest. Any tag-only reference, including ``:latest``, fails.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every step image to a content-addressable digest (``gcr.io/tekton-releases/git-init@sha256:<digest>``). Tag-only references (``alpine:3.18``) and rolling tags (``alpine:latest``) let a compromised registry update redirect the step at the next pull, with no audit trail in the Task manifest.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TKN-002: Tekton step runs privileged or as root { #tkn-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Detection fires on a step with ``securityContext.privileged: true``, ``securityContext.runAsUser: 0``, ``securityContext.runAsNonRoot: false``, ``securityContext.allowPrivilegeEscalation: true``, or no ``securityContext`` block at all.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``securityContext.privileged: false``, ``runAsNonRoot: true``, and ``allowPrivilegeEscalation: false`` on every step. A privileged step shares the node's kernel namespaces; a malicious or compromised step image then has root on the build node, breaking the boundary between build and cluster.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## TKN-003: Tekton param interpolated unsafely in step script { #tkn-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

Fires on any ``$(params.X)`` or ``$(workspaces.X.path)`` token inside a ``script:`` body that isn't already wrapped in double quotes (`"$(params.X)"`). Doesn't fire on the env-var indirection pattern, which is safe.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't interpolate ``$(params.<name>)`` directly into the step ``script:``. Tekton substitutes the value before the shell parses it, so a parameter containing ``; rm -rf /`` runs as shell. Receive the parameter through ``env:`` (``valueFrom: ...`` or ``value: $(params.<name>)``) and reference the env var quoted in the script (``"$NAME"``); or pass it as a positional argument to a shell function.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## TKN-004: Tekton Task mounts hostPath or shares host namespaces { #tkn-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-250</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

Checks ``spec.volumes[].hostPath`` (legacy v1beta1 form), ``spec.workspaces[].volumeClaimTemplate.spec.storageClassName == 'hostpath'``, and ``spec.podTemplate`` host-namespace flags.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use Tekton ``workspaces:`` backed by ``emptyDir`` or ``persistentVolumeClaim`` instead of ``hostPath``. Drop ``hostNetwork: true`` / ``hostPID: true`` / ``hostIPC: true`` on the Task's ``podTemplate``. A hostPath mount of ``/var/run/docker.sock`` or ``/`` lets the build break out of the pod and act as the underlying node.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## TKN-005: Literal secret value in Tekton step env or param default { #tkn-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Strong matches: AWS access keys, GitHub PATs, JWTs. Weak match: env var name suggests a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) and the value is a non-empty literal rather than a ``$(params.X)`` / ``valueFrom`` reference.

<div class="pg-rule__rec" markdown>

**Recommended action**

Mount secrets via ``env.valueFrom.secretKeyRef`` (or a ``volumes:`` Secret mount) instead of writing the value into ``env.value`` or ``params[].default``. Task manifests are committed to git and cluster-readable; literal values leak through normal access paths.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## TKN-006: Tekton run lacks an explicit timeout { #tkn-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Applies to ``PipelineRun``, ``TaskRun``, and ``Pipeline``. For Pipelines, the rule looks for ``spec.tasks[].timeout`` as evidence of intent. ``Task`` / ``ClusterTask`` themselves don't carry a timeout, the timeout lives on the concrete run.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``spec.timeouts.pipeline`` (or ``spec.timeout`` on a TaskRun) on every PipelineRun and TaskRun. A misbehaving step otherwise pins a build pod for the cluster's default timeout (1h). For long jobs, set a generous explicit value (``2h``, ``6h``) rather than leaving it implicit.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## TKN-007: Tekton run uses the default ServiceAccount { #tkn-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-IAM</span> <span class="pg-tag pg-tag--cwe">CWE-250</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

An explicit ``serviceAccountName: default`` setting is treated the same as omission.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``spec.serviceAccountName`` on every ``TaskRun`` and ``PipelineRun`` to a least-privilege ServiceAccount that carries only the secrets and RBAC the run actually needs. Falling back to the namespace's ``default`` SA grants access to whatever cluster-admin or wildcard role someone later binds to ``default``, a privilege-escalation surface that should never be load-bearing for build pods.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TKN-008: Tekton step script pipes remote install or disables TLS { #tkn-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-D-COMMS-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-295</span>
</div>

Uses the cross-provider ``CURL_PIPE_RE`` and ``TLS_BYPASS_RE`` regexes so detection is consistent with the GHA / GitLab / CircleCI / Cloud Build providers.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``curl ... | sh`` with a download-then-verify-then-execute pattern. Drop TLS-bypass flags (``curl -k``, ``git config http.sslverify false``); install the missing CA into the step image instead. Both forms let an attacker controlling DNS / a transparent proxy substitute the script the step runs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## TKN-009: Artifacts not signed (no cosign/sigstore step) { #tkn-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Detection mirrors GHA-006 / BK-009 / CC-006, the shared signing-token catalog (cosign, sigstore, slsa-github-generator, slsa-framework, notation-sign) is searched across every string in the Task / Pipeline document. The rule only fires on artifact-producing Tasks (those that invoke ``docker build`` / ``docker push`` / ``buildah`` / ``kaniko`` / ``helm upgrade`` / ``aws s3 sync`` / etc.) so lint-only Tasks don't trip it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a signing step to the Task, either a dedicated ``cosign sign`` step after the build, or use the official ``cosign`` Tekton catalog Task as a referenced step. The Task should sign by digest (``cosign sign --yes <repo>@sha256:<digest>``) so a re-pushed tag can't bypass the signature.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## TKN-010: No SBOM generated for build artifacts { #tkn-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog: syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool. Fires only on artifact-producing Tasks.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-json > $(workspaces.output.path)/sbom.json`` runs in the official ``syft`` Tekton catalog Task. ``cyclonedx-cli`` and ``cdxgen`` are alternatives. Publish the SBOM as a Workspace result so downstream Tasks can consume it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## TKN-011: No SLSA provenance attestation produced { #tkn-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Tekton Chains is the Tekton-native answer, once enabled on the cluster, every TaskRun's outputs are signed and attested without per-Task wiring. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``attest-build-provenance``, ``witness run``). Tasks produced by tekton-chains pass on the ``cosign attest`` match.

<div class="pg-rule__rec" markdown>

**Recommended action**

After the build step, run ``cosign attest --predicate slsa.json --type slsaprovenance <ref>`` (or use the ``tekton-chains`` controller, which signs and attests every TaskRun automatically when configured). Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## TKN-012: No vulnerability scanning step { #tkn-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Vulnerability scanning sits at a different layer from signing and SBOM. It answers *does this artifact ship a known CVE?* rather than *can we verify what it is?*. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, osv-scanner, govulncheck, anchore, codeql-action, semgrep, bandit, checkov, tfsec, dependency-check. Walks every Task / Pipeline / *Run document; passes if any document includes a scanner reference.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a vulnerability scanner step. ``trivy fs $(workspaces.src.path)`` for source / filesystem; ``trivy image <ref>`` for container images. The official Tekton catalog ships ``trivy-scanner`` and ``grype-scanner`` Tasks if you'd rather reference one. Fail the step on findings above a chosen severity so a regression blocks the merge instead of shipping.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TKN-013: Tekton sidecar runs privileged or as root { #tkn-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

TKN-002 hardens the ``spec.steps`` list. Tekton's ``spec.sidecars`` list runs alongside the steps in the same pod, but a sidecar's container image and command come from a separate place in the manifest, so a Task with hardened steps and a privileged sidecar (a common pattern when wrapping ``docker:dind``) leaves the same kernel-namespace gap TKN-002 was meant to close. The detection mirrors TKN-002: fires on a sidecar with ``securityContext.privileged: true``, ``runAsUser: 0``, ``runAsNonRoot: false``, ``allowPrivilegeEscalation: true``, or no ``securityContext`` block at all.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``securityContext.privileged: false``, ``runAsNonRoot: true``, and ``allowPrivilegeEscalation: false`` on every sidecar in ``spec.sidecars``. A privileged sidecar is the same escape vector as a privileged step, it shares the pod's network and kernel namespaces, and a compromised sidecar image owns the entire TaskRun's execution surface.

</div>

</div>

---

## Adding a new Tekton check

1. Create a new module at
   `pipeline_check/core/checks/tekton/rules/tknNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(ctx: TektonContext) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``TektonContext``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/tekton/TKN-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py tekton
   ```
