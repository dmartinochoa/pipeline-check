# Argo Workflows provider

Parses Argo API documents (`apiVersion: argoproj.io/*`) from `.yaml`
/ `.yml` files on disk, text-only static analysis, no `argo` binary,
no cluster access. Recognized kinds: `Workflow`, `WorkflowTemplate`,
`ClusterWorkflowTemplate`, `CronWorkflow`. Documents that don't
carry an `argoproj.io/*` apiVersion are silently skipped.

## Producer workflow

```bash
pipeline_check --pipeline argo --argo-path workflows/

# A single workflow file works too.
pipeline_check --pipeline argo --argo-path workflows/release.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Argo-specific checks

- **ARGO-005**, `{{inputs.parameters.X}}` substitution happens
  before the shell parses the script, so any unquoted use in
  `script.source` / `container.args` is a command-injection
  primitive. Pass the parameter via `env:` and reference quoted.
- **ARGO-003**, `Workflow` / `CronWorkflow` must set
  `serviceAccountName`. Workflows that fall back to the namespace's
  `default` SA inherit whatever role someone later binds to
  `default`.

## What it covers

18 checks · 2 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [ARGO-001](#argo-001) | Argo template container image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ARGO-002](#argo-002) | Argo template container runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ARGO-003](#argo-003) | Argo workflow uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ARGO-004](#argo-004) | Argo workflow mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ARGO-005](#argo-005) | Argo input parameter interpolated unsafely in script / args | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ARGO-006](#argo-006) | Literal secret value in Argo template env or parameter default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ARGO-007](#argo-007) | Argo workflow has no activeDeadlineSeconds | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [ARGO-008](#argo-008) | Argo script source pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ARGO-009](#argo-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ARGO-010](#argo-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ARGO-011](#argo-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ARGO-012](#argo-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ARGO-013](#argo-013) | Argo workflow does not opt out of SA token automount | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ARGO-014](#argo-014) | Argo template script runs unpinned package install | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ARGO-015](#argo-015) | Input artifact pulls from an insecure (non-HTTPS) URL | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ARGO-016](#argo-016) | Workflow bound to a cluster-admin / over-privileged ServiceAccount | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ARGO-017](#argo-017) | Argo resource template applies a manifest built from an untrusted parameter | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [TAINT-007](#taint-007) | Untrusted input flows across templates via Argo ``outputs.parameters`` | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## ARGO-001: Argo template container image not pinned to a digest { #argo-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Walks ``spec.templates[].container``, ``spec.templates[].script``, ``spec.templates[].containerSet.containers[]``, ``spec.templates[].initContainers[]``, and ``spec.templates[].sidecars[]``. The image must contain ``@sha256:`` followed by a 64-char hex digest.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every container / script template image to a content-addressable digest (``alpine@sha256:<digest>``). Tag-only references (``alpine:3.18``) and rolling tags (``alpine:latest``) let a compromised registry update redirect the workflow's containers at the next pull, with no audit trail in the WorkflowTemplate.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ARGO-002: Argo template container runs privileged or as root { #argo-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Detection fires on ``securityContext.privileged: true``, ``runAsUser: 0``, ``runAsNonRoot: false``, ``allowPrivilegeEscalation: true``, or no ``securityContext`` block at all. Walks ``spec.templates[].container``, ``spec.templates[].script``, ``spec.templates[].containerSet.containers[]``, ``spec.templates[].initContainers[]``, and ``spec.templates[].sidecars[]``. Also walks ``spec.podSpecPatch`` (raw YAML) for an explicit ``privileged: true`` token.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``securityContext.privileged: false``, ``runAsNonRoot: true``, and ``allowPrivilegeEscalation: false`` on every template container / script. A privileged container shares the node's kernel namespaces; a malicious image then has root on the build node and breaks the boundary between workflow and cluster.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ARGO-003: Argo workflow uses the default ServiceAccount { #argo-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-IAM</span> <span class="pg-tag pg-tag--cwe">CWE-250</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Applies to ``Workflow`` and ``CronWorkflow``. ``WorkflowTemplate`` / ``ClusterWorkflowTemplate`` are exempt because the SA is set on the run that references them. An explicit ``serviceAccountName: default`` is treated the same as omission.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``spec.serviceAccountName`` (or ``spec.workflowSpec.serviceAccountName`` for CronWorkflow) to a least-privilege ServiceAccount that carries only the secrets and RBAC the workflow needs. Falling back to the namespace's ``default`` SA grants access to whatever cluster-admin or wildcard role someone later binds to ``default``, a privilege-escalation surface that should never be load-bearing for workflow pods.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ARGO-004: Argo workflow mounts hostPath or shares host namespaces { #argo-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-250</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

Walks ``spec.volumes[].hostPath`` and the raw ``spec.podSpecPatch`` string for ``hostNetwork``, ``hostPID``, ``hostIPC``, and ``hostPath``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use ``emptyDir`` or PVC-backed volumes instead of ``hostPath``. Drop ``hostNetwork: true`` / ``hostPID: true`` / ``hostIPC: true`` from any inline ``podSpecPatch``. A hostPath mount of ``/var/run/docker.sock`` or ``/`` lets the workflow break out of the pod and act as the underlying node.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ARGO-005: Argo input parameter interpolated unsafely in script / args { #argo-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

Fires on any ``{{inputs.parameters.X}}``, ``{{workflow.parameters.X}}``, or ``{{item.X}}`` token inside a ``script.source`` body or a ``container.args`` string that isn't already wrapped in quotes. Doesn't fire on the env-var indirection pattern, which is safe.

**Known false-positive modes**

- Parameters whose values are always controlled by trusted templates (a fixed enum, an internal SHA, an upstream service identifier the workflow generates itself) are safe to interpolate unquoted but the rule has no way to see the producer. Suppress per-template with ``--ignore-file`` once you've verified the parameter source can't reach a user. Quoted forms (``"{{inputs.parameters.X}}"``) are already excluded by the negative-lookbehind, so the typical safe pattern doesn't false-positive.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't interpolate ``{{inputs.parameters.<name>}}`` directly into ``script.source`` or ``container.args``. Argo substitutes the value before the shell parses it, so a parameter containing ``; rm -rf /`` runs as shell. Pass the parameter via ``env:`` (``value: '{{inputs.parameters.<name>}}'``) and reference the env var quoted in the script (``"$NAME"``); or use ``inputs.artifacts`` for file payloads.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ARGO-006: Literal secret value in Argo template env or parameter default { #argo-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Strong matches: AWS access keys, GitHub PATs, JWTs. Weak match: env var name suggests a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) and the value is a non-empty literal rather than an interpolation. Known false positives for the weak-match path: cache or partition keys (``CACHE_KEY``, ``REDIS_KEY``, ``DYNAMO_PARTITION_KEY``); path variables whose name contains ``_KEY_PATH`` or ``_KEY_FILE`` (``SSH_PRIVATE_KEY_PATH``); names where ``KEY`` is followed by a non-secret suffix such as ``_PREFIX``, ``_INDEX``, or ``_NAME``. These are excluded by the rule logic and will not fire.

<div class="pg-rule__rec" markdown>

**Recommended action**

Mount secrets via ``env.valueFrom.secretKeyRef`` (or a ``volumes:`` Secret mount) instead of writing the value into ``env.value`` or ``arguments.parameters[].value``. Workflow manifests are committed to git and cluster-readable; literal values leak through normal access paths.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## ARGO-007: Argo workflow has no activeDeadlineSeconds { #argo-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Applies to ``Workflow``, ``CronWorkflow``, ``WorkflowTemplate``, and ``ClusterWorkflowTemplate``. The field can sit at the workflow level or on individual templates.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``spec.activeDeadlineSeconds`` (or ``spec.workflowSpec.activeDeadlineSeconds`` on a ``CronWorkflow``) so a hung step can't pin the workflow controller's reconcile cycle indefinitely. Pick a value generous enough for the slowest legitimate run (e.g. 3600 for a typical pipeline, 21600 for ML training). Per-template ``activeDeadlineSeconds`` is also accepted as evidence of intent.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ARGO-008: Argo script source pipes remote install or disables TLS { #argo-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-D-COMMS-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-295</span>
</div>

Walks ``script.source`` and joined ``container.args`` text with the cross-provider ``_primitives.remote_script_exec`` and ``_primitives.tls_bypass`` detectors. Coverage stays aligned with GHA-016 / GHA-027 / BK-004 / BK-008 / TKN-008 / GCB-010 / GCB-011 / DF-004.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``curl ... | sh`` with a download-then-verify-then-execute pattern. Drop TLS-bypass flags (``curl -k``, ``git config http.sslverify false``); install the missing CA into the template image instead. Both forms let an attacker controlling DNS / a transparent proxy substitute the script the workflow runs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ARGO-009: Artifacts not signed (no cosign/sigstore step) { #argo-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Detection mirrors GHA-006 / TKN-009 / BK-009, the shared signing-token catalog (cosign, sigstore, slsa-github-generator, slsa-framework, notation-sign) is searched across every string in each Argo document. Fires only on artifact-producing Workflows / WorkflowTemplates (those that invoke ``docker build`` / ``docker push`` / kaniko / ``helm upgrade`` / ``aws s3 sync`` / etc.) so lint-only Workflows don't trip it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a cosign step to the Workflow. The most common shape is a final ``sign`` template that runs ``cosign sign --yes <repo>@sha256:<digest>`` after the build. Sign by digest, not tag, so a re-pushed tag can't bypass the signature.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ARGO-010: No SBOM generated for build artifacts { #argo-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog: syft, cyclonedx, cdxgen, anchore/sbom-action, spdx-sbom-generator, microsoft/sbom-tool. Fires only on artifact-producing Workflows.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an SBOM-generation template. ``syft <artifact> -o cyclonedx-json > /tmp/sbom.json`` runs in any standard container; ``cyclonedx-cli`` and ``cdxgen`` are alternative producers. Persist the SBOM as an output artifact so downstream templates and consumers can read it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ARGO-011: No SLSA provenance attestation produced { #argo-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto-attestation``, ``witness run``, ``attest-build-provenance``).

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``cosign attest --predicate slsa.json --type slsaprovenance <ref>`` step after the build template, or use ``witness run`` to record the build environment. Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ARGO-012: No vulnerability scanning step { #argo-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Vulnerability scanning sits at a different layer from signing and SBOM. It answers *does this artifact ship a known CVE?* rather than *can we verify what it is?*. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, osv-scanner, govulncheck, codeql-action, semgrep, bandit, checkov, tfsec. Walks every Argo document and passes if any document includes a scanner reference.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a vulnerability scanner template. ``trivy fs /workdir`` for source / filesystem; ``trivy image <ref>`` for container images. ``grype``, ``snyk``, ``npm audit``, ``pip-audit`` are alternatives. Fail the template on findings above a chosen severity so a regression blocks the merge instead of shipping.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ARGO-013: Argo workflow does not opt out of SA token automount { #argo-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Companion to ARGO-003 (default ServiceAccount). The default SA only matters when its token is mounted; an explicit ``automountServiceAccountToken: false`` removes the token from the pod regardless of which SA the pod is bound to. Detection: workflow passes when the spec sets it to ``false`` AND every template either inherits that or sets its own ``automountServiceAccountToken: false``. A template with it explicitly ``true`` (or unset against an unset spec-level value) is the failing shape.

**Known false-positive modes**

- Templates that genuinely need to call the Kubernetes API (GitOps pull, ``kubectl apply`` from inside the workflow). Set ``automountServiceAccountToken: true`` on that template specifically and bind it to a least-privilege SA, the rule then fires only on the broad spec-level absence, which is the actual gap.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``spec.automountServiceAccountToken: false`` on the Workflow / WorkflowTemplate, or per-template (``templates[].automountServiceAccountToken: false``) on any template that doesn't need to talk to the Kubernetes API. An explicit ``false`` keeps a compromised step from using the workflow's SA token to escalate inside the cluster, even when the SA itself is hardened (ARGO-003), a token automounted into every pod widens the leak surface.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ARGO-014: Argo template script runs unpinned package install { #argo-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Detection reuses the cross-provider primitives ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from ``checks/base.py``. Same rule pack already exists for GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / ``GL-022``), Bitbucket Pipelines / Azure DevOps / Jenkins / CircleCI / Google Cloud Build / Buildkite / Tekton / Drone. Argo was a gap; this closes it.

Walks ``script.source`` plus joined ``container.args`` / ``container.command`` text per template. Steps and tasks across DAG / steps templates are equally in scope because they all reduce to a container with a shell payload.

**Known false-positive modes**

- Bootstrap-stage installs that intentionally pull latest (``apt-get install -y curl`` for a tooling image rebuild) sometimes legitimately bypass the lockfile. Suppress via ignore-file scoped to the specific template name.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every package install to a lockfile or a checksum-verified version. ``npm ci`` (not ``npm install``), ``yarn install --frozen-lockfile``, ``pip install -r requirements.txt --require-hashes``, ``bundle install --frozen``. Don't use ``--trusted-host`` / ``--no-verify`` / a non-HTTPS index URL — those bypass TLS or trust validation entirely (ARGO-008 covers the TLS subset; this rule covers the lockfile subset).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ARGO-015: Input artifact pulls from an insecure (non-HTTPS) URL { #argo-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-D-COMMS-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-319</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Argo Workflows resolves input artifacts before the template's container starts. The source can be ``http``, ``git``, ``s3``, ``gcs``, ``azure``, ``hdfs``, ``oss``, or ``raw``. The rule fires when:

- ``http.url`` starts with ``http://`` (cleartext fetch)
- ``git.repo`` starts with ``git://`` (legacy unauthenticated git protocol, no integrity)
- ``s3.endpoint`` is set with ``insecure: true`` (explicit TLS bypass)

Other artifact sources are skipped, an OCI / S3 / GCS pull carries its own integrity / signing posture that lives outside this rule.

**Known false-positive modes**

- Local-mirror development workflows occasionally use ``http://`` against an internal registry that's only reachable from a private network. The integrity guarantee still relies on network isolation rather than transport encryption; suppress on the specific template name when this is the deliberate shape.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pull every input artifact over HTTPS. Replace ``http://`` with ``https://`` in any ``http.url:`` block, and use ``https://`` git remote URLs instead of ``git://``, ``ssh://``-without-key-pinning, or anonymous-cleartext access. Plain HTTP fetches let any on-path attacker swap the artifact bytes for a different payload, and Argo will execute whatever bytes arrive without an integrity check unless the artifact source provides one (S3 + checksum, OCI + digest). If the artifact source genuinely doesn't ship over HTTPS (a legacy internal mirror), wrap it in a CDN or proxy that adds TLS, then pin the artifact by checksum on the consuming side.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ARGO-016: Workflow bound to a cluster-admin / over-privileged ServiceAccount { #argo-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-IAM</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Fires when a Workflow / CronWorkflow sets ``spec.serviceAccountName`` to a name that signals a cluster-wide admin binding (``cluster-admin``, or a name containing ``cluster-admin``, ``admin``, ``root``, ``superuser``). The actual privilege lives in the RBAC ``ClusterRoleBinding``, which isn't visible in the Workflow, so this is a name-based heuristic (MEDIUM confidence) for the common copy-paste shape; the broader case (an innocuously-named SA bound to cluster-admin) needs the RBAC manifest. Distinct from ARGO-003, which flags the *default* SA.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't run a Workflow as a cluster-admin / superuser ServiceAccount. Create a dedicated SA scoped to the workflow's namespace and bind it (via a namespaced ``Role`` / ``RoleBinding``) to only the verbs and resources the workflow needs. A workflow running as ``cluster-admin`` lets any step, or any code injected into a step, use the automounted token to act cluster-wide: read every secret, schedule privileged pods on any node, and grant itself more roles.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ARGO-017: Argo resource template applies a manifest built from an untrusted parameter { #argo-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-77</span>
</div>

Fires when a `resource` template with `action: create` / `apply` / `patch` / `replace` has an inline `manifest:` string containing a `{{...parameters...}}` or `{{item...}}` token. The manifest is K8s-object injection, not shell injection, so it fires regardless of quoting (ARGO-005's quoting carve-out does not apply) and `iter_containers` never visits `resource` templates, so no other rule sees this sink. A caller who can set the parameter (a webhook / Sensor, or anyone with Submit on the template) creates attacker-chosen objects, e.g. a privileged Pod or a cluster-admin binding, under the workflow's SA.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't interpolate `{{inputs.parameters.X}}` / `{{workflow.parameters.X}}` / `{{item}}` into a `resource` template's `manifest:` when `action:` is `create` / `apply` / `patch` / `replace`. Argo substitutes the value into the manifest text before `kubectl` applies it, so a parameter carrying YAML injects arbitrary fields or whole objects, applied by the workflow's ServiceAccount. Build the object from a fixed template and pass only scalar leaf values through `kubectl` field args, restrict who can set the parameter, and scope the ServiceAccount's RBAC to the exact objects the workflow needs.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TAINT-007: Untrusted input flows across templates via Argo ``outputs.parameters`` { #taint-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detection walks every workflow document with ``spec.templates``. Pass 1 looks for templates that declare ``outputs.parameters`` AND whose inline ``script.source`` interpolates ``{{inputs.parameters.<X>}}``, recording the template's outputs as tainted. Pass 2 walks each template's DAG / Steps orchestrator for tasks whose ``arguments.parameters[*].value`` is ``{{tasks.<producer>.outputs.parameters.<X>}}`` matching a recorded leak. Pass 3 walks the consumer task's referenced template for the matching ``{{inputs.parameters.<consumer-param>}}`` reference in its script body and emits one path per match.

v1 limitations: ``workflowTemplateRef:`` cross-document references aren't resolved (would need the same machinery as the GHA ``--resolve-remote`` flow). ``onExit:`` exit handlers aren't yet walked.

**Known false-positive modes**

- If the producer template runs a sanitizer between the tainted ``{{inputs.parameters.X}}`` interpolation and the output-path write, the consumer is no longer exploitable but TAINT-007 still fires. Suppress via ignore-file scoped to the consumer template name when this is the deliberate shape; the sanitizer is then load-bearing.

<div class="pg-rule__rec" markdown>

**Recommended action**

Sanitize the value at the producer template before it lands in an output parameter. The canonical safe pattern is to surface ``{{inputs.parameters.<X>}}`` into a quoted shell variable, run a sanitizer (``tr -dc 'a-zA-Z0-9 '`` for a freeform title), and only then redirect the cleaned value to the output path. The consumer template should still reference ``{{inputs.parameters.<name>}}`` quoted (``"{{inputs.parameters.title}}"``) and never inline into a command without re-quoting. Removing the cross-template forwarding is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitizer is doing what you think before relying on it.

</div>

</div>

---

## Adding a new Argo Workflows check

1. Create a new module at
   `pipeline_check/core/checks/argo/rules/argoNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(ctx: ArgoContext) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the ``ArgoContext``.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/argo/ARGO-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py argo
   ```
