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

13 checks · 2 have an autofix patch (``--fix``).

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

---

<div class="pg-rule pg-rule--high" markdown>

## ARGO-001: Argo template container image not pinned to a digest { #argo-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Walks ``spec.templates[].container``, ``spec.templates[].script``, and ``spec.templates[].containerSet.containers[]``. The image must contain ``@sha256:`` followed by a 64-char hex digest.

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

Detection fires on ``securityContext.privileged: true``, ``runAsUser: 0``, ``runAsNonRoot: false``, ``allowPrivilegeEscalation: true``, or no ``securityContext`` block at all. Also walks ``spec.podSpecPatch`` (raw YAML) for an explicit ``privileged: true`` token.

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

Strong matches: AWS access keys, GitHub PATs, JWTs. Weak match: env var name suggests a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) and the value is a non-empty literal rather than an interpolation.

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

Walks ``script.source`` and joined ``container.args`` text with the cross-provider ``CURL_PIPE_RE`` and ``TLS_BYPASS_RE`` regexes.

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

An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog: syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool. Fires only on artifact-producing Workflows.

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

Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``witness run``, ``attest-build-provenance``).

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

Vulnerability scanning sits at a different layer from signing and SBOM. It answers *does this artifact ship a known CVE?* rather than *can we verify what it is?*. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, osv-scanner, govulncheck, anchore, codeql-action, semgrep, bandit, checkov, tfsec. Walks every Argo document and passes if any document includes a scanner reference.

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
