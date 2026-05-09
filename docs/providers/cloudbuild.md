# Google Cloud Build provider

Parses `cloudbuild.yaml` on disk, no Google Cloud credentials, no
`gcloud` install, no Cloud Build API token required. Each document
must declare a top-level `steps:` list; files without it (SAM
templates, ordinary YAML configs) are skipped by the loader.

## Producer workflow

```bash
# --cloudbuild-path is auto-detected when cloudbuild.yaml/cloudbuild.yml
# exists at cwd.
pipeline_check --pipeline cloudbuild

# …or pass it explicitly.
pipeline_check --pipeline cloudbuild --cloudbuild-path ci/cloudbuild.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Cloud Build-specific checks

Several checks target Cloud Build concepts that have no direct
analogue in other providers:

- **GCB-002**, `serviceAccount:` must be set; the default Cloud Build
  SA is typically broader than any single pipeline needs.
- **GCB-003**, secrets must flow through `availableSecrets.secret
  Manager[].env` + `secretEnv:`, never via inline `gcloud secrets
  versions access` in `args`.
- **GCB-004**, `options.dynamicSubstitutions: true` combined with a
  user-substitution (`$_FOO`) in step args opens a trigger-editor-
  controlled shell-injection path.

## What it covers

26 checks · 7 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GCB-001](#gcb-001) | Cloud Build step image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GCB-002](#gcb-002) | Cloud Build uses the default service account | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCB-003](#gcb-003) | Secret Manager value referenced in step args | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCB-004](#gcb-004) | dynamicSubstitutions on with user substitutions in step args | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCB-005](#gcb-005) | Build timeout unset or excessive | <span class="pg-sev pg-sev--low">LOW</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GCB-006](#gcb-006) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCB-007](#gcb-007) | availableSecrets references ``versions/latest`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GCB-008](#gcb-008) | No vulnerability scanning step in Cloud Build pipeline | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCB-009](#gcb-009) | Artifacts not signed (no cosign / sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCB-010](#gcb-010) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCB-011](#gcb-011) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GCB-012](#gcb-012) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GCB-013](#gcb-013) | Package install bypasses registry integrity (git / path / tarball) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCB-014](#gcb-014) | Build logging disabled (options.logging: NONE) | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GCB-015](#gcb-015) | SBOM not produced (no CycloneDX / syft / Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCB-016](#gcb-016) | Step dir field contains parent-directory escape (..) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCB-017](#gcb-017) | Image-producing build does not request SLSA provenance | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCB-018](#gcb-018) | Legacy KMS secrets block in use (prefer availableSecrets / Secret Manager) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCB-019](#gcb-019) | Shell entrypoint inlines a user substitution into args | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCB-020](#gcb-020) | serviceAccount points at the default Cloud Build service account | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GCB-021](#gcb-021) | No private worker pool, build runs on the shared default pool | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GCB-022](#gcb-022) | options.substitutionOption set to ALLOW_LOOSE | <span class="pg-sev pg-sev--low">LOW</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GCB-023](#gcb-023) | Step references a user substitution not declared in substitutions: | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GCB-024](#gcb-024) | Build pushes Docker images but top-level images: is empty | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GCB-025](#gcb-025) | Build has no tags for audit / discoverability | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GCB-026](#gcb-026) | Step waitFor: references an unknown step id | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## GCB-001: Cloud Build step image not pinned by digest { #gcb-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Bare references (``gcr.io/cloud-builders/docker``) are treated as ``:latest`` by Cloud Build. Tag-only references (``:20``, ``:latest``) count as unpinned. Only ``@sha256:…`` suffixes pass.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every ``steps[].name`` image to an ``@sha256:<digest>`` suffix. ``gcr.io/cloud-builders/docker:latest`` is mutable; Google publishes new builder images frequently and the next build would pull whatever is current. Resolve the digest with ``gcloud artifacts docker images describe <ref> --format='value(image_summary.digest)'`` and pin it.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCB-002: Cloud Build uses the default service account { #gcb-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-IDENTITY</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

The default Cloud Build service account historically held ``roles/cloudbuild.builds.builder`` plus project-level editor in many organisations. Even under the GCP April-2024 default-identity change, the default SA is still broader than what a single pipeline needs. Explicit ``serviceAccount:`` is required to pass.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a dedicated service account for the build, grant it only the roles the pipeline actually needs (``roles/artifactregistry.writer``, ``roles/storage.objectCreator`` for artifact upload, etc.), and set ``serviceAccount: projects/<PROJECT>/serviceAccounts/<NAME>@...``. Leaving it unset falls back to the default Cloud Build SA, which accumulates roles over a project's lifetime and is routinely granted ``roles/editor``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCB-003: Secret Manager value referenced in step args { #gcb-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-532</span>
</div>

Detection patterns: literal ``projects/<n>/secrets/<name>/versions/...`` URIs, ``gcloud secrets versions access`` shell invocations, and ``$(gcloud secrets …)`` command substitutions in step args or entrypoint.

<div class="pg-rule__rec" markdown>

**Recommended action**

Map the secret under ``availableSecrets.secretManager[]`` with an ``env:`` alias, then reference it from each step via ``secretEnv: [ALIAS]``. Avoid inline ``gcloud secrets versions access`` in ``args``, the resolved plaintext lands in build logs.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCB-004: dynamicSubstitutions on with user substitutions in step args { #gcb-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-INPUT-VAL</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-77</span>
</div>

The ``_``-prefix is Cloud Build's naming convention for user substitutions; they are editable via build trigger UI, ``gcloud builds submit --substitutions``, and the REST API. Built-in substitutions (``$PROJECT_ID``, ``$COMMIT_SHA``, ``$BUILD_ID``) are derived from the trigger event and are *not* treated as user-controlled by this rule.

<div class="pg-rule__rec" markdown>

**Recommended action**

Either disable ``options.dynamicSubstitutions`` (it defaults to false) or move user substitutions (``$_FOO``) out of step ``args``, pass them through ``env:`` and reference them inside a shell script the builder runs. Dynamic substitution re-evaluates bash syntax after variable expansion, giving trigger-config editors a script-injection channel.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GCB-005: Build timeout unset or excessive { #gcb-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-C-RESOURCE-LIMITS</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Cloud Build's default 10-minute timeout applies silently when ``timeout:`` is absent. Accepted format is ``<N>s`` (seconds); ``<N>m``/``<N>h`` forms are a gcloud convenience and are treated as malformed by the API.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare an explicit ``timeout:`` at the top of ``cloudbuild.yaml`` bounded to the build's realistic worst case (e.g. ``1800s`` for most container builds). Explicit bounds shorten the window a compromised build can spend on a shared worker and flag regressions when a legitimate step slows down.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCB-006: Dangerous shell idiom (eval, sh -c variable, backtick exec) { #gcb-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-95</span>
</div>

Complements GCB-004 (dynamicSubstitutions + user substitution in args). GCB-006 fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the substitution source is currently trusted.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary. In Cloud Build these idioms typically appear in ``args: [-c, ...]`` entries under a bash entrypoint.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCB-007: availableSecrets references ``versions/latest`` { #gcb-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-353</span>
</div>

``versions/latest`` is documented as a rolling alias. A build run on Monday and a re-run on Tuesday can consume different secret bodies without any change to ``cloudbuild.yaml``, breaking the reproducibility invariant that pinning protects.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin each ``availableSecrets.secretManager[].versionName`` to a specific version number (``.../versions/7``) rather than ``latest``. Rotate by updating the number when a new version is promoted, not by silently publishing a new version that the next build pulls.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCB-008: No vulnerability scanning step in Cloud Build pipeline { #gcb-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VULN-SCAN</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

The detector matches tool names anywhere in the document, step images, ``args``, or ``entrypoint`` strings. Container Analysis API scanning configured at the project level counts as compensating control but is out of scope for this YAML-only check; if you rely on it, suppress this rule via ``--checks``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a step that runs a vulnerability scanner, trivy, grype, snyk test, npm audit, pip-audit, osv-scanner, or govulncheck. In Cloud Build this typically looks like a step with ``name: aquasec/trivy`` or an ``entrypoint: bash`` step that invokes ``trivy image`` / ``grype <ref>`` on the built image.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCB-009: Artifacts not signed (no cosign / sigstore step) { #gcb-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Silent-pass when the pipeline does not appear to produce artifacts (no ``docker push`` / ``gcloud run deploy`` / ``kubectl apply`` / etc. in any step). The detector matches cosign, sigstore, slsa-framework, and notation.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a signing step before ``images:`` is resolved, for example, a step with ``name: gcr.io/projectsigstore/cosign`` that runs ``cosign sign --yes <registry>/<repo>@<digest>``. Pair with an attestation step (``cosign attest --predicate sbom.json --type cyclonedx``) so consumers can verify both the signature and the build provenance.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCB-010: Remote script piped to shell interpreter { #gcb-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects ``curl | bash``, ``wget | sh``, ``bash -c "$(curl …)"``, inline ``python -c urllib.urlopen``, ``curl > x.sh && bash x.sh``, and PowerShell ``irm | iex`` idioms. Vendor-trusted hosts (rustup.rs, get.docker.com, sdk.cloud.google.com, …) are still flagged at HIGH but the hit carries a ``vendor_trusted`` marker so dashboards can stratify known-vendor installers from arbitrary attacker URLs.

<div class="pg-rule__rec" markdown>

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository and invoke it from the checkout, removing the network fetch removes the attacker-controllable content entirely.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCB-011: TLS / certificate verification bypass { #gcb-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-295</span>
</div>

Covers ``curl -k`` / ``wget --no-check-certificate``, ``git config http.sslVerify false``, ``NODE_TLS_REJECT_UNAUTHORIZED=0``, ``npm config set strict-ssl false``, ``PYTHONHTTPSVERIFY=0``, ``GOINSECURE=``, ``helm --insecure-skip-tls-verify``, ``kubectl --insecure-skip-tls-verify``, and ``ssh -o StrictHostKeyChecking=no``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Fix the underlying certificate issue, install the correct CA bundle into the step image, or point the tool at a mirror that presents a valid chain. Disabling verification trades a build error for a silent MITM window.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GCB-012: Credential-shaped literal in pipeline body { #gcb-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Complements GCB-003 (inline ``gcloud secrets versions access``) and GCB-007 (``/versions/latest`` alias). This rule runs the shared credential-shape catalog against every string in the YAML. AWS keys, GitHub PATs, Slack webhooks, JWTs, PEM private key blocks, and any user-registered ``--secret-pattern`` regex. Known placeholders like ``EXAMPLE``/``CHANGEME`` are already filtered upstream so fixtures and docs don't false-match.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the exposed credential immediately. Move the value to ``availableSecrets.secretManager`` and reference it via ``secretEnv:`` so the plaintext never lands in the YAML or the build logs. For cloud access prefer workload-identity federation over long-lived keys.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCB-013: Package install bypasses registry integrity (git / path / tarball) { #gcb-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Complements GCB-012 (literal secrets) and GCB-010 (curl-pipe). Where those catch attacker content at fetch time, this rule catches installs that silently bypass the lockfile/registry integrity model, the build is technically reproducible but the source of truth is whatever the git ref / filesystem / tarball URL served most recently.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to Artifact Registry (or another internal registry) instead of installing from a filesystem path or tarball URL.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCB-014: Build logging disabled (options.logging: NONE) { #gcb-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-O-AUDIT</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

``options.logging`` defaults to ``CLOUD_LOGGING_ONLY`` when omitted, which passes. Only the explicit ``NONE`` value (case- insensitive) trips this rule. ``GCS_ONLY`` / ``LEGACY`` pass. They persist logs, just to a different destination.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the ``logging: NONE`` override, or replace it with ``CLOUD_LOGGING_ONLY`` / ``GCS_ONLY``, so every step's stdout, stderr, and exit code is persisted. Loss of logs is a detection-and-response black hole; the storage cost is measured in cents.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCB-015: SBOM not produced (no CycloneDX / syft / Trivy-SBOM step) { #gcb-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Complements GCB-009 (signing) and GCB-008 (vuln scanning). Without an SBOM, downstream consumers cannot audit the exact dependency set shipped in a Cloud Build image, delaying vulnerability response when a transitive dep is disclosed. Pairs naturally with ``cosign attest --type cyclonedx`` in a follow-up step.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an SBOM generation step, ``syft <image> -o cyclonedx-json``, ``trivy image --format cyclonedx``, and publish the resulting document alongside the image (typically via a cosign attestation so the SBOM travels with the artifact).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCB-016: Step dir field contains parent-directory escape (..) { #gcb-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-22</span>
</div>

Cloud Build doesn't sandbox the ``dir:`` value beyond a join against ``/workspace``. ``dir: ../etc`` resolves to ``/etc`` inside the builder container, which is rarely the intent. The check fires on any literal ``..`` segment; single-dot ``./`` and absolute paths are fine.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``..`` traversals in ``dir:`` with absolute paths rooted under ``/workspace`` (e.g. ``dir: /workspace/sub``) or split the work across multiple steps that each set ``dir:`` to an exact subdirectory. The Cloud Build worker starts each step with the workspace mounted at ``/workspace``; a ``..`` escape from there reaches the builder image's root filesystem and any credentials the image carries.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCB-017: Image-producing build does not request SLSA provenance { #gcb-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

SLSA Build Level 2 requires that the build platform produce signed provenance. Cloud Build's ``VERIFIED`` verify option is the documented way to opt in. The check is silent when the build does not produce an image (no top-level ``images:`` and no ``docker push`` / ``gcloud run deploy`` style steps); for those, signing and provenance aren't applicable.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``options.requestedVerifyOption: VERIFIED`` on builds that publish container images. Cloud Build then emits a signed SLSA provenance attestation alongside the image, which downstream verifiers (Binary Authorization, cosign verify-attestation, gcloud artifacts docker images describe) can use to check that an image was built by the configured pipeline rather than smuggled in from elsewhere.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCB-018: Legacy KMS secrets block in use (prefer availableSecrets / Secret Manager) { #gcb-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Cloud Build supports two secret-injection mechanisms. The older ``secrets:`` block carries KMS-encrypted ciphertext directly in the YAML; the cipher is decrypted at build time if the build's service account has ``cloudkms.cryptoKeyDecrypter`` on the key. The newer ``availableSecrets`` block references Secret Manager versions by URL, which is the documented modern approach. The legacy form still works, but rotating a value means re-encrypting and committing a new ciphertext.

<div class="pg-rule__rec" markdown>

**Recommended action**

Migrate from the top-level ``secrets:`` block (KMS-encrypted values stored inline in the YAML) to ``availableSecrets`` + Secret Manager. Replace each ``secrets[].secretEnv`` mapping with a ``versionName`` reference under ``availableSecrets.secretManager``. Secret Manager rotates without re-encrypting and re-committing the YAML, scopes access via IAM rather than the KMS key's IAM, and produces an explicit audit log entry on every read.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCB-019: Shell entrypoint inlines a user substitution into args { #gcb-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-INPUT-VAL</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-77</span>
</div>

Distinct from GCB-004, which fires only when ``options.dynamicSubstitutions: true`` re-evaluates bash syntax after expansion. GCB-019 fires whenever a step uses a shell as its entrypoint AND a ``$_USER_VAR`` token lands inside ``args``: Cloud Build expands the substitution before the step runs, and the shell then interprets any metacharacters the substitution carried, straight command injection through trigger configuration.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pass user substitutions through ``env:`` (or ``secretEnv:`` for sensitive values) and reference them inside a checked-in shell script rather than splicing them directly into ``args``. If the step truly needs to invoke shell logic inline, switch the entrypoint to the underlying tool (``docker``, ``gcloud``, ``gsutil``) and let the tool see the substitution as an argument, not as shell text.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GCB-020: serviceAccount points at the default Cloud Build service account { #gcb-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-IDENTITY</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Complements GCB-002, which only fires when ``serviceAccount:`` is unset. This rule fires when an explicit value is set but still resolves to the project default, typically the email shape ``<digits>@cloudbuild.gserviceaccount.com``, optionally wrapped in the ``projects/<id>/serviceAccounts/...`` URI form. The April-2024 GCP default-identity change kept the same SA shape; the broad-permissions concern remains.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't bind the build to ``<project-number>@cloudbuild.gserviceaccount.com``. The default Cloud Build SA accumulates roles over a project's lifetime (commonly ``roles/editor`` or broad Artifact Registry / Secret Manager access). Create a dedicated SA per pipeline, grant only the roles the build actually needs, and reference it by its bespoke email (``<name>@<project>.iam.gserviceaccount.com``). Revoking a compromised pipeline then doesn't unbind every other build in the project.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCB-021: No private worker pool, build runs on the shared default pool { #gcb-021 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-NETWORK-SEG</span> <span class="pg-tag pg-tag--esf">ESF-D-ISOLATION</span> <span class="pg-tag pg-tag--cwe">CWE-668</span>
</div>

Cloud Build runs in a shared Google-managed pool by default. Switching to a *private worker pool* is the prerequisite for every other network-perimeter control: egress restriction to specific peered networks, ingress blocking of public endpoints, and traffic interoperation with VPC Service Controls. Both ``options.pool.name`` and the legacy ``options.workerPool`` field are accepted.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``options.pool.name: projects/<PROJECT>/locations/<REGION>/workerPools/<NAME>`` to bind the build to a private worker pool inside your VPC. The default pool runs on a shared Google-managed network with public-internet egress and ingress paths Google chooses, which makes egress filtering, VPC-SC perimeters, and source-IP allowlists on internal endpoints impossible. A private pool also gives you the option to disable external IPs and to log the build's network activity through your own VPC flow logs.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GCB-022: options.substitutionOption set to ALLOW_LOOSE { #gcb-022 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-INPUT-VAL</span> <span class="pg-tag pg-tag--cwe">CWE-1188</span>
</div>

Cloud Build accepts two values for ``options.substitutionOption``: ``MUST_MATCH`` (default, any undefined ``$_VAR`` reference fails the build at parse time) and ``ALLOW_LOOSE`` (undefined references silently expand to ``""``). The default is the safer setting; this rule only fires on the explicit ``ALLOW_LOOSE`` opt-in. Builds that genuinely depend on optional substitutions should pass them through ``substitutions:`` defaults, not rely on silent empty-string fallback.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``options.substitutionOption`` (the default is ``MUST_MATCH``) or set it explicitly to ``MUST_MATCH``. ``ALLOW_LOOSE`` makes Cloud Build expand undefined substitutions to the empty string instead of failing the build. That paper-overs typos (``$_REGON`` instead of ``$_REGION``), masks unset variables that should have tripped review, and combined with ``dynamicSubstitutions: true`` (GCB-004) it widens the command-injection surface by letting attacker-controlled substitution tokens collapse to empty strings inside shell commands.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCB-023: Step references a user substitution not declared in substitutions: { #gcb-023 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-S-INPUT-VAL</span> <span class="pg-tag pg-tag--cwe">CWE-1188</span>
</div>

Walks every step's ``args:`` / ``entrypoint:`` / ``env:`` / ``dir:`` / ``id:`` / ``waitFor:`` for ``$_NAME`` tokens (Cloud Build's user-substitution syntax is leading underscore + uppercase / digits / underscore) and cross-references against the top-level ``substitutions:`` mapping. Built-in substitutions (``$PROJECT_ID``, ``$REPO_NAME``, ``$BRANCH_NAME``, ``$TAG_NAME``, ``$COMMIT_SHA``, ``$SHORT_SHA``, ``$REVISION_ID``, ``$BUILD_ID``, ``$LOCATION``, ``$TRIGGER_NAME``, ``$_HEAD_*``, ``$_BASE_*``, ``$_PR_NUMBER`` and the ``$_HEAD_REPO_URL`` family) are Cloud Build server-set and don't appear in ``substitutions:``; the rule allow-lists them so they don't false-positive.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an entry for every ``$_USER_VAR`` referenced anywhere in the build to the top-level ``substitutions:`` block, either with a sensible default or with an empty string if the trigger always supplies the value. Cloud Build's default ``options.substitutionOption: MUST_MATCH`` then fails the build at parse time on undeclared references (catching typos at the gate). With the looser ``ALLOW_LOOSE`` opt-in (GCB-022) undeclared references silently expand to the empty string, which masks the bug and quietly broadens any shell command that interpolates the value.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GCB-024: Build pushes Docker images but top-level images: is empty { #gcb-024 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SBOM</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-1059</span>
</div>

Walks step args / entrypoint / cmd looking for ``docker push`` (or the ``buildx imagetools push`` variant) invocations. When the build has at least one such step but the top-level ``images:`` field is missing or empty, fires. Steps that build *and* push via the ``gcr.io/cloud-builders/docker`` builder image are the common case; ``--push`` flags on ``buildx build`` are also detected. ``kaniko`` and ``buildah`` push idioms aren't currently detected. Those are different builder images entirely.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add every image the build produces to the top-level ``images:`` array (e.g. ``images: ['gcr.io/$PROJECT_ID/myapp:$COMMIT_SHA']``). Cloud Build then verifies the push succeeded before marking the build SUCCESS, records the image in the build's metadata for provenance / Binary Authorization attestation, and surfaces the image in the ``builds.list --image`` query. Without it, a push that happens inside a step is invisible to Cloud Build's tracking layer even though the image still lands in the registry.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GCB-025: Build has no tags for audit / discoverability { #gcb-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-LOGS</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Cloud Build tags are user-defined labels attached to a build. They appear in the build's metadata (``tags:`` field on the Build resource), in every Cloud Logging audit event for the build, and as a filter argument to ``gcloud builds list --filter='tags:<value>'``. Substitution-bearing tags (``$BRANCH_NAME``, ``$COMMIT_SHA``) count as populated. Cloud Build expands them at submission time.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a top-level ``tags:`` array to every ``cloudbuild.yaml``, at minimum, an environment tag (``prod`` / ``staging`` / ``dev``) and a service tag (``backend`` / ``frontend`` / ``infra``). Cloud Build records tags in the build metadata and Cloud Logging entries so post-incident triage of ``which build emitted this`` becomes a single ``gcloud builds list --filter='tags:prod'`` query. Without tags, builds discoverable only by build-id; the id is a UUID with no signal.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GCB-026: Step waitFor: references an unknown step id { #gcb-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-684</span>
</div>

Cloud Build's step dependency graph is built from each step's ``waitFor:`` array. A step with no ``waitFor:`` runs after all previous steps; a step with ``waitFor: ['-']`` runs at the start of the build; a step with ``waitFor: ['<id>']`` waits for the specific step. There's no validation that the referenced id exists, typo'd ids are silently treated like ``-`` (no-wait), so the dependency disappears without warning. This rule catches the silent-skip by walking every ``waitFor:`` value and cross-referencing it against the set of declared step ids.

<div class="pg-rule__rec" markdown>

**Recommended action**

Verify every ID listed in a step's ``waitFor:`` array matches an ``id:`` declared on a sibling step in the same build. The special token ``-`` (start at the beginning of the build, no dependencies) is the only non-id value Cloud Build accepts. A typo in ``waitFor:`` doesn't fail the build, Cloud Build silently skips the wait, so a step that was supposed to run *after* a setup step ends up running in parallel with it.

</div>

</div>

---

## Adding a new Google Cloud Build check

1. Create a new module at
   `pipeline_check/core/checks/cloudbuild/rules/gcbNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/cloudbuild/GCB-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py cloudbuild
   ```
