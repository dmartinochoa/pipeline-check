# Google Cloud Build provider

Parses `cloudbuild.yaml` on disk — no Google Cloud credentials, no
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

- **GCB-002** — `serviceAccount:` must be set; the default Cloud Build
  SA is typically broader than any single pipeline needs.
- **GCB-003** — secrets must flow through `availableSecrets.secret
  Manager[].env` + `secretEnv:`, never via inline `gcloud secrets
  versions access` in `args`.
- **GCB-004** — `options.dynamicSubstitutions: true` combined with a
  user-substitution (`$_FOO`) in step args opens a trigger-editor-
  controlled shell-injection path.

## What it covers

| Check | Title | Severity |
|-------|-------|----------|
| GCB-001 | Cloud Build step image not pinned by digest | HIGH |
| GCB-002 | Cloud Build uses the default service account | HIGH |
| GCB-003 | Secret Manager value referenced in step args | HIGH |
| GCB-004 | dynamicSubstitutions on with user substitutions in step args | HIGH |
| GCB-005 | Build timeout unset or excessive | LOW |
| GCB-006 | Dangerous shell idiom (eval, sh -c variable, backtick exec) | HIGH |
| GCB-007 | availableSecrets references ``versions/latest`` | MEDIUM |
| GCB-008 | No vulnerability scanning step in Cloud Build pipeline | MEDIUM |
| GCB-009 | Artifacts not signed (no cosign / sigstore step) | MEDIUM |

---

## GCB-001 — Cloud Build step image not pinned by digest
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-VERIFY-DEPS

Bare references (``gcr.io/cloud-builders/docker``) are treated as ``:latest`` by Cloud Build. Tag-only references (``:20``, ``:latest``) count as unpinned. Only ``@sha256:…`` suffixes pass.

**Recommended action**

Pin every ``steps[].name`` image to an ``@sha256:<digest>`` suffix. ``gcr.io/cloud-builders/docker:latest`` is mutable; Google publishes new builder images frequently and the next build would pull whatever is current. Resolve the digest with ``gcloud artifacts docker images describe <ref> --format='value(image_summary.digest)'`` and pin it.

## GCB-002 — Cloud Build uses the default service account
**Severity:** HIGH · OWASP CICD-SEC-2 · ESF ESF-D-IDENTITY, ESF-D-LEAST-PRIV

The default Cloud Build service account historically held ``roles/cloudbuild.builds.builder`` plus project-level editor in many organisations. Even under the GCP April-2024 default-identity change, the default SA is still broader than what a single pipeline needs. Explicit ``serviceAccount:`` is required to pass.

**Recommended action**

Create a dedicated service account for the build, grant it only the roles the pipeline actually needs (``roles/artifactregistry.writer``, ``roles/storage.objectCreator`` for artifact upload, etc.), and set ``serviceAccount: projects/<PROJECT>/serviceAccounts/<NAME>@...``. Leaving it unset falls back to the default Cloud Build SA, which accumulates roles over a project's lifetime and is routinely granted ``roles/editor``.

## GCB-003 — Secret Manager value referenced in step args
**Severity:** HIGH · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Detection patterns: literal ``projects/<n>/secrets/<name>/versions/...`` URIs, ``gcloud secrets versions access`` shell invocations, and ``$(gcloud secrets …)`` command substitutions in step args or entrypoint.

**Recommended action**

Map the secret under ``availableSecrets.secretManager[]`` with an ``env:`` alias, then reference it from each step via ``secretEnv: [ALIAS]``. Avoid inline ``gcloud secrets versions access`` in ``args`` — the resolved plaintext lands in build logs.

## GCB-004 — dynamicSubstitutions on with user substitutions in step args
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-S-INPUT-VAL

The ``_``-prefix is Cloud Build's naming convention for user substitutions; they are editable via build trigger UI, ``gcloud builds submit --substitutions``, and the REST API. Built-in substitutions (``$PROJECT_ID``, ``$COMMIT_SHA``, ``$BUILD_ID``) are derived from the trigger event and are *not* treated as user-controlled by this rule.

**Recommended action**

Either disable ``options.dynamicSubstitutions`` (it defaults to false) or move user substitutions (``$_FOO``) out of step ``args`` — pass them through ``env:`` and reference them inside a shell script the builder runs. Dynamic substitution re-evaluates bash syntax after variable expansion, giving trigger-config editors a script-injection channel.

## GCB-005 — Build timeout unset or excessive
**Severity:** LOW · OWASP CICD-SEC-7 · ESF ESF-C-RESOURCE-LIMITS

Cloud Build's default 10-minute timeout applies silently when ``timeout:`` is absent. Accepted format is ``<N>s`` (seconds); ``<N>m``/``<N>h`` forms are a gcloud convenience and are treated as malformed by the API.

**Recommended action**

Declare an explicit ``timeout:`` at the top of ``cloudbuild.yaml`` bounded to the build's realistic worst case (e.g. ``1800s`` for most container builds). Explicit bounds shorten the window a compromised build can spend on a shared worker and flag regressions when a legitimate step slows down.

## GCB-006 — Dangerous shell idiom (eval, sh -c variable, backtick exec)
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION

Complements GCB-004 (dynamicSubstitutions + user substitution in args). GCB-006 fires on intrinsically risky shell idioms — ``eval``, ``sh -c "$X"``, backtick exec — regardless of whether the substitution source is currently trusted.

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary. In Cloud Build these idioms typically appear in ``args: [-c, ...]`` entries under a bash entrypoint.

## GCB-007 — availableSecrets references ``versions/latest``
**Severity:** MEDIUM · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS, ESF-S-PIN-DEPS

``versions/latest`` is documented as a rolling alias. A build run on Monday and a re-run on Tuesday can consume different secret bodies without any change to ``cloudbuild.yaml`` — breaking the reproducibility invariant that pinning protects.

**Recommended action**

Pin each ``availableSecrets.secretManager[].versionName`` to a specific version number (``.../versions/7``) rather than ``latest``. Rotate by updating the number when a new version is promoted, not by silently publishing a new version that the next build pulls.

## GCB-008 — No vulnerability scanning step in Cloud Build pipeline
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-VULN-SCAN

The detector matches tool names anywhere in the document — step images, ``args``, or ``entrypoint`` strings. Container Analysis API scanning configured at the project level counts as compensating control but is out of scope for this YAML-only check; if you rely on it, suppress this rule via ``--checks``.

**Recommended action**

Add a step that runs a vulnerability scanner — trivy, grype, snyk test, npm audit, pip-audit, osv-scanner, or govulncheck. In Cloud Build this typically looks like a step with ``name: aquasec/trivy`` or an ``entrypoint: bash`` step that invokes ``trivy image`` / ``grype <ref>`` on the built image.

## GCB-009 — Artifacts not signed (no cosign / sigstore step)
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-D-SIGN-ARTIFACTS

Silent-pass when the pipeline does not appear to produce artifacts (no ``docker push`` / ``gcloud run deploy`` / ``kubectl apply`` / etc. in any step). The detector matches cosign, sigstore, slsa-framework, and notation.

**Recommended action**

Add a signing step before ``images:`` is resolved — for example, a step with ``name: gcr.io/projectsigstore/cosign`` that runs ``cosign sign --yes <registry>/<repo>@<digest>``. Pair with an attestation step (``cosign attest --predicate sbom.json --type cyclonedx``) so consumers can verify both the signature and the build provenance.

---

## Adding a new Google Cloud Build check

1. Create a new module at
   `pipeline_check/core/checks/cloudbuild/rules/gcbNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) ->
   Finding` function. The orchestrator auto-discovers it.
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
