# GitLab CI provider

Parses `.gitlab-ci.yml` on disk — no GitLab API token, no runner install.
Works against the file in a detached clone or a merged-result pipeline
export.

## Producer workflow

```bash
# --gitlab-path auto-detected when .gitlab-ci.yml exists at cwd.
pipeline_check --pipeline gitlab

# …or pass it explicitly (file or directory).
pipeline_check --pipeline gitlab --gitlab-path ci/
```

## What it covers

| Check | Title | Severity |
|-------|-------|----------|
| GL-001 | Image not pinned to specific version or digest | HIGH |
| GL-002 | Script injection via untrusted commit/MR context | HIGH |
| GL-003 | Variables contain literal secret values | CRITICAL |
| GL-004 | Deploy job lacks manual approval or environment gate | MEDIUM |
| GL-005 | include: pulls remote / project without pinned ref | HIGH |
| GL-006 | Artifacts not signed | MEDIUM |
| GL-007 | SBOM not produced | MEDIUM |
| GL-008 | Credential-shaped literal in pipeline body | CRITICAL |
| GL-009 | Image pinned to version tag rather than sha256 digest | LOW |
| GL-010 | Multi-project pipeline ingests upstream artifact unverified | CRITICAL |
| GL-011 | include: local file pulled in MR-triggered pipeline | HIGH |
| GL-012 | Cache key derives from MR-controlled CI variable | MEDIUM |

---

## GL-001 — Image not pinned to specific version or digest
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-VERIFY-DEPS

Floating tags (`latest` or major-only) can be silently swapped under the job. Every `image:` reference should pin a specific version tag or digest.

**Recommended action**

Reference images by `@sha256:<digest>` or at minimum a full immutable version tag (e.g. `python:3.12.1-slim`). Avoid `:latest` and bare tags like `:3`.

## GL-002 — Script injection via untrusted commit/MR context
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION

CI_COMMIT_MESSAGE / CI_COMMIT_REF_NAME / CI_MERGE_REQUEST_TITLE and friends are populated from SCM event metadata the attacker controls. Interpolating them into a shell body executes the crafted content as part of the build.

**Recommended action**

Read these values into intermediate `variables:` entries or shell variables and quote them defensively (`"$BRANCH"`). Never inline `$CI_COMMIT_MESSAGE` / `$CI_MERGE_REQUEST_TITLE` into a shell command.

## GL-003 — Variables contain literal secret values
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Scans `variables:` at the top level and on each job for entries whose KEY looks credential-shaped and whose VALUE is a literal string (not a `$VAR` reference). AWS access keys are detected by value pattern regardless of key name.

**Recommended action**

Store credentials as protected + masked CI/CD variables in project or group settings, and reference them by name from the YAML. For cloud access prefer short-lived OIDC tokens.

## GL-004 — Deploy job lacks manual approval or environment gate
**Severity:** MEDIUM · OWASP CICD-SEC-1 · ESF ESF-C-APPROVAL, ESF-C-ENV-SEP

A job whose stage or name contains `deploy` / `release` / `publish` / `promote` should either require manual approval or declare an `environment:` binding. Otherwise any push to the trigger branch ships to the target.

**Recommended action**

Add `when: manual` (optionally with `rules:` for protected branches) or bind the job to an `environment:` with a deployment tier so approvals and audit are enforced by GitLab's environment controls.

## GL-005 — include: pulls remote / project without pinned ref
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-TRUSTED-REG

Cross-project and remote includes can be silently re-pointed. Branch-name refs (`main`/`master`/`develop`/`head`) are treated as unpinned; tag and SHA refs are considered safe.

**Recommended action**

Pin `include: project:` entries with `ref:` set to a tag or commit SHA. Avoid `include: remote:` for untrusted URLs; mirror the content into a trusted project and pin it.

## GL-006 — Artifacts not signed
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-D-SIGN-ARTIFACTS

Unsigned artifacts can't be verified downstream, so a tampered build is indistinguishable from a legitimate one. Pass when any of cosign / sigstore / slsa-* / notation-sign appears in the pipeline text.

**Recommended action**

Add a job that runs `cosign sign` (keyless OIDC with GitLab's id_tokens works out of the box) or `notation sign`. Publish the signature next to the artifact and verify it on consume.

## GL-007 — SBOM not produced
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-D-SBOM

Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / spdx-sbom-generator / sbom-tool / Trivy-SBOM appears in the pipeline body.

**Recommended action**

Add an SBOM step — `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or GitLab's built-in CycloneDX dependency-scanning template. Attach the SBOM as a pipeline artifact.

## GL-008 — Credential-shaped literal in pipeline body
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Complements GL-003 (which looks at `variables:` block keys). GL-008 scans every string in the pipeline against the cross-provider credential-pattern catalogue — catches secrets pasted into `script:` bodies or environment blocks where the name-based detector can't see them.

**Recommended action**

Rotate the exposed credential immediately. Move the value to a protected + masked CI/CD variable and reference it by name. For cloud access prefer short-lived OIDC tokens.

## GL-009 — Image pinned to version tag rather than sha256 digest
**Severity:** LOW · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-IMMUTABLE

GL-001 fails floating tags at HIGH; GL-009 is the stricter tier. Even immutable-looking version tags (`python:3.12.1`) can be repointed by registry operators. Digest pins are the only tamper-evident form.

**Recommended action**

Resolve each image to its current digest (`docker buildx imagetools inspect <ref>` prints it) and replace the tag with `@sha256:<digest>`. Automate refreshes with Renovate.

## GL-010 — Multi-project pipeline ingests upstream artifact unverified
**Severity:** CRITICAL · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-S-VERIFY-DEPS

`needs: { project: ..., artifacts: true }` pulls artifacts from another project's pipeline. If that upstream project accepts MR pipelines, the artifact may have been built by attacker-controlled code.

**Recommended action**

Add a verification step before consuming the artifact: `cosign verify-attestation`, `sha256sum -c`, or `gpg --verify` against a manifest signed by the upstream project's release key. Only consume artifacts produced by upstream pipelines whose origin you can trust.

## GL-011 — include: local file pulled in MR-triggered pipeline
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-S-PIN-DEPS

`include: local: '<path>'` resolves from the current pipeline's checked-out tree. On an MR pipeline the tree is the MR source branch — the MR author controls the included YAML content.

**Recommended action**

Move the included template into a separate, read-only project and reference it via `include: project: ... ref: <sha-or-tag>`. That way the included content is fixed at MR creation time and not editable from the MR branch.

## GL-012 — Cache key derives from MR-controlled CI variable
**Severity:** MEDIUM · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-S-VERIFY-DEPS

GitLab caches restore by key prefix. When the key includes an MR-controlled variable, an attacker can poison a cache entry that a later default-branch pipeline restores.

**Recommended action**

Build the cache key from values the MR can't control: lockfile contents (`files: [Cargo.lock]`), the job name, and `$CI_PROJECT_NAMESPACE`. Never reference `$CI_MERGE_REQUEST_*` or `$CI_COMMIT_BRANCH` from a cache key namespace.

---

## Adding a new GitLab CI check

1. Create a new module at
   `pipeline_check/core/checks/gitlab/rules/glNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) ->
   Finding` function. The orchestrator auto-discovers it.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/gitlab/GL-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py gitlab
   ```
