# Bitbucket Pipelines provider

Parses `bitbucket-pipelines.yml` on disk — no Bitbucket API token, no
runner install.

## Producer workflow

```bash
# --bitbucket-path auto-detected when bitbucket-pipelines.yml exists at cwd.
pipeline_check --pipeline bitbucket

# …or pass it explicitly (file or directory).
pipeline_check --pipeline bitbucket --bitbucket-path ci/
```

## What it covers

| Check | Title | Severity |
|-------|-------|----------|
| BB-001 | pipe: action not pinned to exact version | HIGH |
| BB-002 | Script injection via attacker-controllable context | HIGH |
| BB-003 | Variables contain literal secret values | CRITICAL |
| BB-004 | Deploy step missing `deployment:` environment gate | MEDIUM |
| BB-005 | Step has no `max-time` — unbounded build | MEDIUM |
| BB-006 | Artifacts not signed | MEDIUM |
| BB-007 | SBOM not produced | MEDIUM |
| BB-008 | Credential-shaped literal in pipeline body | CRITICAL |
| BB-009 | pipe: pinned by version rather than sha256 digest | LOW |
| BB-010 | Deploy step ingests pull-request artifact unverified | CRITICAL |

---

## BB-001 — pipe: action not pinned to exact version
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-VERIFY-DEPS

Bitbucket pipes are docker-image references. Major-only (`:1`) or missing tags let Atlassian/the publisher swap the image contents. Full semver or sha256 digest is required.

**Recommended action**

Pin every `pipe:` to a full semver tag (e.g. `atlassian/aws-s3-deploy:1.4.0`) or to an immutable SHA. Floating majors like `:1` can roll to new code silently.

## BB-002 — Script injection via attacker-controllable context
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION

$BITBUCKET_BRANCH, $BITBUCKET_TAG, and $BITBUCKET_PR_* are populated from SCM event metadata the attacker controls. Interpolating them unquoted into a shell command lets a crafted branch/tag name execute inline.

**Recommended action**

Always double-quote interpolations of ref-derived variables (`"$BITBUCKET_BRANCH"`). Avoid passing them to `eval`, `sh -c`, or unquoted command arguments.

## BB-003 — Variables contain literal secret values
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Scans `definitions.variables` and each step's `variables:` for entries whose KEY looks credential-shaped and whose VALUE is a literal string. AWS access keys are detected by value shape regardless of key name.

**Recommended action**

Store credentials as Repository / Deployment Variables in Bitbucket's Pipelines settings with the 'Secured' flag, and reference them by name. Prefer short-lived OIDC tokens for cloud access.

## BB-004 — Deploy step missing `deployment:` environment gate
**Severity:** MEDIUM · OWASP CICD-SEC-1 · ESF ESF-C-APPROVAL, ESF-C-ENV-SEP

A step whose name or invoked pipe matches `deploy` / `release` / `publish` / `promote` should declare a `deployment:` field so Bitbucket enforces deployment-scoped variables, approvals, and history.

**Recommended action**

Add `deployment: production` (or `staging` / `test`) to the step. Configure the matching environment in the repo's Deployments settings with required reviewers and secured variables.

## BB-005 — Step has no `max-time` — unbounded build
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-TIMEOUT

Without `max-time`, the step runs until Bitbucket's 120-minute global default kills it. Explicit per-step timeouts cap blast radius and cost.

**Recommended action**

Add `max-time: <minutes>` to each step, sized to the 95th percentile of historical runtime plus margin. Bounded runs limit the blast radius of a compromised build and prevent runaway minute consumption.

## BB-006 — Artifacts not signed
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-D-SIGN-ARTIFACTS

Unsigned artifacts can't be verified downstream. Passes when cosign / sigstore / slsa-* / notation-sign appears in the pipeline body.

**Recommended action**

Add a step that runs `cosign sign` against the built image or archive, using Bitbucket OIDC for keyless signing where possible. Publish the signature next to the artifact and verify it at deploy time.

## BB-007 — SBOM not produced
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-D-SBOM

Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / sbom-tool / Trivy-SBOM appears.

**Recommended action**

Add an SBOM step — `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM as a build artifact.

## BB-008 — Credential-shaped literal in pipeline body
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Complements BB-003 (variable-name scan). BB-008 checks every string in the pipeline against the cross-provider credential-pattern catalogue — catches secrets pasted into script bodies or environment blocks.

**Recommended action**

Rotate the exposed credential. Move the value to a Secured Repository or Deployment Variable and reference it by name.

## BB-009 — pipe: pinned by version rather than sha256 digest
**Severity:** LOW · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-IMMUTABLE

BB-001 fails floating tags at HIGH; BB-009 is the stricter tier. Even immutable-looking semver tags can be repointed by the registry; sha256 digests are tamper-evident.

**Recommended action**

Resolve each pipe to its digest (`docker buildx imagetools inspect bitbucketpipelines/<name>:<ver>`) and reference it via `@sha256:<digest>`.

## BB-010 — Deploy step ingests pull-request artifact unverified
**Severity:** CRITICAL · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-S-VERIFY-DEPS

Bitbucket steps declare artifacts on the producer and downstream steps implicitly receive them. When an unprivileged step produces an artifact and a later `deployment:` step consumes it without verification, attacker-controlled output flows into the privileged stage.

**Recommended action**

Add a verification step before the deploy step consumes the artifact: `sha256sum -c artifact.sha256` against a manifest the producer signed, or `cosign verify` over the artifact directly. Alternatively, restrict the artifact-producing step to non-PR pipelines via ``branches:`` or ``custom:`` triggers.

---

## Adding a new Bitbucket Pipelines check

1. Create a new module at
   `pipeline_check/core/checks/bitbucket/rules/bbNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) ->
   Finding` function. The orchestrator auto-discovers it.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/bitbucket/BB-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py bitbucket
   ```
