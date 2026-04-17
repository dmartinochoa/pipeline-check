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
| GL-013 | AWS auth uses long-lived access keys | MEDIUM |
| GL-014 | Self-managed runner without ephemeral tag | MEDIUM |
| GL-015 | Job has no `timeout` — unbounded build | MEDIUM |
| GL-016 | Remote script piped to shell interpreter | HIGH |
| GL-017 | Docker run with insecure flags (privileged/host mount) | CRITICAL |
| GL-018 | Package install from insecure source | HIGH |
| GL-019 | No vulnerability scanning step | MEDIUM |
| GL-020 | CI_JOB_TOKEN written to persistent storage | CRITICAL |
| GL-021 | Package install without lockfile enforcement | MEDIUM |
| GL-022 | Dependency update command bypasses lockfile pins | MEDIUM |
| GL-023 | TLS / certificate verification bypass | HIGH |
| GL-024 | No SLSA provenance attestation produced | MEDIUM |
| GL-025 | Pipeline contains indicators of malicious activity | CRITICAL |
| GL-026 | Dangerous shell idiom (eval, sh -c variable, backtick exec) | HIGH |
| GL-027 | Package install bypasses registry integrity (git / path / tarball source) | MEDIUM |

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

## GL-013 — AWS auth uses long-lived access keys
**Severity:** MEDIUM · OWASP CICD-SEC-6 · ESF ESF-D-TOKEN-HYGIENE

Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values in CI/CD variables can't be rotated on a fine-grained schedule. GitLab supports OIDC via `id_tokens:` for short-lived credential injection.

**Recommended action**

Use GitLab CI/CD OIDC with `id_tokens:` to obtain short-lived AWS credentials via `sts:AssumeRoleWithWebIdentity`. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from CI/CD variables.

## GL-014 — Self-managed runner without ephemeral tag
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-ENV, ESF-D-PRIV-BUILD

Self-managed runners that don't tear down between jobs leak filesystem and process state. The check looks for an `ephemeral` tag on any job whose `tags:` list doesn't match SaaS-only runner names.

**Recommended action**

Register the runner with `--executor docker` + `--docker-pull-policy always` so containers are fresh per job, and add an `ephemeral` tag. Alternatively use the GitLab Runner Operator with autoscaling.

## GL-015 — Job has no `timeout` — unbounded build
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-TIMEOUT

Without an explicit `timeout`, the job runs until the instance-level default (typically 60 minutes). Explicit timeouts cap blast radius and the window during which a compromised script has access to CI/CD variables.

**Recommended action**

Add `timeout:` to each job (e.g. `timeout: 30 minutes`), sized to the 95th percentile of historical runtime. GitLab's default is 60 minutes (or the instance admin setting).

## GL-016 — Remote script piped to shell interpreter
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-VERIFY-DEPS

Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

## GL-017 — Docker run with insecure flags (privileged/host mount)
**Severity:** CRITICAL · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-ENV

Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a pipeline give the container full access to the CI runner, enabling container escape and lateral movement.

**Recommended action**

Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

## GL-018 — Package install from insecure source
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-VERIFY-DEPS

Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommended action**

Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

## GL-019 — No vulnerability scanning step
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-VULN-MGMT

Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognises trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommended action**

Add a vulnerability scanning step — trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

## GL-020 — CI_JOB_TOKEN written to persistent storage
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Detects patterns where `CI_JOB_TOKEN` is redirected to a file, piped through `tee`, or appended to dotenv/artifact paths. Persisted tokens survive the job boundary and can be read by later stages, downloaded artifacts, or cache entries — turning a scoped credential into a long-lived one.

**Recommended action**

Never write CI_JOB_TOKEN to files, artifacts, or dotenv reports. Use the token inline in the command that needs it and let GitLab revoke it automatically when the job finishes.

## GL-021 — Package install without lockfile enforcement
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS

Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest — exactly the window a supply-chain attacker exploits.

**Recommended action**

Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

## GL-022 — Dependency update command bypasses lockfile pins
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS

Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommended action**

Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

## GL-023 — TLS / certificate verification bypass
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-VERIFY-DEPS

Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommended action**

Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

## GL-024 — No SLSA provenance attestation produced
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-S-PROVENANCE

``cosign sign`` and ``cosign attest`` look similar but mean different things: the first binds identity to bytes; the second binds a structured claim (builder, source, inputs) to the artifact. SLSA Build L3 verifiers check the latter.

**Recommended action**

Add a job that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or adopt a SLSA-aware builder (the SLSA project ships GitLab templates). Signing the artifact (GL-006) isn't enough for SLSA L3 — the attestation describes *how* the build ran.

## GL-025 — Pipeline contains indicators of malicious activity
**Severity:** CRITICAL · OWASP CICD-SEC-4, CICD-SEC-7 · ESF ESF-D-INJECTION, ESF-S-VERIFY-DEPS

Fires on concrete indicators (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, ``webhook.site`` callbacks, ``env | curl`` credential dumps, ``history -c`` audit erasure). Orthogonal to GL-003 (curl pipe) and GL-017 (Docker insecure flags) — those flag risky defaults; this flags evidence.

**Recommended action**

Treat as a potential compromise. Identify the MR that added the matching job(s), rotate any credentials the pipeline can reach, and audit recent runs for outbound traffic to the matched hosts. A legitimate red-team exercise should be time-bounded via ``.pipelinecheckignore`` with ``expires:``.

## GL-026 — Dangerous shell idiom (eval, sh -c variable, backtick exec)
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION

``eval``, ``sh -c "$X"``, and `` `$X` `` all re-parse the variable's value as shell syntax. Once a CI variable feeds into one of these idioms, any ``;``, ``&&``, ``|``, backtick, or ``$()`` in the value executes — even if the variable's source is currently trusted, future refactors may expose it.

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec of variables with direct command invocation. If the command must be dynamic, pass arguments as array members or validate the input against an allow-list at the boundary.

## GL-027 — Package install bypasses registry integrity (git / path / tarball source)
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-VERIFY-DEPS

Complements GL-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs all bypass the registry integrity controls the lockfile relies on — an attacker who can move a branch head, drop a sibling checkout, or change a served tarball can substitute code into the build.

**Recommended action**

Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

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
