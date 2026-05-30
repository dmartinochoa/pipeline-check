# GitLab CI provider

Parses `.gitlab-ci.yml` on disk, no GitLab API token, no runner install.
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

39 checks · 12 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GL-001](#gl-001) | Image not pinned to specific version or digest | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GL-002](#gl-002) | Script injection via untrusted commit/MR context | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GL-003](#gl-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GL-004](#gl-004) | Deploy job lacks manual approval or environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GL-005](#gl-005) | include: pulls remote / project without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GL-006](#gl-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GL-007](#gl-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GL-008](#gl-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GL-009](#gl-009) | Image pinned to version tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GL-010](#gl-010) | Multi-project pipeline ingests upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GL-011](#gl-011) | include: local file pulled in MR-triggered pipeline | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GL-012](#gl-012) | Cache key derives from MR-controlled CI variable | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GL-013](#gl-013) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GL-014](#gl-014) | Self-managed runner without ephemeral tag | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GL-015](#gl-015) | Job has no `timeout`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GL-016](#gl-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GL-017](#gl-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GL-018](#gl-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GL-019](#gl-019) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GL-020](#gl-020) | CI_JOB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GL-021](#gl-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GL-022](#gl-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GL-023](#gl-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GL-024](#gl-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GL-025](#gl-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GL-026](#gl-026) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GL-027](#gl-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GL-028](#gl-028) | services: image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GL-029](#gl-029) | Manual deploy job defaults to allow_failure: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GL-030](#gl-030) | trigger: include: pulls child pipeline without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GL-031](#gl-031) | id_tokens: missing audience pin or environment binding | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GL-032](#gl-032) | tags: interpolates untrusted CI variable | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GL-033](#gl-033) | Global before_script / after_script propagates taint to every job | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GL-034](#gl-034) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GL-035](#gl-035) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GL-036](#gl-036) | Secret-named variable echoed / printed in a script block | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GL-037](#gl-037) | Pipeline disables Go module checksum / sum-db verification | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TAINT-004](#taint-004) | Untrusted input flows across jobs via dotenv artifact | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TAINT-008](#taint-008) | Untrusted input flows via GitLab ``extends:`` template inheritance | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## GL-001: Image not pinned to specific version or digest { #gl-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Floating tags (`latest` or major-only) can be silently swapped under the job. Every `image:` reference should pin a specific version tag or digest.

<div class="pg-rule__rec" markdown>

**Recommended action**

Reference images by `@sha256:<digest>` or at minimum a full immutable version tag (e.g. `python:3.12.1-slim`). Avoid `:latest` and bare tags like `:3`.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-002: Script injection via untrusted commit/MR context { #gl-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

CI_COMMIT_MESSAGE / CI_COMMIT_REF_NAME / CI_MERGE_REQUEST_TITLE and friends are populated from SCM event metadata the attacker controls. Interpolating them into a shell body executes the crafted content as part of the build.

<div class="pg-rule__rec" markdown>

**Recommended action**

Read these values into intermediate `variables:` entries or shell variables and quote them defensively (`"$BRANCH"`). Never inline `$CI_COMMIT_MESSAGE` / `$CI_MERGE_REQUEST_TITLE` into a shell command.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GL-003: Variables contain literal secret values { #gl-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Scans `variables:` at the top level and on each job for entries whose KEY looks credential-shaped and whose VALUE is a literal string (not a `$VAR` reference). AWS access keys are detected by value pattern regardless of key name.

<div class="pg-rule__rec" markdown>

**Recommended action**

Store credentials as protected + masked CI/CD variables in project or group settings, and reference them by name from the YAML. For cloud access prefer short-lived OIDC tokens.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-004: Deploy job lacks manual approval or environment gate { #gl-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--esf">ESF-C-ENV-SEP</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A job whose stage or name contains `deploy` / `release` / `publish` / `promote` should either require manual approval or declare an `environment:` binding. Otherwise any push to the trigger branch ships to the target.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `when: manual` (optionally with `rules:` for protected branches) or bind the job to an `environment:` with a deployment tier so approvals and audit are enforced by GitLab's environment controls.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-005: include: pulls remote / project without pinned ref { #gl-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Cross-project and remote includes can be silently re-pointed. Branch-name refs (`main`/`master`/`develop`/`head`/`trunk`) are treated as unpinned; tag and SHA refs are considered safe.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin `include: project:` entries with `ref:` set to a tag or commit SHA. Avoid `include: remote:` for untrusted URLs; mirror the content into a trusted project and pin it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-006: Artifacts not signed { #gl-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Unsigned artifacts can't be verified downstream, so a tampered build is indistinguishable from a legitimate one. Pass when any of cosign / sigstore / slsa-* / notation-sign appears in the pipeline text.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a job that runs `cosign sign` (keyless OIDC with GitLab's id_tokens works out of the box) or `notation sign`. Publish the signature next to the artifact and verify it on consume.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-007: SBOM not produced { #gl-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / spdx-sbom-generator / sbom-tool / Trivy-SBOM appears in the pipeline body.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an SBOM step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or GitLab's built-in CycloneDX dependency-scanning template. Attach the SBOM as a pipeline artifact.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GL-008: Credential-shaped literal in pipeline body { #gl-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Complements GL-003 (which looks at `variables:` block keys). GL-008 scans every string in the pipeline against the cross-provider credential-pattern catalog, catches secrets pasted into `script:` bodies or environment blocks where the name-based detector can't see them.

**Known false-positive modes**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, vendor example keys). Well-known vendor example tokens (``AKIAIOSFODNN7EXAMPLE``, Stripe ``sk_test_`` docs keys) are suppressed via the ``VENDOR_EXAMPLE_TOKENS`` allowlist. Defaults to LOW confidence.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the exposed credential immediately. Move the value to a protected + masked CI/CD variable and reference it by name. For cloud access prefer short-lived OIDC tokens.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GL-009: Image pinned to version tag rather than sha256 digest { #gl-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

GL-001 fails floating tags at HIGH; GL-009 is the stricter tier. Even immutable-looking version tags (`python:3.12.1`) can be repointed by registry operators. Digest pins are the only tamper-evident form.

<div class="pg-rule__rec" markdown>

**Recommended action**

Resolve each image to its current digest (`docker buildx imagetools inspect <ref>` prints it) and replace the tag with `@sha256:<digest>`. Automate refreshes with Renovate.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GL-010: Multi-project pipeline ingests upstream artifact unverified { #gl-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

`needs: { project: ..., artifacts: true }` pulls artifacts from another project's pipeline. If that upstream project accepts MR pipelines, the artifact may have been built by attacker-controlled code.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a verification step before consuming the artifact: `cosign verify-attestation`, `sha256sum -c`, or `gpg --verify` against a manifest signed by the upstream project's release key. Only consume artifacts produced by upstream pipelines whose origin you can trust.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-011: include: local file pulled in MR-triggered pipeline { #gl-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

`include: local: '<path>'` resolves from the current pipeline's checked-out tree. On an MR pipeline the tree is the MR source branch, the MR author controls the included YAML content.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the included template into a separate, read-only project and reference it via `include: project: ... ref: <sha-or-tag>`. That way the included content is fixed at MR creation time and not editable from the MR branch.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-012: Cache key derives from MR-controlled CI variable { #gl-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

GitLab caches restore by key prefix. When the key includes an MR-controlled variable, an attacker can poison a cache entry that a later default-branch pipeline restores.

<div class="pg-rule__rec" markdown>

**Recommended action**

Build the cache key from values the MR can't control: lockfile contents (`files: [Cargo.lock]`), the job name, and `$CI_PROJECT_NAMESPACE`. Never reference `$CI_MERGE_REQUEST_*` or `$CI_COMMIT_BRANCH` from a cache key namespace.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-013: AWS auth uses long-lived access keys { #gl-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-TOKEN-HYGIENE</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values in CI/CD variables can't be rotated on a fine-grained schedule. GitLab supports OIDC via `id_tokens:` for short-lived credential injection.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use GitLab CI/CD OIDC with `id_tokens:` to obtain short-lived AWS credentials via `sts:AssumeRoleWithWebIdentity`. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from CI/CD variables.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-014: Self-managed runner without ephemeral tag { #gl-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Self-managed runners that don't tear down between jobs leak filesystem and process state. The check looks for an `ephemeral` tag on any job whose `tags:` list doesn't match SaaS-only runner names.

<div class="pg-rule__rec" markdown>

**Recommended action**

Register the runner with `--executor docker` + `--docker-pull-policy always` so containers are fresh per job, and add an `ephemeral` tag. Alternatively use the GitLab Runner Operator with autoscaling.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-015: Job has no `timeout`, unbounded build { #gl-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-TIMEOUT</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Without an explicit `timeout`, the job runs until the instance-level default (typically 60 minutes). Explicit timeouts cap blast radius and the window during which a compromised script has access to CI/CD variables.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `timeout:` to each job (e.g. `timeout: 30 minutes`), sized to the 95th percentile of historical runtime. GitLab's default is 60 minutes (or the instance admin setting).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-016: Remote script piped to shell interpreter { #gl-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Known false-positive modes**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

<div class="pg-rule__rec" markdown>

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GL-017: Docker run with insecure flags (privileged/host mount) { #gl-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a pipeline give the container full access to the CI runner, enabling container escape and lateral movement.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-018: Package install from insecure source { #gl-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-019: No vulnerability scanning step { #gl-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GL-020: CI_JOB_TOKEN written to persistent storage { #gl-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Detects patterns where `CI_JOB_TOKEN` is redirected to a file, piped through `tee`, or appended to dotenv/artifact paths. Persisted tokens survive the job boundary and can be read by later stages, downloaded artifacts, or cache entries, turning a scoped credential into a long-lived one.

<div class="pg-rule__rec" markdown>

**Recommended action**

Never write CI_JOB_TOKEN to files, artifacts, or dotenv reports. Use the token inline in the command that needs it and let GitLab revoke it automatically when the job finishes.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-021: Package install without lockfile enforcement { #gl-021 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-022: Dependency update command bypasses lockfile pins { #gl-022 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Known false-positive modes**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-023: TLS / certificate verification bypass { #gl-023 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-295</span>
</div>

Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-024: No SLSA provenance attestation produced { #gl-024 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

``cosign sign`` and ``cosign attest`` look similar but mean different things: the first binds identity to bytes; the second binds a structured claim (builder, source, inputs) to the artifact. SLSA Build L3 verifiers check the latter.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a job that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or adopt a SLSA-aware builder (the SLSA project ships GitLab templates). Signing the artifact (GL-006) isn't enough for SLSA L3, the attestation describes *how* the build ran.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GL-025: Pipeline contains indicators of malicious activity { #gl-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-506</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Fires on concrete indicators (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, ``webhook.site`` callbacks, ``env | curl`` credential dumps, ``history -c`` audit erasure). Orthogonal to GL-003 (curl pipe) and GL-017 (Docker insecure flags). Those flag risky defaults; this flags evidence.

**Known false-positive modes**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat as a potential compromise. Identify the MR that added the matching job(s), rotate any credentials the pipeline can reach, and audit recent runs for outbound traffic to the matched hosts. A legitimate red-team exercise should be time-bounded via ``.pipelinecheckignore`` with ``expires:``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-026: Dangerous shell idiom (eval, sh -c variable, backtick exec) { #gl-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-95</span>
</div>

``eval``, ``sh -c "$X"``, and `` `$X` `` all re-parse the variable's value as shell syntax. Once a CI variable feeds into one of these idioms, any ``;``, ``&&``, ``|``, backtick, or ``$()`` in the value executes, even if the variable's source is currently trusted, future refactors may expose it.

**Known false-positive modes**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec of variables with direct command invocation. If the command must be dynamic, pass arguments as array members or validate the input against an allow-list at the boundary.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-027: Package install bypasses registry integrity (git / path / tarball source) { #gl-027 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Complements GL-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs all bypass the registry integrity controls the lockfile relies on, an attacker who can move a branch head, drop a sibling checkout, or change a served tarball can substitute code into the build.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-028: services: image not pinned { #gl-028 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

``services:`` entries (top-level or per-job) can be either a string (``redis:7``) or a dict (``{name: redis:7, alias: cache}``). Both forms are normalized via ``image_ref``-style extraction and evaluated with the same floating-tag regex GL-001 uses for ``image:``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every ``services:`` entry the same way ``image:`` is pinned, prefer ``@sha256:<digest>``, or at minimum a full immutable version tag (``postgres:16.2-alpine``). Avoid ``:latest`` and bare tags like ``:16``.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-029: Manual deploy job defaults to allow_failure: true { #gl-029 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

This is the most common GitLab deployment gotcha: a manual ``deploy`` job looks like a gate in the UI, but the pipeline reports success on the first run because the job is marked allow_failure by default. Downstream jobs (and the overall pipeline status) proceed as though the human approved.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add ``allow_failure: false`` to every deploy-like ``when: manual`` job. GitLab defaults ``allow_failure`` to *true* for manual jobs, which makes the pipeline report success whether or not the operator clicks, exactly the opposite of the gate you meant to add.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-030: trigger: include: pulls child pipeline without pinned ref { #gl-030 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

GL-005 only audits top-level ``include:``. Parent-child and multi-project pipelines that load YAML via the job-level ``trigger: include:`` slot slip through. Branch refs (``main``/``master``/``develop``/``head``/``trunk``) count as unpinned.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin ``trigger: include: project:`` entries with ``ref:`` set to a tag or commit SHA. Avoid ``trigger: include: remote:`` for untrusted URLs; mirror the content into a trusted project and pin it there.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-031: id_tokens: missing audience pin or environment binding { #gl-031 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Pairs with IAM-008. IAM-008 verifies the cloud-side trust policy pins audience + subject; this rule verifies the GitLab-side workflow can't request a token without an audience claim or without a deployment gate.

<div class="pg-rule__rec" markdown>

**Recommended action**

For every job that declares an ``id_tokens:`` block, pin a non-wildcard ``aud:`` (a literal string the consumer trusts) AND bind the job to a protected ``environment:``. Audience pinning prevents token replay against unintended consumers; the environment binding gates which refs can drive the assume-role on the consumer side.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-032: tags: interpolates untrusted CI variable { #gl-032 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

GL-014 catches self-managed runners that aren't ephemeral; this rule catches the upstream targeting choice. When ``tags:`` is computed from an attacker-controllable CI variable, the operator (or anyone who can craft a PR title / branch name / commit message that the workflow consumes) picks where the job runs, including any privileged tag the instance exposes (``deploy-prod``, ``signer``, ``hsm`` …). The rule reuses the same untrusted-context catalog as GL-002 (``CI_COMMIT_MESSAGE``, ``CI_COMMIT_REF_NAME``, ``CI_MERGE_REQUEST_TITLE`` and friends) so the two rules stay in lockstep.

**Known false-positive modes**

- Workflows that intentionally select runners by environment via a vetted ``variables:`` block (``RUNNER_TAG: deploy-prod``) referencing a build-time-set value are out of scope, the rule only matches the curated untrusted-predefined-variable catalog. Static custom variables (``$DEPLOY_FLEET`` defined inside the workflow file) are intentionally not flagged.

<div class="pg-rule__rec" markdown>

**Recommended action**

Hard-code ``tags:`` to a specific runner tag list. If runner selection has to be parameterised, validate the candidate value against an explicit allowlist in a job ``rules:`` block before the job runs, and never accept a ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` field as a tag value directly.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-033: Global before_script / after_script propagates taint to every job { #gl-033 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

GL-002 catches injection in **per-job** ``before_script:`` / ``script:`` / ``after_script:``, but its scanner walks ``iter_jobs`` which deliberately skips top-level keywords (``before_script``, ``after_script``, ``default``, ``image``, ``services``, ``variables``, ``stages``, ``workflow``, ``include``, ...). That means a tainted ``$CI_COMMIT_TITLE`` interpolation in a document-root ``before_script:`` or ``default.before_script:`` evades GL-002 entirely, even though it propagates to every job in the pipeline.

GL-033 closes that gap. It scans:

- ``before_script:`` at document root
- ``after_script:`` at document root
- ``default.before_script:`` (the modern form)
- ``default.after_script:``

for direct interpolation of the same attacker-controllable predefined variables tracked by GL-002 (``CI_COMMIT_TITLE`` / ``CI_COMMIT_MESSAGE`` / ``CI_COMMIT_REF_NAME`` / ``CI_MERGE_REQUEST_TITLE`` / ``CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`` / etc.). The detection mirrors GL-002's ``has_direct_taint`` helper so the quote-aware semantics are identical.

**Known false-positive modes**

- Some self-hosted GitLab installations build a diagnostic banner into the global ``before_script`` that ``echo``s commit metadata for log-correlation purposes. Suppress per pipeline file rather than globally, the rule is checking propagation reach, not intent.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move any setup logic that touches commit / MR metadata out of the document-root ``before_script:`` (and ``default.before_script:`` / ``default.after_script:``) and into a dedicated job that opts in via ``extends:`` or that runs on a known-safe trigger only. The global before-script runs verbatim before every job in the pipeline (including child pipelines launched by ``trigger:include:``); a single unquoted ``$CI_COMMIT_TITLE`` interpolation there is, in effect, that injection in N jobs at once. Quote the value defensively (``branch="$CI_COMMIT_REF_NAME"``) and copy it into a job-local variable before any further use.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-034: npm install without registry-signature verification step { #gl-034 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Fires once per pipeline file when:

1. Some job's ``before_script:`` / ``script:`` / ``after_script:`` runs an npm or pnpm install verb (``npm ci``, ``npm install``, ``npm i``, ``pnpm install``, ``pnpm i``, ``pnpm ci``);
2. No job anywhere in the pipeline runs ``npm audit signatures`` or ``pnpm audit signatures``.

Yarn / Bun-only pipelines pass silently because the ``audit signatures`` primitive is npm-CLI-specific (Yarn Berry's ``yarn npm audit`` does not yet verify registry trusted-publisher records). Pairs with the per-package lockfile rules NPM-002 / NPM-006: NPM-002 / NPM-006 verify *what* the lockfile pinned, GL-034 verifies the lockfile pinned what the maintainer actually signed.

**Known false-positive modes**

- Pipelines that build against a private registry without trusted-publisher records (legacy Artifactory, self-hosted Verdaccio without sigstore) cannot run ``audit signatures`` meaningfully. Suppress on the specific pipeline with a rationale that names the private registry.

**Seen in the wild**

- Shai-Hulud npm worm (2026) / TanStack / axios patch-release compromises rode the gap between lockfile-pinned integrity and registry-signed-publisher provenance. ``npm audit signatures`` is the gate that consumes trusted-publisher records.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an ``npm audit signatures`` step (or ``pnpm audit signatures``) after the install. Lockfile pinning only guarantees the bytes installed match what the lockfile recorded; ``audit signatures`` is what verifies those bytes were signed by the maintainer the registry recognizes as the package's trusted publisher. Run it as a separate script line after ``npm ci`` and before any code from ``node_modules/`` executes.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GL-035: pip install without `--require-hashes` verification { #gl-035 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Fires once per pipeline file when:

1. Some job's ``before_script:`` / ``script:`` / ``after_script:`` runs a real ``pip install`` (``pip install``, ``pip3 install``, ``python -m pip install``) that isn't a tooling-bootstrap exempted by the allowlist;
2. No job uses ``--require-hashes`` AND no job uses a lockfile-consuming manager (``uv sync`` / ``uv pip sync``, ``poetry install``, ``pipenv install --deploy`` / ``pipenv sync``).

Tooling-bootstrap allowlist (same as GHA-060).

**Known false-positive modes**

- Pipelines that build against a private index without SHA-256 hash records (legacy DevPI, self-hosted simple indexes without per-file hashes) cannot run ``--require-hashes`` meaningfully. Suppress on the specific pipeline with a rationale that names the private index.

**Seen in the wild**

- PyPI maintainer-account compromises (ctx 2022, requests-darwin-lite 2024) shipped malicious sdists / wheels under existing version pins; ``--require-hashes`` would have refused the swap.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every dependency with a SHA-256 hash and install with ``pip install -r requirements.txt --require-hashes``, or migrate to a manager that hash-pins by default: ``uv sync``, ``poetry install``, ``pipenv install --deploy``. Hash-pinned install is the PyPI equivalent of npm's lockfile-integrity guarantee: it refuses to install any tarball whose SHA-256 doesn't match a recorded entry.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-036: Secret-named variable echoed / printed in a script block { #gl-036 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-532</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Detects three shapes in ``script:``, ``before_script:``, and ``after_script:`` blocks:

1. ``echo`` / ``printf`` / ``cat`` / ``tee`` of a variable whose name matches common secret patterns (PASSWORD, TOKEN, API_KEY, SECRET, CREDENTIAL, etc.).
2. ``printenv`` / ``env`` commands that dump the entire environment (which includes CI/CD variables that may hold secrets).
3. ``set -x`` (shell trace) enabled alongside any reference to a secret-named variable.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't print secret values in CI scripts. GitLab's log masking only covers variables explicitly marked as masked in the UI, and only when the full value appears as a contiguous string. Base64-encoded, URL-encoded, or partial substrings bypass the mask. Log a boolean instead (``[ -n "$X" ] && echo set || echo unset``). Avoid ``set -x`` when secret-bound variables are in scope.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GL-037: Pipeline disables Go module checksum / sum-db verification { #gl-037 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-353</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Walks the global and per-job ``variables:`` maps and every ``script:`` / ``before_script:`` / ``after_script:`` body (for inline ``export GOSUMDB=off`` assignments) and flags the Go integrity-disabling settings via the shared ``_primitives/go_insecure_env`` detector: ``GOFLAGS`` with ``-insecure``, ``GOSUMDB=off``, truthy ``GONOSUMCHECK``, any ``GOINSECURE``, and a broad ``GOPRIVATE`` / ``GONOSUMDB`` glob.

Scoped ``GOPRIVATE`` and ``GOPROXY=off`` / ``direct`` (still checksum-verified) are not flagged. The CI-variable face of the verification-bypass surface GOMOD-001 warns about; the GitLab sibling of GHA-110 / CC-033.

**Known false-positive modes**

- A pipeline that builds only against an internal module proxy on a trusted network may set a scoped ``GOINSECURE`` for one internal host deliberately. Suppress per pipeline with a rationale; a TLS-terminating internal proxy that preserves checksum verification is the safer path.

**Seen in the wild**

- V
- e
- r
- i
- f
- i
- c
- a
- t
- i
- o
- n
- -
- b
- y
- p
- a
- s
- s
- 
- c
- l
- a
- s
- s
- :
- 
- a
- 
- r
- u
- n
- n
- e
- r
- 
- t
- o
- l
- d
- 
- t
- o
- 
- s
- k
- i
- p
- 
- t
- h
- e
- 
- G
- o
- 
- c
- h
- e
- c
- k
- s
- u
- m
- 
- d
- a
- t
- a
- b
- a
- s
- e
- 
- /
- 
- s
- u
- m
- 
- f
- i
- l
- e
- 
- c
- a
- n
- 
- b
- e
- 
- s
- e
- r
- v
- e
- d
- 
- a
- 
- s
- u
- b
- s
- t
- i
- t
- u
- t
- e
- d
- 
- m
- o
- d
- u
- l
- e
- 
- w
- i
- t
- h
- o
- u
- t
- 
- `
- `
- g
- o
- 
- m
- o
- d
- 
- v
- e
- r
- i
- f
- y
- `
- `
- 
- c
- a
- t
- c
- h
- i
- n
- g
- 
- i
- t
- ,
- 
- t
- h
- e
- 
- s
- a
- m
- e
- 
- g
- a
- p
- 
- G
- O
- M
- O
- D
- -
- 0
- 0
- 1
- 
- f
- l
- a
- g
- s
- 
- f
- r
- o
- m
- 
- t
- h
- e
- 
- `
- `
- g
- o
- .
- s
- u
- m
- `
- `
- 
- s
- i
- d
- e
- .

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the Go toolchain variables that turn off module integrity verification so ``go build`` keeps checking every downloaded module against ``go.sum`` and the checksum transparency database. Drop ``GOFLAGS=-insecure`` (plain HTTP fetch, TLS off), ``GOSUMDB=off`` / legacy ``GONOSUMCHECK`` (checksum DB / sum check off), and any ``GOINSECURE``; scope ``GOPRIVATE`` / ``GONOSUMDB`` to the exact internal namespace (``corp.example.com/team/*``) rather than a broad ``*`` or whole public host. This is the CI-variable twin of GOMOD-001, a committed ``go.sum`` is moot if the runner ignores it. For private modules, prefer a trusted internal ``GOPROXY`` that still enforces checksums over disabling verification.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TAINT-004: Untrusted input flows across jobs via dotenv artifact { #taint-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detection is a two-pass walk over the pipeline. Pass 1 looks for jobs whose scripts write ``KEY=value`` to a file declared under ``artifacts.reports.dotenv:`` and whose ``value`` interpolates an attacker-controllable GitLab predefined variable (the ``UNTRUSTED_VAR_RE`` vocabulary GL-002 already uses). Pass 2 walks every job with a ``needs:`` / ``dependencies:`` link to a producer and looks for ``$KEY`` references in scripts that match a tainted leak.

v1 limitations: ``extends:`` job-template inheritance and cross-pipeline ``include:`` are not yet tracked. The dotenv path matching is literal (``./taint.env`` and ``taint.env`` are treated as the same path), no glob expansion is performed.

**Known false-positive modes**

- If the producer job runs a sanitiser between the tainted source interpolation and the dotenv write (``echo "$CI_COMMIT_TITLE" | tr -dc 'a-zA-Z0-9 ' > taint.env``), the consumer is no longer exploitable but TAINT-004 still fires. Suppress via ignore-file scoped to the consumer job's pipeline file when this is the deliberate shape; the sanitiser is then load-bearing and any future regression in it would re-expose the consumer.

<div class="pg-rule__rec" markdown>

**Recommended action**

Sanitise the value at the producer job before it lands in the dotenv file. The canonical safe pattern is to copy the ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` source into an intermediate shell variable, run a sanitiser (``tr -dc 'a-zA-Z0-9 '`` is enough for a freeform title), and only then write the cleaned value to dotenv. The consuming job should still treat the auto-imported variable as tainted, reference it quoted (``"$TITLE"``) and never inline into a command without re-quoting. Removing the dotenv entirely is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitiser is doing what you think before relying on it.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TAINT-008: Untrusted input flows via GitLab ``extends:`` template inheritance { #taint-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Two-pass walk over the pipeline doc. Pass 1 builds a universe of every job-shaped entry (hidden templates included, top-level keywords excluded), resolves each non-hidden job's ``extends:`` chain transitively, and gathers tainted variables (any ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` interpolation in the link's ``variables:`` block). Pass 2 walks the consuming job's ``before_script:`` / ``script:`` / ``after_script:`` for unquoted ``$<name>`` references matching an inherited tainted variable. Cycles in the extends chain are broken via a visited set; unresolvable extends entries are silently dropped.

v1 limitations: ``include:`` cross-pipeline file inclusion isn't tracked yet (would need cross-document analysis like the GHA ``--resolve-remote`` flow). ``extends:`` chains that pull templates from include-d files are partial: in-doc links resolve, external links are treated as missing.

**Known false-positive modes**

- If the consuming job sanitises the inherited variable before referencing it (``CLEAN=$(echo "$TITLE" | tr -dc 'a-zA-Z0-9 '); echo $CLEAN``), the rule still fires on the original ``$TITLE`` reference even though the sanitised value is what reaches the shell. Suppress via ignore-file scoped to the consuming job's name when the sanitiser is audited and load-bearing.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the tainted-source interpolation out of the template's ``variables:`` block. The canonical safe pattern is to receive the source value through ``$CI_*`` directly in the consuming job's script (or a dedicated sanitiser step) and never copy it into a shared variable a downstream job can interpolate unquoted. If the inheritance is genuinely needed, sanitise at the boundary (``TITLE_SAFE: '$(echo "$CI_COMMIT_TITLE" | tr -dc "a-zA-Z0-9 ")'``) and have the extending job reference the cleaned variable. Removing the ``extends:`` propagation is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitiser is doing what you think before relying on it.

</div>

</div>

---

## Adding a new GitLab CI check

1. Create a new module at
   `pipeline_check/core/checks/gitlab/rules/glNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
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
