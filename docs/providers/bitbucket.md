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

29 checks · 11 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [BB-001](#bb-001) | pipe: action not pinned to exact version | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BB-002](#bb-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BB-003](#bb-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [BB-004](#bb-004) | Deploy step missing `deployment:` environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BB-005](#bb-005) | Step has no `max-time` — unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BB-006](#bb-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BB-007](#bb-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BB-008](#bb-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BB-009](#bb-009) | pipe: pinned by version rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [BB-010](#bb-010) | Deploy step ingests pull-request artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [BB-011](#bb-011) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BB-012](#bb-012) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BB-013](#bb-013) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BB-014](#bb-014) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BB-015](#bb-015) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BB-016](#bb-016) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BB-017](#bb-017) | Repository token written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BB-018](#bb-018) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BB-019](#bb-019) | after-script references secrets | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BB-020](#bb-020) | Full clone depth exposes complete history | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [BB-021](#bb-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BB-022](#bb-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BB-023](#bb-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BB-024](#bb-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BB-025](#bb-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [BB-026](#bb-026) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BB-027](#bb-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BB-028](#bb-028) | OIDC step without deployment-gated environment | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BB-029](#bb-029) | image: (step or service) not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## BB-001 — pipe: action not pinned to exact version { #bb-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Bitbucket pipes are docker-image references. Major-only (`:1`) or missing tags let Atlassian/the publisher swap the image contents. Full semver or sha256 digest is required.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every `pipe:` to a full semver tag (e.g. `atlassian/aws-s3-deploy:1.4.0`) or to an immutable SHA. Floating majors like `:1` can roll to new code silently.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-002 — Script injection via attacker-controllable context { #bb-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

$BITBUCKET_BRANCH, $BITBUCKET_TAG, and $BITBUCKET_PR_* are populated from SCM event metadata the attacker controls. Interpolating them unquoted into a shell command lets a crafted branch or tag name can execute inline.

<div class="pg-rule__rec" markdown>

**Recommended action**

Always double-quote interpolations of ref-derived variables (`"$BITBUCKET_BRANCH"`). Avoid passing them to `eval`, `sh -c`, or unquoted command arguments.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BB-003 — Variables contain literal secret values { #bb-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Scans `definitions.variables` and each step's `variables:` for entries whose KEY looks credential-shaped and whose VALUE is a literal string. AWS access keys are detected by value shape regardless of key name.

<div class="pg-rule__rec" markdown>

**Recommended action**

Store credentials as Repository / Deployment Variables in Bitbucket's Pipelines settings with the 'Secured' flag, and reference them by name. Prefer short-lived OIDC tokens for cloud access.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-004 — Deploy step missing `deployment:` environment gate { #bb-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--esf">ESF-C-ENV-SEP</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A step whose name or invoked pipe matches `deploy` / `release` / `publish` / `promote` should declare a `deployment:` field so Bitbucket enforces deployment-scoped variables, approvals, and history.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `deployment: production` (or `staging` / `test`) to the step. Configure the matching environment in the repo's Deployments settings with required reviewers and secured variables.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-005 — Step has no `max-time` — unbounded build { #bb-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-TIMEOUT</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Without `max-time`, the step runs until Bitbucket's 120-minute global default kills it. Explicit per-step timeouts cap blast radius and cost.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `max-time: <minutes>` to each step, sized to the 95th percentile of historical runtime plus margin. Bounded runs limit the blast radius of a compromised build and prevent runaway minute consumption.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-006 — Artifacts not signed { #bb-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Unsigned artifacts can't be verified downstream. Passes when cosign / sigstore / slsa-* / notation-sign appears in the pipeline body.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a step that runs `cosign sign` against the built image or archive, using Bitbucket OIDC for keyless signing where possible. Publish the signature next to the artifact and verify it at deploy time.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-007 — SBOM not produced { #bb-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / sbom-tool / Trivy-SBOM appears.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an SBOM step — `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM as a build artifact.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BB-008 — Credential-shaped literal in pipeline body { #bb-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Complements BB-003 (variable-name scan). BB-008 checks every string in the pipeline against the cross-provider credential-pattern catalog — catches secrets pasted into script bodies or environment blocks.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the exposed credential. Move the value to a Secured Repository or Deployment Variable and reference it by name.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## BB-009 — pipe: pinned by version rather than sha256 digest { #bb-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

BB-001 fails floating tags at HIGH; BB-009 is the stricter tier. Even immutable-looking semver tags can be repointed by the registry; sha256 digests are tamper-evident.

<div class="pg-rule__rec" markdown>

**Recommended action**

Resolve each pipe to its digest (`docker buildx imagetools inspect bitbucketpipelines/<name>:<ver>`) and reference it via `@sha256:<digest>`.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BB-010 — Deploy step ingests pull-request artifact unverified { #bb-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Bitbucket steps declare artifacts on the producer and downstream steps implicitly receive them. When an unprivileged step produces an artifact and a later `deployment:` step consumes it without verification, attacker-controlled output flows into the privileged stage.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a verification step before the deploy step consumes the artifact: `sha256sum -c artifact.sha256` against a manifest the producer signed, or `cosign verify` over the artifact directly. Alternatively, restrict the artifact-producing step to non-PR pipelines via ``branches:`` or ``custom:`` triggers.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-011 — AWS auth uses long-lived access keys { #bb-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-TOKEN-HYGIENE</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values embedded in the pipeline file can't be rotated on a fine-grained schedule. Prefer OIDC or Bitbucket secured variables for cross-cloud access.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use Bitbucket OIDC with `oidc: true` on the AWS pipe, or store credentials as secured Bitbucket variables rather than inline values. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the pipeline file.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-012 — Remote script piped to shell interpreter { #bb-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build runner.

<div class="pg-rule__rec" markdown>

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BB-013 — Docker run with insecure flags (privileged/host mount) { #bb-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a pipeline give the container full access to the build runner, enabling container escape and lateral movement.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-014 — Package install from insecure source { #bb-014 }

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

## BB-015 — No vulnerability scanning step { #bb-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognises trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a vulnerability scanning step — trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-016 — Self-hosted runner without ephemeral marker { #bb-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Self-hosted runners that persist between jobs leak filesystem and process state. A PR-triggered step writes to a well-known path; a subsequent deploy step on the same runner reads it. Detects `runs-on: self.hosted` without an `ephemeral` marker or Docker image override.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use Docker-based self-hosted runners or configure runners to tear down between jobs. Add 'ephemeral' to `runs-on` labels or use Bitbucket's runner images that are rebuilt per-job.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BB-017 — Repository token written to persistent storage { #bb-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Detects patterns where Bitbucket pipeline tokens are redirected to files or piped through `tee`. Persisted tokens survive the step boundary and can be exfiltrated by later steps, artifacts, or cache entries.

<div class="pg-rule__rec" markdown>

**Recommended action**

Never write BITBUCKET_TOKEN or REPOSITORY_OAUTH_ACCESS_TOKEN to files or artifacts. Use the token inline in the command that needs it and let Bitbucket revoke it after the build.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-018 — Cache key derives from attacker-controllable input { #bb-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Bitbucket caches are restored by key. When the key includes a value the attacker controls (branch name, tag, PR ID), a pull-request pipeline can plant a poisoned cache entry that a subsequent default-branch build restores.

<div class="pg-rule__rec" markdown>

**Recommended action**

Build the cache key from values the attacker cannot control. Prefer `hashFiles()` on lockfiles enforced by branch protection. Never include $BITBUCKET_BRANCH or PR-related variables in the cache key.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-019 — after-script references secrets { #bb-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Bitbucket's `after-script` runs unconditionally after the main `script` block (including on failure). If the `after-script` references secrets or tokens, those values may leak into build logs or artifacts even when the step fails unexpectedly. This check detects secret-like variable references in `after-script` blocks.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move secret-dependent operations into the main `script:` block. `after-script` runs even when the step fails and executes in a separate shell context — credential exposure here is harder to audit and more likely to persist in logs.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## BB-020 — Full clone depth exposes complete history { #bb-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

By default Bitbucket Pipelines clone with `depth: 50`. Setting `depth: full` exposes the entire commit history, including any secrets that were committed and later removed. This check flags explicit `clone: depth: full` settings.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set `clone: depth: 1` (or a small number) in pipeline or step options to limit the amount of repository history available in the build environment. Full clones make it easier to extract secrets that were committed and later removed.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-021 — Package install without lockfile enforcement { #bb-021 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest — exactly the window a supply-chain attacker exploits.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-022 — Dependency update command bypasses lockfile pins { #bb-022 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-023 — TLS / certificate verification bypass { #bb-023 }

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

## BB-024 — No SLSA provenance attestation produced { #bb-024 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Bitbucket has no native SLSA builder; self-hosted attestation via ``cosign attest`` or ``witness run`` is the usual path. Pipes like ``atlassian/cosign-attest`` (if published) would also match.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a step that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or integrate the TestifySec ``witness run`` attestor. Artifact signing alone (BB-006) doesn't satisfy SLSA Build L3.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BB-025 — Pipeline contains indicators of malicious activity { #bb-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-506</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Specific indicators only (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, credential-dump pipes, audit-erasure commands). Does not replace BB-014 (TLS bypass) or BB-013 (Docker insecure) — those are hygiene; this is evidence.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat as a potential compromise. Identify the PR that added the matching step(s), rotate any credentials referenced from the pipeline's variable groups, and audit recent builds.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-026 — Dangerous shell idiom (eval, sh -c variable, backtick exec) { #bb-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-95</span>
</div>

Complements BB-002 (script injection from untrusted PR context). This rule fires on intrinsically risky idioms — ``eval``, ``sh -c "$X"``, backtick exec — regardless of whether the input source is currently trusted.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-027 — Package install bypasses registry integrity (git / path / tarball source) { #bb-027 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Complements BB-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin git dependencies to a commit SHA. Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-028 — OIDC step without deployment-gated environment { #bb-028 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Pairs with IAM-008 — IAM-008 verifies the cloud-side trust policy pins audience + subject; this rule verifies the Bitbucket-side workflow can't request a token without a deployment gate. Bitbucket's ``pull-requests:`` triggers from forks so OIDC under that branch is always an unbounded blast radius.

<div class="pg-rule__rec" markdown>

**Recommended action**

Every step that sets ``oidc: true`` must also declare a ``deployment:`` (production / staging / test). Bitbucket deployments enforce manual approvals, restricted variables, and audit logs that an ungated step bypasses. Steps reached through ``pull-requests:`` should never request OIDC tokens — any forked PR can drive the role assumption.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-029 — image: (step or service) not pinned by sha256 digest { #bb-029 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

BB-001 / BB-009 only inspect ``pipe:`` references inside ``script:`` lists. Step ``image:`` directives and ``definitions.services.<name>.image:`` define the runtime container the build executes inside (and the auxiliary containers the step talks to over the loopback network). Both surfaces ship code into the build context — a compromised service image (the postgres container, the selenium-grid container, …) can exfiltrate every secret the step touches just as easily as the step image itself. This rule reuses ``_primitives.image_pinning.classify`` so the floating-tag semantics match GHA-001 / GL-001 / JF-009 / ADO-009 / CC-003 / K8S-001.

<div class="pg-rule__rec" markdown>

**Recommended action**

Resolve every ``image:`` reference to its current digest (``docker buildx imagetools inspect <ref>`` or ``crane digest <ref>``) and pin via ``image: name@sha256:<digest>``. Floating tags (``:latest``, ``:3``, no tag) silently swap the runtime image — the build's reproducibility invariant is broken and a registry-side compromise lands inside CI without any local change.

</div>

</div>

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
