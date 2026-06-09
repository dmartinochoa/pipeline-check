# Bitbucket Pipelines provider

Parses `bitbucket-pipelines.yml` on disk, no Bitbucket API token, no
runner install.

## Producer workflow

```bash
# --bitbucket-path auto-detected when bitbucket-pipelines.yml exists at cwd.
pipeline_check --pipeline bitbucket

# …or pass it explicitly (file or directory).
pipeline_check --pipeline bitbucket --bitbucket-path ci/
```

## What it covers

37 checks · 11 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [BB-001](#bb-001) | pipe: action not pinned to exact version | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BB-002](#bb-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BB-003](#bb-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [BB-004](#bb-004) | Deploy step missing `deployment:` environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BB-005](#bb-005) | Step has no `max-time`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
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
| [BB-030](#bb-030) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BB-031](#bb-031) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BB-032](#bb-032) | Secret-named variable echoed / printed in a script block | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BB-033](#bb-033) | IaC apply on a pull-request pipeline | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [BB-034](#bb-034) | Production deployment on a pull-request pipeline | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [BB-035](#bb-035) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BB-036](#bb-036) | Untrusted PR/branch context reaches an agentic AI CLI (prompt injection) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BB-037](#bb-037) | Unsafe deserialization of a fetched artifact (pickle RCE) | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## BB-001: pipe: action not pinned to exact version { #bb-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Bitbucket pipes are docker-image references. Major-only (`:1`) or missing tags let Atlassian/the publisher swap the image contents. Full semver or sha256 digest is required.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every `pipe:` to a full semver tag (e.g. `atlassian/aws-s3-deploy:1.4.0`) or to an immutable SHA. Floating majors like `:1` can roll to new code silently.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-002: Script injection via attacker-controllable context { #bb-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

$BITBUCKET_BRANCH, $BITBUCKET_TAG, and $BITBUCKET_PR_* are populated from SCM event metadata the attacker controls. Interpolating them unquoted into a shell command lets a crafted branch or tag name can execute inline. The same applies to trigger-time ``variables:`` declared by a ``custom:`` pipeline: anyone with run / trigger rights supplies the value (UI or API), so an unquoted reference in a later ``script:`` step is injection (the Bitbucket analogue of a workflow_dispatch input).

**Known false-positive modes**

- Pipelines that *parse* a ref name rather than execute it (``echo "$BITBUCKET_BRANCH" | cut -d/ -f2``) still interpolate the variable but expose no shell-execution surface for the value. The rule has no AST-level understanding of the surrounding shell context, so a well-quoted use that happens to live near an unrelated ``$(...)`` substitution can read as an offender. Suppress per-step via ``--ignore-file`` if the value is only consumed as data.

<div class="pg-rule__rec" markdown>

**Recommended action**

Always double-quote interpolations of ref-derived variables (`"$BITBUCKET_BRANCH"`). Avoid passing them to `eval`, `sh -c`, or unquoted command arguments.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BB-003: Variables contain literal secret values { #bb-003 }

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

## BB-004: Deploy step missing `deployment:` environment gate { #bb-004 }

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

## BB-005: Step has no `max-time`, unbounded build { #bb-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-TIMEOUT</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Without `max-time`, the step runs until Bitbucket's 120-minute global default kills it. Explicit per-step timeouts cap blast radius and cost. A global `options.max-time` sets the default for all steps and satisfies this control when no per-step override is present.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `max-time: <minutes>` to each step, sized to the 95th percentile of historical runtime plus margin. Bounded runs limit the blast radius of a compromised build and prevent runaway minute consumption.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-006: Artifacts not signed { #bb-006 }

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

## BB-007: SBOM not produced { #bb-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / sbom-tool / Trivy-SBOM appears.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an SBOM step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM as a build artifact.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BB-008: Credential-shaped literal in pipeline body { #bb-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Complements BB-003 (variable-name scan). BB-008 checks every string in the pipeline against the cross-provider credential-pattern catalog, catches secrets pasted into script bodies or environment blocks.

**Known false-positive modes**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, vendor example keys). Well-known vendor example tokens (``AKIAIOSFODNN7EXAMPLE``, Stripe ``sk_test_`` docs keys) are suppressed via the ``VENDOR_EXAMPLE_TOKENS`` allowlist. Defaults to LOW confidence.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the exposed credential. Move the value to a Secured Repository or Deployment Variable and reference it by name.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## BB-009: pipe: pinned by version rather than sha256 digest { #bb-009 }

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

## BB-010: Deploy step ingests pull-request artifact unverified { #bb-010 }

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

## BB-011: AWS auth uses long-lived access keys { #bb-011 }

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

## BB-012: Remote script piped to shell interpreter { #bb-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build runner.

**Known false-positive modes**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

<div class="pg-rule__rec" markdown>

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BB-013: Docker run with insecure flags (privileged/host mount) { #bb-013 }

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

## BB-014: Package install from insecure source { #bb-014 }

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

## BB-015: No vulnerability scanning step { #bb-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes common scanners including trivy, grype, snyk, pip-audit, osv-scanner, govulncheck, semgrep, checkov, and others.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-016: Self-hosted runner without ephemeral marker { #bb-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Self-hosted runners that persist between jobs leak filesystem and process state. A PR-triggered step writes to a well-known path; a subsequent deploy step on the same runner reads it. Detects `runs-on: self.hosted` without an `ephemeral` marker.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure runners to tear down between jobs. Add 'ephemeral' to `runs-on` labels or use Bitbucket's runner images that are rebuilt per-job.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BB-017: Repository token written to persistent storage { #bb-017 }

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

## BB-018: Cache key derives from attacker-controllable input { #bb-018 }

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

## BB-019: after-script references secrets { #bb-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Bitbucket's `after-script` runs unconditionally after the main `script` block (including on failure). If the `after-script` references secrets or tokens, those values may leak into build logs or artifacts even when the step fails unexpectedly. This check detects secret-like variable references in `after-script` blocks.

**Known false-positive modes**

- The detector matches any variable whose name contains ``TOKEN`` / ``SECRET`` / ``PASSWORD`` / ``KEY`` (case-insensitive). Names that are descriptive rather than secret (``CACHE_KEY``, ``SORT_KEY``, ``TOKEN_TYPE`` used as a label, ``API_KEY_NAME`` storing the *name* of the key rather than its value) trigger the regex even though they aren't credentials. The rule has no way to tell from the name alone, suppress per-step via ``--ignore-file`` when the referenced value is benign.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move secret-dependent operations into the main `script:` block. `after-script` runs even when the step fails and executes in a separate shell context, credential exposure here is harder to audit and more likely to persist in logs.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## BB-020: Full clone depth exposes complete history { #bb-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

By default Bitbucket Pipelines clone with `depth: 50`. Setting `depth: full` exposes the entire commit history, including any secrets that were committed and later removed. This check flags explicit `clone: depth: full` settings at the top level or inside individual steps.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set `clone: depth: 1` (or a small number) in pipeline or step options to limit the amount of repository history available in the build environment. Full clones make it easier to extract secrets that were committed and later removed.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-021: Package install without lockfile enforcement { #bb-021 }

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

## BB-022: Dependency update command bypasses lockfile pins { #bb-022 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Known false-positive modes**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-023: TLS / certificate verification bypass { #bb-023 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-295</span>
</div>

Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

Also flags Bitbucket's structural clone bypass, a step-level `clone: { skip-ssl-verify: true }`, which turns off certificate verification on the repository clone itself so a MITM can inject source into the build before any script runs.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-024: No SLSA provenance attestation produced { #bb-024 }

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

## BB-025: Pipeline contains indicators of malicious activity { #bb-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-506</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Specific indicators only (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, credential-dump pipes, audit-erasure commands). Does not replace BB-014 (TLS bypass) or BB-013 (Docker insecure), those are hygiene; this is evidence.

**Known false-positive modes**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat as a potential compromise. Identify the PR that added the matching step(s), rotate any credentials referenced from the pipeline's variable groups, and audit recent builds.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-026: Dangerous shell idiom (eval, sh -c variable, backtick exec) { #bb-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-95</span>
</div>

Complements BB-002 (script injection from untrusted PR context). This rule fires on intrinsically risky idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Known false-positive modes**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-027: Package install bypasses registry integrity (git / path / tarball source) { #bb-027 }

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

## BB-028: OIDC step without deployment-gated environment { #bb-028 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Pairs with IAM-008. IAM-008 verifies the cloud-side trust policy pins audience + subject; this rule verifies the Bitbucket-side workflow can't request a token without a deployment gate. Bitbucket's ``pull-requests:`` triggers from forks so OIDC under that branch is always an unbounded blast radius.

<div class="pg-rule__rec" markdown>

**Recommended action**

Every step that sets ``oidc: true`` must also declare a ``deployment:`` (production / staging / test). Bitbucket deployments enforce manual approvals, restricted variables, and audit logs that an ungated step bypasses. Steps reached through ``pull-requests:`` should never request OIDC tokens, any forked PR can drive the role assumption.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-029: image: (step or service) not pinned by sha256 digest { #bb-029 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

BB-001 / BB-009 only inspect ``pipe:`` references inside ``script:`` lists. Step ``image:`` directives and ``definitions.services.<name>.image:`` define the runtime container the build executes inside (and the auxiliary containers the step talks to over the loopback network). Both surfaces ship code into the build context, a compromised service image (the postgres container, the selenium-grid container, …) can exfiltrate every secret the step touches just as easily as the step image itself. This rule reuses ``_primitives.image_pinning.classify`` so the floating-tag semantics match GHA-001 / GL-001 / JF-009 / ADO-009 / CC-003 / K8S-001.

**Known false-positive modes**

- Bitbucket-vendored helper images (``atlassian/`` namespace) are still treated as third-party, the registry can move the tag. Pin them too rather than suppressing the rule globally.

<div class="pg-rule__rec" markdown>

**Recommended action**

Resolve every ``image:`` reference to its current digest (``docker buildx imagetools inspect <ref>`` or ``crane digest <ref>``) and pin via ``image: name@sha256:<digest>``. Floating tags (``:latest``, ``:3``, no tag) silently swap the runtime image, the build's reproducibility invariant is broken and a registry-side compromise lands inside CI without any local change.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-030: npm install without registry-signature verification step { #bb-030 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Fires once per ``bitbucket-pipelines.yml`` when:

1. Some step's ``script:`` runs an npm or pnpm install verb (``npm ci``, ``npm install``, ``npm i``, ``pnpm install``, ``pnpm i``, ``pnpm ci``);
2. No step anywhere in the file runs ``npm audit signatures`` or ``pnpm audit signatures``.

Yarn / Bun-only pipelines pass silently because the ``audit signatures`` primitive is npm-CLI-specific (Yarn Berry's ``yarn npm audit`` does not yet verify registry trusted-publisher records). Pairs with the per-package lockfile rules NPM-002 / NPM-006.

**Known false-positive modes**

- Pipelines that build against a private registry without trusted-publisher records (legacy Artifactory, self-hosted Verdaccio without sigstore) cannot run ``audit signatures`` meaningfully. Suppress on the specific pipeline with a rationale that names the private registry.

**Seen in the wild**

- Shai-Hulud npm worm (2026) / TanStack / axios patch-release compromises rode the gap between lockfile-pinned integrity and registry-signed-publisher provenance.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an ``npm audit signatures`` step (or ``pnpm audit signatures``) after the install. Lockfile pinning only guarantees the bytes installed match the lockfile; ``audit signatures`` is what verifies those bytes were signed by the registry's trusted publisher for the package. Run it as a separate script line after ``npm ci`` and before any code from ``node_modules/`` executes.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BB-031: pip install without `--require-hashes` verification { #bb-031 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Fires once per ``bitbucket-pipelines.yml`` when some step's ``script:`` runs a real ``pip install`` (excluding the tooling-bootstrap allowlist) AND no step in the file uses ``--require-hashes`` or a hash-pinning manager (``uv sync`` / ``poetry install`` / ``pipenv install --deploy``).

**Known false-positive modes**

- Pipelines that build against a private index without SHA-256 hash records cannot run ``--require-hashes`` meaningfully. Suppress with a rationale that names the private index.

**Seen in the wild**

- PyPI maintainer-account compromises (ctx 2022, requests-darwin-lite 2024) shipped malicious sdists / wheels under existing version pins.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every dependency with a SHA-256 hash and install with ``pip install -r requirements.txt --require-hashes``, or migrate to a manager that hash-pins by default: ``uv sync``, ``poetry install``, ``pipenv install --deploy``. Hash-pinned install is the PyPI equivalent of npm's lockfile-integrity guarantee.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-032: Secret-named variable echoed / printed in a script block { #bb-032 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-532</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Scans every ``script:`` line across all pipeline steps. Variable names matching common secret patterns (PASSWORD, TOKEN, API_KEY, SECRET, CREDENTIAL) trigger the rule when they appear as arguments to ``echo``, ``printf``, ``cat``, or ``tee``. Also fires on ``printenv`` / ``env`` (full environment dump) and ``set -x`` with secret-named variables in scope.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't print secret values in pipeline scripts. Bitbucket's log masking covers secured variables, but only when the full value appears as a contiguous string. Base64-encoded, URL-encoded, or partial substrings bypass the mask. Log a boolean instead (``[ -n "$X" ] && echo set || echo unset``). Avoid ``set -x`` when secret-bound variables are in scope.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BB-033: IaC apply on a pull-request pipeline { #bb-033 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

Fires when a step in the `pull-requests:` section runs an IaC apply command (`terraform apply`, `cloudformation deploy`, `cdk deploy`, `pulumi up`, `sam deploy`, `terragrunt apply`) in its `script:` or `after-script:`. Steps under `branches:`, `default:`, `custom:`, and `tags:` are out of scope, only the pull-request-triggered section runs untrusted branch content. This is the Bitbucket analog of GL-041 / GHA-117.

**Known false-positive modes**

- A pipeline that runs `apply` only against a short-lived, fully-sandboxed review environment with no production-adjacent credentials. Even then the apply executes unreviewed IaC on the runner; prefer `plan` on PRs. Suppress with a rationale naming the sandbox scope.

<div class="pg-rule__rec" markdown>

**Recommended action**

Never run `terraform apply` (or `cloudformation deploy` / `cdk deploy` / `pulumi up` / `sam deploy`) in a step under the `pull-requests:` section. That pipeline runs the PR branch's IaC, so an `external` data source, a `local-exec` provisioner, or a hijacked provider executes arbitrary code on the runner with whatever cloud credentials (often an OIDC identity) the apply uses, before the change is reviewed or merged. On pull requests run a read-only `plan`; move the `apply` into the `branches:` section for your default branch (or a `custom:` manual pipeline) gated by a `deployment:` environment so it runs against merged, reviewed code.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BB-034: Production deployment on a pull-request pipeline { #bb-034 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--esf">ESF-C-ENV-SEP</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Fires when a step under the `pull-requests:` section declares a production-tier `deployment:` environment (a name matching `production` / `prod`). The PR branch's code reaches production before it is reviewed or merged, and the production deployment's scoped variables are exposed to PR-controlled pipeline steps. Steps under `branches:` / `default:` / `custom:` / `tags:` are out of scope, and per-PR preview, `test`, or `staging` environments don't fire, only a production-tier name on the pull-request-triggered section.

**Known false-positive modes**

- A repo that intentionally publishes a per-PR preview deployment to an environment it happens to have named `production`. Rename it to a preview / review tier, or suppress with a rationale. A production environment configured under a custom name (not `production` / `prod`) can't be recognized from the YAML alone and won't fire.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't bind a `pull-requests:` step to a production `deployment:` environment. A pull-request pipeline runs the PR branch's code, so this ships unreviewed (and on fork PRs, untrusted) changes straight to production with the production environment's scoped credentials, before any reviewer or merge gate. On pull requests deploy only to an ephemeral preview or `test` environment; move the production `deployment:` into the `branches:` section for your default branch (or a manual `custom:` pipeline) so it runs against merged, reviewed code with the environment's required reviewers enforced.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-035: ML model loaded with trust_remote_code (code execution) { #bb-035 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on ``trust_remote_code=True`` / ``--trust-remote-code`` in a step's ``script``. The transformers / huggingface_hub loader executes the model repo's own Python at load time, so an untrusted or unpinned model is arbitrary code execution in the pipeline with the step's credentials in scope.

<div class="pg-rule__rec" markdown>

**Recommended action**

Load models with ``trust_remote_code=False`` (the library default). If a model genuinely needs custom code, vet it and pin an exact revision (a commit SHA, not a tag or branch), run the load in a step scoped to no production deployment credentials, and prefer safetensors weights over pickle.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-036: Untrusted PR/branch context reaches an agentic AI CLI (prompt injection) { #bb-036 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-77</span>
</div>

The AI analog of BB-002 (script injection). Fires when a ``script:`` line invokes an agentic CLI (claude / gemini / cursor-agent / aider / openhands / goose / ``q chat``) AND attacker-controllable Bitbucket context reaches it, either a predefined untrusted variable (`$BITBUCKET_BRANCH` / `$BITBUCKET_TAG` / `$BITBUCKET_PR_*`) interpolated directly, or a local shell variable assigned from one earlier in the step. Unlike a shell, an LLM ingests a quoted value as prompt text, so the BB-002 mitigation (quote the value) does not apply, which is why this is separate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Do not place attacker-controllable context (a PR's branch / tag name or `$BITBUCKET_PR_*` metadata) in an agentic CLI's prompt. Quoting does NOT sanitize a prompt the way it does a shell command, the model still reads the value. If the agent must see PR content, run it on a step with no deployment / repository secrets in scope and no tool / shell access, and treat its output as untrusted.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BB-037: Unsafe deserialization of a fetched artifact (pickle RCE) { #bb-037 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-502</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires per ``script:`` step in two shapes (shared with GHA-122 / GL-047 via ``_primitives/unsafe_deser``): an explicit unsafe opt-in (``weights_only=False`` / ``allow_pickle=True``) always; or a remote fetch (curl / wget / ``hf_hub_download`` / ``snapshot_download`` / ``huggingface-cli download`` / ``requests``) alongside a pickle-backed loader (``torch.load`` / ``pickle.load(s)`` / ``joblib.load``) with no safe path (``weights_only=True`` or safetensors) in the same step. A bare local load with no fetch does not fire.

<div class="pg-rule__rec" markdown>

**Recommended action**

Load models / artifacts through a non-executing format: prefer ``safetensors``, or pass ``weights_only=True`` to ``torch.load`` (default in PyTorch 2.6+). Never ``pickle.load`` / ``joblib.load`` / ``numpy.load(allow_pickle=True)`` a file fetched at build time, and pin + checksum any model you must deserialize.

</div>

</div>

---

## Adding a new Bitbucket Pipelines check

1. Create a new module at
   `pipeline_check/core/checks/bitbucket/rules/bbNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
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
