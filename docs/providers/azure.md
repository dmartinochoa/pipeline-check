# Azure DevOps Pipelines provider

Parses an `azure-pipelines.yml` from disk, no network calls, no ADO
personal access token.

## Producer workflow

```bash
# --azure-path is auto-detected when azure-pipelines.yml is present at cwd;
# the CLI announces the pick on stderr.
pipeline_check --pipeline azure

# …or pass it explicitly.
pipeline_check --pipeline azure --azure-path azure-pipelines.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Shape coverage

The walker handles every layout ADO supports:

- Flat single-job pipeline, top-level `steps:`
- Single-stage multi-job, top-level `jobs:`
- Multi-stage, `stages: → jobs: → steps:`
- Deployment jobs, steps under
  `strategy.{runOnce|rolling|canary}.{preDeploy|deploy|routeTraffic|postRouteTraffic}.steps`
  and `strategy.*.on.{success|failure}.steps`.

## What it covers

31 checks · 11 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [ADO-001](#ado-001) | Task reference not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ADO-002](#ado-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ADO-003](#ado-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ADO-004](#ado-004) | Deployment job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ADO-005](#ado-005) | Container image not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ADO-006](#ado-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ADO-007](#ado-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ADO-008](#ado-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ADO-009](#ado-009) | Container image pinned by tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [ADO-010](#ado-010) | Cross-pipeline `download:` ingestion unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ADO-011](#ado-011) | `template: <local-path>` on PR-validated pipeline | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ADO-012](#ado-012) | Cache@2 key derives from $(System.PullRequest.*) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ADO-013](#ado-013) | Self-hosted pool without explicit ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ADO-014](#ado-014) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ADO-015](#ado-015) | Job has no `timeoutInMinutes`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ADO-016](#ado-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ADO-017](#ado-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ADO-018](#ado-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ADO-019](#ado-019) | `extends:` template on PR-validated pipeline points to local path | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ADO-020](#ado-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ADO-021](#ado-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ADO-022](#ado-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ADO-023](#ado-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ADO-024](#ado-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ADO-025](#ado-025) | Cross-repo template not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ADO-026](#ado-026) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ADO-027](#ado-027) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ADO-028](#ado-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ADO-029](#ado-029) | Service-connection-using job without environment or branch gate | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ADO-030](#ado-030) | pool interpolates attacker-controllable value | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [ADO-031](#ado-031) | Secret variable echoed / printed in a script step | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## ADO-001: Task reference not pinned to specific version { #ado-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Floating-major task references (`@1`, `@2`) can roll forward silently when the task publisher ships a breaking or malicious update. Pass when every `task:` reference carries a two- or three-segment semver.

<div class="pg-rule__rec" markdown>

**Recommended action**

Reference tasks by a full semver (`DownloadSecureFile@1.2.3`) or extension-published-version. Track task updates explicitly via Azure DevOps extension settings rather than letting `@1` drift.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ADO-002: Script injection via attacker-controllable context { #ado-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

`$(Build.SourceBranch*)`, `$(Build.SourceVersionMessage)`, and `$(System.PullRequest.*)` are populated from SCM event metadata the attacker controls. Inline interpolation into a script body executes crafted content.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pass these values through an intermediate pipeline variable declared with `readonly: true`, and reference that variable through an environment variable rather than `$(...)` macro interpolation. ADO expands `$(…)` before shell quoting, so inline use is never safe.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ADO-003: Variables contain literal secret values { #ado-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Scans `variables:` in both the mapping form (`{KEY: VAL}`) and the list form (`[{name: X, value: Y}]`) that ADO supports. AWS keys are detected by value shape regardless of variable name.

<div class="pg-rule__rec" markdown>

**Recommended action**

Store secrets in an Azure Key Vault or a Library variable group with the secret flag set; reference them via `$(SECRET_NAME)` at runtime. For cloud access prefer Azure workload identity federation.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ADO-004: Deployment job missing environment binding { #ado-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--esf">ESF-C-ENV-SEP</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Without an `environment:` binding, ADO cannot enforce approvals, checks, or deployment history against a named resource. Every `deployment:` job should bind one.

**Known false-positive modes**

- The deploy-name regex (``deploy`` / ``release`` / ``publish`` / ``promote``) flags jobs whose names include those tokens for non-deploy reasons (e.g. ``release-notes-build`` that only generates a changelog). The deploy-command regex similarly fires on test pipelines that exercise ``kubectl apply --dry-run`` or ``helm template`` for validation. Suppress those jobs per-resource via ``--ignore-file`` once you've verified they don't actually mutate any environment.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `environment: <name>` to every `deployment:` job. Configure approvals, required branches, and business-hours checks on the matching Environment in the ADO UI.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ADO-005: Container image not pinned to specific version { #ado-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-TRUSTED-REG</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Container images can be declared at `resources.containers[].image` or `job.container` (string or `{image:}`). Floating / untagged refs let the publisher swap the image contents.

<div class="pg-rule__rec" markdown>

**Recommended action**

Reference images by `@sha256:<digest>` or at minimum a full immutable version tag. Avoid `:latest` and untagged refs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ADO-006: Artifacts not signed { #ado-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Passes when cosign / sigstore / slsa-* / notation-sign appears anywhere in the pipeline text.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a task that runs `cosign sign` or `notation sign`, Azure Pipelines' workload identity federation enables keyless signing. Publish the signature to the artifact feed and verify it at deploy time.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ADO-007: SBOM not produced { #ado-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an SBOM step, `microsoft/sbom-tool`, `syft . -o cyclonedx-json`, or `anchore/sbom-action`. Publish the SBOM as a pipeline artifact so downstream consumers can ingest it.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ADO-008: Credential-shaped literal in pipeline body { #ado-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Complements ADO-003 (which looks at `variables:` keys). ADO-008 scans every string in the pipeline against the cross-provider credential-pattern catalog.

**Known false-positive modes**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, vendor example keys). Well-known vendor example tokens (``AKIAIOSFODNN7EXAMPLE``, Stripe ``sk_test_`` docs keys) are suppressed via the ``VENDOR_EXAMPLE_TOKENS`` allowlist. Defaults to LOW confidence.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the exposed credential. Move the value to Azure Key Vault or a secret variable group and reference it via `$(SECRET_NAME)`.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## ADO-009: Container image pinned by tag rather than sha256 digest { #ado-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

ADO-005 fails floating tags at HIGH; ADO-009 is the stricter tier. Even immutable-looking version tags can be repointed by registry operators.

<div class="pg-rule__rec" markdown>

**Recommended action**

Resolve each image to its current digest and replace the tag with `@sha256:<digest>`. Schedule regular digest bumps via Renovate or a scheduled pipeline.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ADO-010: Cross-pipeline `download:` ingestion unverified { #ado-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

`resources.pipelines:` declares an upstream pipeline; a `download: <name>` step pulls its artifacts. If the upstream accepts PR validation, the artifact may have been built by PR-controlled code.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a verification step before consuming the artifact: `cosign verify-attestation`, `sha256sum -c`, or `gpg --verify` against a manifest the producing pipeline signed.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ADO-011: `template: <local-path>` on PR-validated pipeline { #ado-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

`template: <relative-path>` includes another YAML from the CURRENT repo. On PR validation builds, the repo content is the PR branch, letting the PR author swap the template body. Cross-repo templates (`template: foo.yml@my-repo`) are version-pinned and not affected.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the template into a separate, branch-protected repository and reference it via `template: foo.yml@<repo-resource>` with a pinned `ref:` on the resource. That way the template content is fixed at PR creation time and can't be modified from the PR branch.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ADO-012: Cache@2 key derives from $(System.PullRequest.*) { #ado-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

`Cache@2` (and older `CacheBeta@1`) restore by key. A key including PR-controlled variables on PR-validated pipelines lets a PR seed a poisoned cache entry that a later default-branch pipeline restores.

<div class="pg-rule__rec" markdown>

**Recommended action**

Build the cache key from values the PR can't control: `$(Agent.OS)`, lockfile hashes, the pipeline name. Never reference `$(System.PullRequest.*)` or `$(Build.SourceBranch*)` from a cache key namespace.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ADO-013: Self-hosted pool without explicit ephemeral marker { #ado-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

`pool: { name: <agent-pool> }` (or the bare string form `pool: <name>`) targets a self-hosted agent pool. Without an explicit ephemeral arrangement, agents reuse state across jobs. Microsoft-hosted pools (`vmImage:` or the `Azure Pipelines` / `Default` names) are skipped.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure the agent pool with autoscaling + ephemeral agents (the Azure VM Scale Set agent), and add `demands: [ephemeral -equals true]` on the pool block so this check can verify it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ADO-014: AWS auth uses long-lived access keys { #ado-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-TOKEN-HYGIENE</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values in pipeline variables or task inputs can't be rotated on a fine-grained schedule. Prefer OIDC or vault-based credential injection for cross-cloud access.

**Known false-positive modes**

- The check only flags literal AKIA-shaped *values*, never variable names. The residual false positive is a literal AKIA-shaped value that is actually a deactivated or test key (a documentation sample, or a deliberately revoked credential left in place). The rule can't tell a live key from a dead one. Suppress per-pipeline via ``--ignore-file`` once you've confirmed the value is deactivated or non-production.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use workload identity federation or an Azure Key Vault task to inject short-lived AWS credentials at runtime. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from pipeline variables and task parameters.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ADO-015: Job has no `timeoutInMinutes`, unbounded build { #ado-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-TIMEOUT</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Without `timeoutInMinutes`, the job runs until Azure's 60-minute default kills it. Explicit timeouts cap blast radius and the window during which a compromised step has access to service connections.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `timeoutInMinutes:` to each job, sized to the 95th percentile of historical runtime plus margin. Azure's default is 60 minutes, an explicitly shorter value limits blast radius and agent cost.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ADO-016: Remote script piped to shell interpreter { #ado-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build agent.

**Known false-positive modes**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

<div class="pg-rule__rec" markdown>

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ADO-017: Docker run with insecure flags (privileged/host mount) { #ado-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a pipeline give the container full access to the build agent, enabling container escape and lateral movement.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ADO-018: Package install from insecure source { #ado-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ADO-019: `extends:` template on PR-validated pipeline points to local path { #ado-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

`extends: template: <local-file>` includes another YAML from the CURRENT repo. On PR validation builds, the repo content is the PR branch, letting the PR author swap the template body and inject arbitrary pipeline logic. Cross-repo templates (`template: foo.yml@my-repo`) are version-pinned and not affected.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin the extends template to a protected repository ref (`template@ref`). Local templates in PR-validated pipelines can be poisoned by the PR author.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ADO-020: No vulnerability scanning step { #ado-020 }

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

## ADO-021: Package install without lockfile enforcement { #ado-021 }

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

## ADO-022: Dependency update command bypasses lockfile pins { #ado-022 }

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

## ADO-023: TLS / certificate verification bypass { #ado-023 }

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

## ADO-024: No SLSA provenance attestation produced { #ado-024 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SBOM</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

On Azure Pipelines the common pattern is a ``Bash@3`` task invoking ``cosign attest --yes --predicate=provenance.json $(image)``. The native Microsoft SBOM tool emits ``_manifest/spdx_2.2/manifest.spdx.json`` for SBOM but does not produce provenance on its own.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a task that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or Microsoft's ``sbom-tool`` in attestation mode. ADO-006 covers signing; this rule covers the in-toto statement SLSA Build L3 additionally requires.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ADO-025: Cross-repo template not pinned to commit SHA { #ado-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Azure Pipelines resolves ``template: build.yml@tools`` against the ``tools`` repo resource's ``ref:`` field. When that ref is ``refs/heads/main`` (or missing, which defaults to the pipeline's default branch), a push to the callee repo changes what your pipeline runs on the next invocation.

<div class="pg-rule__rec" markdown>

**Recommended action**

On every ``resources.repositories`` entry referenced from a ``template: ...@repo-alias`` directive, set ``ref: refs/tags/<sha>`` or the bare 40-char commit SHA, never a branch or floating tag. A moved branch/tag swaps the template body without changing your pipeline file.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ADO-026: Pipeline contains indicators of malicious activity { #ado-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-506</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

ADO pipelines can run arbitrary shell via ``bash`` / ``script`` / ``powershell`` tasks. This rule scans every string value for known-bad patterns (reverse shells, base64-decoded execution, miner binaries, exfil channels). Orthogonal to ADO-016/ADO-017/ADO-023.

**Known false-positive modes**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat as a potential compromise. Identify the PR/branch that added the matching task(s), rotate any Service Connections the pipeline can reach, and audit Pipeline run logs for outbound traffic to the matched hosts.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ADO-027: Dangerous shell idiom (eval, sh -c variable, backtick exec) { #ado-027 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-95</span>
</div>

Complements ADO-002 (script injection from untrusted PR context). Fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Known false-positive modes**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate any value that must feed a dynamic command at the boundary.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ADO-028: Package install bypasses registry integrity (git / path / tarball source) { #ado-028 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Complements ADO-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin git dependencies to a commit SHA. Publish private packages to an internal registry (Azure Artifacts) instead of installing from a filesystem path or tarball URL.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ADO-029: Service-connection-using job without environment or branch gate { #ado-029 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Pairs with IAM-008 (the AWS-side OIDC rule). Azure's equivalent trust path runs through service connections that map to Azure AD federated identity credentials. The ADO-side gate is either a deployment + environment or a branch-pinned condition; this rule flags jobs that have neither.

<div class="pg-rule__rec" markdown>

**Recommended action**

Every job that consumes an Azure service connection (via ``AzureCLI@``, ``AzurePowerShell@``, ``AzureKeyVault@``, ``AzureWebApp@``, etc.) must either be a ``deployment:`` job bound to an ``environment:`` (which carries approval checks and audit) or carry a ``condition:`` that pins ``Build.SourceBranch`` to a protected ref. Without one of those gates, any branch push drives the federated assume-role on Azure AD.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ADO-030: pool interpolates attacker-controllable value { #ado-030 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

ADO-013 catches self-hosted pools that aren't ephemeral; this rule catches the upstream targeting choice. When ``pool:`` (or its ``name`` / ``demands`` sub-fields) is computed from an attacker-controllable expression, whoever triggers the pipeline picks where the job runs, including any agent pool the project exposes (``deploy-prod``, ``signer``, ``hsm`` …). Two attacker surfaces are flagged: runtime SCM macros (``$(Build.SourceBranchName)``, ``$(System.PullRequest.SourceBranch)``, …) and caller-controlled template parameters (``${{ parameters.X }}``, the value comes from whoever queued the run). The rule walks all three pool shapes, string scalar, dict ``{ name, vmImage, demands }``, and the ``demands`` list form.

**Known false-positive modes**

- Pipelines that intentionally select agent pools via a vetted ``variables:`` block (``POOL_NAME: prod-pool``) are out of scope, pipeline variables defined in the same file are author-controlled. Static custom names are not flagged. The rule only matches the curated runtime-macro catalog and the literal ``${{ parameters.X }}`` template-parameter shape.

<div class="pg-rule__rec" markdown>

**Recommended action**

Hard-code ``pool:`` to a specific agent pool name (or ``vmImage:`` for Microsoft-hosted). If pool selection has to be parameterized, validate the candidate against an explicit allowlist before the job runs (e.g. a ``condition:`` guard against a vetted set), and never inline ``$(Build.*)`` / ``$(System.PullRequest.*)`` / ``${{ parameters.X }}`` values as the pool name or as a demand.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ADO-031: Secret variable echoed / printed in a script step { #ado-031 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-532</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Scans ``script:``, ``bash:``, ``powershell:``, and ``pwsh:`` step bodies. Azure template expressions ``$(VAR)`` are matched alongside POSIX ``$VAR`` / ``${VAR}`` forms.

Variables declared with ``issecret: true`` in the pipeline YAML are treated as known secrets (highest confidence). Variables whose names match common secret patterns (PASSWORD, TOKEN, API_KEY, etc.) are flagged heuristically.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't print secret values in pipeline scripts. Azure Pipelines masks variables marked ``issecret=true`` in logs, but only exact-match substrings. Encoded, truncated, or derived forms bypass the mask, and raw API log downloads are not masked. Log a boolean instead. Avoid ``set -x`` when secret-bound variables are in scope.

</div>

</div>

---

## Adding a new Azure DevOps Pipelines check

1. Create a new module at
   `pipeline_check/core/checks/azure/rules/adoNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/azure/ADO-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py azure
   ```
