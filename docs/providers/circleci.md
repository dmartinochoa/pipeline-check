# CircleCI provider

Parses `.circleci/config.yml` on disk, no CircleCI API token, no
runner install.

## Producer workflow

```bash
# --circleci-path is auto-detected when .circleci/config.yml exists at cwd.
pipeline_check --pipeline circleci

# …or pass it explicitly.
pipeline_check --pipeline circleci --circleci-path .circleci/config.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### CircleCI-specific checks

Several checks target CircleCI concepts that have no direct analogue
in other providers:

- **CC-001**, orb version pinning (`@volatile`, `@1` → `@5.1.0`)
- **CC-009**, approval gate via `type: approval` predecessor job
- **CC-012**, dynamic config generation via `setup: true`
- **CC-019**, `add_ssh_keys` fingerprint restriction

## What it covers

36 checks · 10 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [CC-001](#cc-001) | Orb not pinned to exact semver | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [CC-002](#cc-002) | Script injection via untrusted environment variable | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CC-003](#cc-003) | Docker image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CC-004](#cc-004) | Secret-like environment variable not managed via context | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-005](#cc-005) | AWS auth uses long-lived access keys in environment block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [CC-006](#cc-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-007](#cc-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-008](#cc-008) | Credential-shaped literal in config body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [CC-009](#cc-009) | Deploy job missing manual approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-010](#cc-010) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-011](#cc-011) | No store_test_results step (test results not archived) | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [CC-012](#cc-012) | Dynamic config via `setup: true` enables code injection | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-013](#cc-013) | Deploy job in workflow has no branch filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-014](#cc-014) | Job missing `resource_class` declaration | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-015](#cc-015) | No `no_output_timeout` configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [CC-016](#cc-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [CC-017](#cc-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [CC-018](#cc-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [CC-019](#cc-019) | `add_ssh_keys` without fingerprint restriction | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CC-020](#cc-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-021](#cc-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [CC-022](#cc-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [CC-023](#cc-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [CC-024](#cc-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-025](#cc-025) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-026](#cc-026) | Config contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [CC-027](#cc-027) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CC-028](#cc-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-029](#cc-029) | Machine executor image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CC-030](#cc-030) | Workflow job uses context without branch filter or approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-031](#cc-031) | OIDC role assumption without branch filter or approval gate | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CC-032](#cc-032) | Secret-named variable echoed / printed in a run step | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CC-033](#cc-033) | Job disables Go module checksum / sum-db verification | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CC-034](#cc-034) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CC-035](#cc-035) | AI model pulled without a pinned revision | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CC-036](#cc-036) | Unsafe deserialization of a fetched artifact (pickle RCE) | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## CC-001: Orb not pinned to exact semver { #cc-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Orb references in the `orbs:` block must include an `@x.y.z` suffix to lock a specific version. References without `@`, with `@volatile`, or with only a major (`@1`) or major.minor (`@5.1`) version float and can silently pull in malicious updates.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every orb to an exact semver version (`circleci/node@5.1.0`). Floating references like `@volatile`, `@1`, or bare names without `@` resolve to whatever is latest at build time, allowing a compromised orb update to execute in the pipeline.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CC-002: Script injection via untrusted environment variable { #cc-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

CircleCI exposes environment variables like `$CIRCLE_BRANCH`, `$CIRCLE_TAG`, and `$CIRCLE_PR_NUMBER` that are controlled by the event source (branch name, tag, PR). Interpolating them unquoted into `run:` commands allows shell injection via specially crafted branch or tag names. The same applies to the native `<< pipeline.git.branch >>` / `<< pipeline.git.tag >>` interpolations, which CircleCI splices into the command at config-compile time straight from the (attacker-named) ref. `<< pipeline.parameters.* >>` is the safe alternative: typed and set by the triggering workflow, not by a ref name.

<div class="pg-rule__rec" markdown>

**Recommended action**

Do not interpolate attacker-controllable environment variables (CIRCLE_BRANCH, CIRCLE_TAG, CIRCLE_PR_NUMBER, etc.) directly into shell commands. Pass them through an intermediate variable and quote them, or use CircleCI pipeline parameters instead.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CC-003: Docker image not pinned by digest { #cc-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Docker images referenced in `docker:` blocks under jobs or executors must include an `@sha256:...` digest suffix. Tag-only references (`:latest`, `:18`) are mutable and can be replaced at any time by whoever controls the upstream registry.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every Docker image to its sha256 digest: `cimg/node:18@sha256:abc123...`. Tags like `:latest` or `:18` are mutable, a registry compromise or upstream push silently replaces the image content.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-004: Secret-like environment variable not managed via context { #cc-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Jobs that declare environment variables with secret-looking names (containing PASSWORD, TOKEN, SECRET, or API_KEY) in inline `environment:` blocks bypass CircleCI's context restrictions, security groups, OIDC claims, and audit logs are only enforced when secrets live in contexts.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move secret-like variables (PASSWORD, TOKEN, SECRET, API_KEY) into a CircleCI context and reference the context in the workflow job configuration. Contexts support security groups and audit logging that inline `environment:` blocks lack.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-005: AWS auth uses long-lived access keys in environment block { #cc-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-TOKEN-HYGIENE</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Long-lived AWS access keys declared directly in a job's `environment:` block are visible to anyone who can read the config. They cannot be rotated automatically and remain valid until manually revoked. OIDC-based federation yields short-lived credentials per build.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the job `environment:` block. Use CircleCI's OIDC token with `aws-cli/setup` orb's role-based auth, or store credentials in a context with security group restrictions.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-006: Artifacts not signed (no cosign/sigstore step) { #cc-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-framework, and notation-sign as signing tools.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a signing step to the pipeline, e.g. install cosign and run `cosign sign`, or use the `sigstore` CLI. Publish the signature alongside the artifact and verify it at consumption time.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-007: SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) { #cc-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognizes CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an SBOM generation step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the build artifacts so consumers can ingest it into their vulnerability management pipeline.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CC-008: Credential-shaped literal in config body { #cc-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Every string in the config is scanned against a set of credential patterns (AWS access keys, GitHub tokens, Slack tokens, JWTs, Stripe, Google, Anthropic, etc.). A match means a secret was pasted into YAML, the value is visible in every fork and every build log and must be treated as compromised.

**Known false-positive modes**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, vendor example keys). Well-known vendor example tokens (``AKIAIOSFODNN7EXAMPLE``, Stripe ``sk_test_`` docs keys) are suppressed via the ``VENDOR_EXAMPLE_TOKENS`` allowlist. Defaults to LOW confidence.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the exposed credential immediately. Move the value to a CircleCI project environment variable or a context and reference it via the variable name. For cloud access, prefer OIDC federation over long-lived keys.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-009: Deploy job missing manual approval gate { #cc-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--esf">ESF-C-ENV-SEP</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

In CircleCI, manual approval is implemented by adding a job with `type: approval` to the workflow and making the deploy job require it. Without this gate, any push to the triggering branch deploys immediately with no human review.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a `type: approval` job that precedes the deploy job in the workflow, and list it in the deploy job's `requires:`. This ensures a human must click Approve in the CircleCI UI before production changes roll out.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-010: Self-hosted runner without ephemeral marker { #cc-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Self-hosted runners that persist between jobs leak filesystem and process state. A PR-triggered job writes to `/tmp`; a subsequent prod-deploy job on the same runner reads it. The check looks for `resource_class` values containing 'self-hosted', if found, it checks for 'ephemeral' in the value.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure self-hosted runners to tear down between jobs. Use a `resource_class` value that includes an ephemeral marker, or use CircleCI's machine executor with runner auto-scaling so each job gets a fresh environment.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CC-011: No store_test_results step (test results not archived) { #cc-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-C-AUDIT</span> <span class="pg-tag pg-tag--cwe">CWE-532</span>
</div>

Without `store_test_results`, test output is only available in the raw build log. Archiving test results enables CircleCI's test insights, timing-based splitting, and provides an audit trail that links each build to its test outcomes.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a `store_test_results` step to jobs that run tests. This archives test results in CircleCI for traceability, trend analysis, and debugging flaky tests.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-012: Dynamic config via `setup: true` enables code injection { #cc-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

When `setup: true` is set at the top level, the config becomes a setup workflow. It generates the real pipeline config dynamically (typically via the `circleci/continuation` orb). An attacker who controls the setup job (e.g. via a malicious PR in a fork) can inject arbitrary config for all subsequent jobs, including deploy steps with production secrets.

<div class="pg-rule__rec" markdown>

**Recommended action**

If `setup: true` is required, restrict the setup job to a trusted branch filter and audit the generated config carefully. Ensure the continuation orb's `configuration_path` points to a checked-in file, not a dynamically generated one that could be influenced by PR content.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-013: Deploy job in workflow has no branch filter { #cc-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Without branch filters, a deploy job triggers on every branch push, including feature branches and forks. Restricting sensitive jobs to specific branches limits the blast radius of a compromised commit.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `filters.branches.only` to deploy-like workflow jobs so they only run on protected branches (e.g. main, release/*).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-014: Job missing `resource_class` declaration { #cc-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Without an explicit `resource_class`, CircleCI assigns a default executor. Declaring the class documents the expected scope and prevents accidental use of larger (or self-hosted) executors that may have elevated privileges.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `resource_class:` to every job to explicitly control the executor size and capabilities. Use the smallest class that satisfies build requirements.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-015: No `no_output_timeout` configured { #cc-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-TIMEOUT</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Without `no_output_timeout`, a hung step can consume executor time indefinitely. Explicit timeouts cap cost and the window during which a compromised step has access to secrets and the build environment.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `no_output_timeout:` to long-running run steps, or set it at the job level. A reasonable default is 10-30 minutes. CircleCI's default of 10 minutes may be too long for some pipelines and absent for others.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CC-016: Remote script piped to shell interpreter { #cc-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a CircleCI config. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Known false-positive modes**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

<div class="pg-rule__rec" markdown>

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CC-017: Docker run with insecure flags (privileged/host mount) { #cc-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a CircleCI config give the container full access to the runner, enabling container escape and lateral movement.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CC-018: Package install from insecure source { #cc-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a CircleCI config. These patterns allow man-in-the-middle injection of malicious packages.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CC-019: `add_ssh_keys` without fingerprint restriction { #cc-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-C-SECRET-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

A bare `- add_ssh_keys` step (without `fingerprints:`) loads every SSH key configured on the project into the job. This violates least privilege, the job gains access to keys it does not need, increasing the blast radius if the job is compromised.

<div class="pg-rule__rec" markdown>

**Recommended action**

Always specify `fingerprints:` when using `add_ssh_keys` to restrict which SSH keys are loaded into the job. A bare `add_ssh_keys` step loads ALL project SSH keys.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-020: No vulnerability scanning step { #cc-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-021: Package install without lockfile enforcement { #cc-021 }

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

## CC-022: Dependency update command bypasses lockfile pins { #cc-022 }

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

## CC-023: TLS / certificate verification bypass { #cc-023 }

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

## CC-024: No SLSA provenance attestation produced { #cc-024 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Signing (``cosign sign``) binds identity to bytes; attestation (``cosign attest``) binds a structured claim about *how* the artifact was built. SLSA verifiers check the latter so consumers can enforce builder/source/parameter policies.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``run: cosign attest`` command against a ``provenance.intoto.jsonl`` statement, or use the ``circleci/attestation`` orb. CC-006 covers signing; this rule covers the build-provenance step SLSA Build L3 requires.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-025: Cache key derives from attacker-controllable input { #cc-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

CircleCI's ``restore_cache`` falls through each listed key until it finds a hit. When one of those keys is derived from ``CIRCLE_BRANCH``, ``CIRCLE_TAG``, or ``CIRCLE_PR_*``, values an attacker can set by opening a PR, the attacker can plant a cache entry that a protected job later uses. Uses checksum-of-lockfile or a static version label instead.

<div class="pg-rule__rec" markdown>

**Recommended action**

Derive ``save_cache`` and ``restore_cache`` keys from values the attacker can't control, the lockfile checksum (``{{ checksum "package-lock.json" }}``) and the build variant, not ``{{ .Branch }}`` or ``${CIRCLE_PR_NUMBER}``. A PR-scoped branch can seed a poisoned cache entry that a later main-branch run restores as trusted.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CC-026: Config contains indicators of malicious activity { #cc-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-506</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Fires on concrete indicators only (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, ``webhook.site`` callbacks, credential-dump pipes, history-erasure).

**Known false-positive modes**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat as a potential compromise. Identify the PR that added the matching step(s), rotate any contexts/env vars the pipeline can reach, and audit recent CircleCI runs for outbound traffic to the matched hosts.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CC-027: Dangerous shell idiom (eval, sh -c variable, backtick exec) { #cc-027 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-95</span>
</div>

Complements CC-002 (script injection from untrusted context). Fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Known false-positive modes**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-028: Package install bypasses registry integrity (git / path / tarball source) { #cc-028 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Complements CC-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin git dependencies to a commit SHA. Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CC-029: Machine executor image not pinned { #cc-029 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

CC-003 covers Docker images declared under ``docker:`` blocks. It does not reach the machine executor, where the image is on ``machine.image``. A rolling tag (``current``, ``edge``, ``default``) pulls a fresh image whenever CircleCI publishes one, reintroducing the same supply-chain risk Docker-image pinning is designed to eliminate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every ``machine.image`` to a dated release tag, ``ubuntu-2204:2024.05.1`` rather than ``:current``, ``:edge``, ``:default``, or a bare image name. CircleCI rotates the ``current`` / ``edge`` aliases on its own cadence, so builds re-run on an image the author never reviewed.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-030: Workflow job uses context without branch filter or approval gate { #cc-030 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

CircleCI contexts are the recommended way to store shared secrets, but binding a context to a job is only half of least-privilege, the other half is controlling *when* the binding activates. Unrestricted workflow entries with ``context:`` turn every branch push into a secret-read event.

<div class="pg-rule__rec" markdown>

**Recommended action**

Either add ``filters.branches.only: [<protected branches>]`` to restrict when the context-bound job runs, or require a ``type: approval`` job in ``requires:`` so a human gates the secret-carrying execution. Without either gate, every push to the project loads the context's secrets into an ephemeral runner where any compromised step can exfiltrate them.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CC-031: OIDC role assumption without branch filter or approval gate { #cc-031 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Pairs with IAM-008. IAM-008 verifies the cloud-side trust policy pins audience + subject; this rule verifies the CircleCI-side workflow can't drive the role assumption from any branch. Distinct from CC-030 (broad context binding, MEDIUM); CC-031 narrows to OIDC role assumption and is HIGH because role-bound credentials reach further than the project-scoped secrets in a context.

<div class="pg-rule__rec" markdown>

**Recommended action**

Restrict every workflow job that passes a cloud ``role_arn`` (or equivalent OIDC parameter) to a protected branch list, or require a ``type: approval`` predecessor. Without either gate, any push triggers a cloud-role assumption with the full blast radius of the IdP-side trust policy.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CC-032: Secret-named variable echoed / printed in a run step { #cc-032 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-532</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Scans every ``run:`` command across all jobs. Variable names matching common secret patterns (PASSWORD, TOKEN, API_KEY, SECRET, CREDENTIAL) trigger the rule when they appear as arguments to ``echo``, ``printf``, ``cat``, or ``tee``. Also fires on ``printenv`` / ``env`` (full environment dump) and ``set -x`` with secret-named variables in scope.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't print secret values in CI scripts. CircleCI masks context variables in logs, but only exact-match substrings. Encoded, truncated, or derived forms bypass the mask. Log a boolean instead (``[ -n "$X" ] && echo set || echo unset``). Avoid ``set -x`` when secret-bound variables are in scope.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CC-033: Job disables Go module checksum / sum-db verification { #cc-033 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-353</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Walks each job's ``environment:`` map, every ``run`` step's ``environment:`` map, and every ``run`` command body (for inline ``export GOSUMDB=off`` assignments), and flags the Go integrity-disabling settings via the shared ``_primitives/go_insecure_env`` detector: ``GOFLAGS`` with ``-insecure``, ``GOSUMDB=off``, truthy ``GONOSUMCHECK``, any ``GOINSECURE``, and a broad ``GOPRIVATE`` / ``GONOSUMDB`` glob.

Scoped ``GOPRIVATE`` and ``GOPROXY=off`` / ``direct`` (still checksum-verified) are not flagged. The CircleCI sibling of GHA-110 / GL-037, the CI-env face of the verification-bypass surface GOMOD-001 warns about.

**Known false-positive modes**

- A job that builds only against an internal module proxy on a trusted network may set a scoped ``GOINSECURE`` for one internal host deliberately. Suppress per job with a rationale; a TLS-terminating internal proxy that preserves checksum verification is the safer path.

**Seen in the wild**

- Verification-bypass class: a runner told to skip the Go checksum database / sum file can be served a substituted module without ``go mod verify`` catching it, the same gap GOMOD-001 flags from the ``go.sum`` side.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the Go toolchain environment settings that turn off module integrity verification so ``go build`` keeps checking every downloaded module against ``go.sum`` and the checksum transparency database. Drop ``GOFLAGS=-insecure`` (plain HTTP fetch, TLS off), ``GOSUMDB=off`` / legacy ``GONOSUMCHECK`` (checksum DB / sum check off), and any ``GOINSECURE``; scope ``GOPRIVATE`` / ``GONOSUMDB`` to the exact internal namespace (``corp.example.com/team/*``) rather than a broad ``*`` or whole public host. This is the CI-env twin of GOMOD-001, a committed ``go.sum`` is moot if the runner ignores it. For private modules, prefer a trusted internal ``GOPROXY`` that still enforces checksums over disabling verification.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CC-034: ML model loaded with trust_remote_code (code execution) { #cc-034 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Scans every ``run:`` command across all jobs for ``trust_remote_code=True`` / ``--trust-remote-code`` (the shared ``model_trust`` detector, with GHA-120 / GL-045 / BB-035 / ADO-034 / HARNESS-010 / JF-039). The transformers / huggingface_hub loader executes the model repo's own Python at load time, so an untrusted or unpinned model is arbitrary code execution on the runner with the job's context secrets and OIDC in scope. The first AI model-load rule for CircleCI.

<div class="pg-rule__rec" markdown>

**Recommended action**

Load models with ``trust_remote_code=False`` (the library default). If a model genuinely needs custom code, vet it and pin an exact revision (a commit SHA, not a tag or branch), run the load in a job with no production context bound, and prefer safetensors weights over pickle.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CC-035: AI model pulled without a pinned revision { #cc-035 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Scans every ``run:`` command for a model fetched by a mutable registry reference with no revision pin (the shared ``model_ref`` detector, with GHA-121 / GL-046 / BB-038 / ADO-037 / HARNESS-012 / JF-040). Detected fetch forms: ``from_pretrained("org/model")``, ``hf_hub_download`` / ``snapshot_download`` with a ``org/model`` repo id, and ``huggingface-cli download org/model``.

Does NOT fire when a revision is pinned in the same command (``revision='<sha>'`` / ``--revision <sha>``), when the reference is a local path or a variable interpolation (the value can't be judged statically), or on a bare single-segment canonical hub name (``bert-base-uncased``) with no ``org/`` namespace.

**Known false-positive modes**

- A team that re-pulls its own org's model on every run may treat the latest revision as intentional. The right fix is still to pin the revision (it makes an upstream compromise visible); if a rolling pull is genuinely wanted, suppress on the specific step with a rationale naming the model and who controls it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin the model to an immutable revision. Pass an exact commit ``revision=`` to ``from_pretrained`` / ``hf_hub_download`` / ``snapshot_download`` (a 40-char commit SHA, not a branch or a tag, both of which the owner can move), or ``--revision <sha>`` to ``huggingface-cli download``. A pinned revision is what makes a swapped-weights or swapped-loader-code attack show up as a diff in your repo instead of silently landing on the next build. Pair with ``trust_remote_code=False`` (CC-034) and prefer safetensors weights over pickle.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CC-036: Unsafe deserialization of a fetched artifact (pickle RCE) { #cc-036 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-502</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reuses the shared ``unsafe_deser`` detector (with GHA-122 / GL-047 / BB-037 / ADO-036 / HARNESS-011 / JF-041) over every ``run:`` command. Fires in two shapes: (A) an explicit unsafe opt-in (``weights_only=False`` on a load, or ``allow_pickle=True`` on ``numpy.load``), always; and (B) a remote fetch (``curl`` / ``wget`` / ``hf_hub_download`` / ``snapshot_download`` / ``huggingface-cli download`` / ``requests.get`` / ``urlretrieve``) together with a pickle-backed loader (``torch.load`` / ``pickle.load(s)`` / ``joblib.load``) in the same command, with no safe path (``weights_only=True`` / safetensors). A bare local unpickle with no fetch does not fire.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't deserialize a downloaded artifact through pickle. Load weights with safetensors, or pass ``weights_only=True`` to ``torch.load`` (the PyTorch 2.6+ default) so only tensors, not arbitrary Python, are unpickled. Drop ``allow_pickle=True`` from ``numpy.load``. If a pickle / joblib artifact is unavoidable, pin and verify its source (a pinned revision, a checksum, a signature) and load it in a job with no production context bound.

</div>

</div>

---

## Adding a new CircleCI check

1. Create a new module at
   `pipeline_check/core/checks/circleci/rules/ccNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/circleci/CC-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py circleci
   ```
