# Azure DevOps Pipelines provider

Parses an `azure-pipelines.yml` from disk — no network calls, no ADO
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

- Flat single-job pipeline — top-level `steps:`
- Single-stage multi-job — top-level `jobs:`
- Multi-stage — `stages: → jobs: → steps:`
- Deployment jobs — steps under
  `strategy.{runOnce|rolling|canary}.{preDeploy|deploy|routeTraffic|postRouteTraffic}.steps`
  and `strategy.*.on.{success|failure}.steps`.

## What it covers

| Check | Title | Severity |
|-------|-------|----------|
| ADO-001 | Task reference not pinned to specific version | HIGH |
| ADO-002 | Script injection via attacker-controllable context | HIGH |
| ADO-003 | Variables contain literal secret values | CRITICAL |
| ADO-004 | Deployment job missing environment binding | MEDIUM |
| ADO-005 | Container image not pinned to specific version | HIGH |
| ADO-006 | Artifacts not signed | MEDIUM |
| ADO-007 | SBOM not produced | MEDIUM |
| ADO-008 | Credential-shaped literal in pipeline body | CRITICAL |
| ADO-009 | Container image pinned by tag rather than sha256 digest | LOW |
| ADO-010 | Cross-pipeline `download:` ingestion unverified | CRITICAL |
| ADO-011 | `template: <local-path>` on PR-validated pipeline | HIGH |
| ADO-012 | Cache@2 key derives from $(System.PullRequest.*) | MEDIUM |
| ADO-013 | Self-hosted pool without explicit ephemeral marker | MEDIUM |
| ADO-014 | AWS auth uses long-lived access keys | MEDIUM |
| ADO-015 | Job has no `timeoutInMinutes` — unbounded build | MEDIUM |
| ADO-016 | Remote script piped to shell interpreter | HIGH |
| ADO-017 | Docker run with insecure flags (privileged/host mount) | CRITICAL |
| ADO-018 | Package install from insecure source | HIGH |
| ADO-019 | `extends:` template on PR-validated pipeline points to local path | CRITICAL |
| ADO-020 | No vulnerability scanning step | MEDIUM |
| ADO-021 | Package install without lockfile enforcement | MEDIUM |
| ADO-022 | Dependency update command bypasses lockfile pins | MEDIUM |
| ADO-023 | TLS / certificate verification bypass | HIGH |

---

## ADO-001 — Task reference not pinned to specific version
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-VERIFY-DEPS

Floating-major task references (`@1`, `@2`) can roll forward silently when the task publisher ships a breaking or malicious update. Pass when every `task:` reference carries a two- or three-segment semver.

**Recommended action**

Reference tasks by a full semver (`DownloadSecureFile@1.2.3`) or extension-published-version. Track task updates explicitly via Azure DevOps extension settings rather than letting `@1` drift.

## ADO-002 — Script injection via attacker-controllable context
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION

`$(Build.SourceBranch*)`, `$(Build.SourceVersionMessage)`, and `$(System.PullRequest.*)` are populated from SCM event metadata the attacker controls. Inline interpolation into a script body executes crafted content.

**Recommended action**

Pass these values through an intermediate pipeline variable declared with `readonly: true`, and reference that variable through an environment variable rather than `$(...)` macro interpolation. ADO expands `$(…)` before shell quoting, so inline use is never safe.

## ADO-003 — Variables contain literal secret values
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Scans `variables:` in both the mapping form (`{KEY: VAL}`) and the list form (`[{name: X, value: Y}]`) that ADO supports. AWS keys are detected by value shape regardless of variable name.

**Recommended action**

Store secrets in an Azure Key Vault or a Library variable group with the secret flag set; reference them via `$(SECRET_NAME)` at runtime. For cloud access prefer Azure workload identity federation.

## ADO-004 — Deployment job missing environment binding
**Severity:** MEDIUM · OWASP CICD-SEC-1 · ESF ESF-C-APPROVAL, ESF-C-ENV-SEP

Without an `environment:` binding, ADO cannot enforce approvals, checks, or deployment history against a named resource. Every `deployment:` job should bind one.

**Recommended action**

Add `environment: <name>` to every `deployment:` job. Configure approvals, required branches, and business-hours checks on the matching Environment in the ADO UI.

## ADO-005 — Container image not pinned to specific version
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-TRUSTED-REG

Container images can be declared at `resources.containers[].image` or `job.container` (string or `{image:}`). Floating / untagged refs let the publisher swap the image contents.

**Recommended action**

Reference images by `@sha256:<digest>` or at minimum a full immutable version tag. Avoid `:latest` and untagged refs.

## ADO-006 — Artifacts not signed
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-D-SIGN-ARTIFACTS

Passes when cosign / sigstore / slsa-* / notation-sign appears anywhere in the pipeline text.

**Recommended action**

Add a task that runs `cosign sign` or `notation sign` — Azure Pipelines' workload identity federation enables keyless signing. Publish the signature to the artifact feed and verify it at deploy time.

## ADO-007 — SBOM not produced
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-D-SBOM

Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact.

**Recommended action**

Add an SBOM step — `microsoft/sbom-tool`, `syft . -o cyclonedx-json`, or `anchore/sbom-action`. Publish the SBOM as a pipeline artifact so downstream consumers can ingest it.

## ADO-008 — Credential-shaped literal in pipeline body
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Complements ADO-003 (which looks at `variables:` keys). ADO-008 scans every string in the pipeline against the cross-provider credential-pattern catalogue.

**Recommended action**

Rotate the exposed credential. Move the value to Azure Key Vault or a secret variable group and reference it via `$(SECRET_NAME)`.

## ADO-009 — Container image pinned by tag rather than sha256 digest
**Severity:** LOW · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-IMMUTABLE

ADO-005 fails floating tags at HIGH; ADO-009 is the stricter tier. Even immutable-looking version tags can be repointed by registry operators.

**Recommended action**

Resolve each image to its current digest and replace the tag with `@sha256:<digest>`. Schedule regular digest bumps via Renovate or a scheduled pipeline.

## ADO-010 — Cross-pipeline `download:` ingestion unverified
**Severity:** CRITICAL · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-S-VERIFY-DEPS

`resources.pipelines:` declares an upstream pipeline; a `download: <name>` step pulls its artifacts. If the upstream accepts PR validation, the artifact may have been built by PR-controlled code.

**Recommended action**

Add a verification step before consuming the artifact: `cosign verify-attestation`, `sha256sum -c`, or `gpg --verify` against a manifest the producing pipeline signed.

## ADO-011 — `template: <local-path>` on PR-validated pipeline
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-S-PIN-DEPS

`template: <relative-path>` includes another YAML from the CURRENT repo. On PR validation builds, the repo content is the PR branch — letting the PR author swap the template body. Cross-repo templates (`template: foo.yml@my-repo`) are version-pinned and not affected.

**Recommended action**

Move the template into a separate, branch-protected repository and reference it via `template: foo.yml@<repo-resource>` with a pinned `ref:` on the resource. That way the template content is fixed at PR creation time and can't be modified from the PR branch.

## ADO-012 — Cache@2 key derives from $(System.PullRequest.*)
**Severity:** MEDIUM · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-S-VERIFY-DEPS

`Cache@2` (and older `CacheBeta@1`) restore by key. A key including PR-controlled variables on PR-validated pipelines lets a PR seed a poisoned cache entry that a later default-branch pipeline restores.

**Recommended action**

Build the cache key from values the PR can't control: `$(Agent.OS)`, lockfile hashes, the pipeline name. Never reference `$(System.PullRequest.*)` or `$(Build.SourceBranch*)` from a cache key namespace.

## ADO-013 — Self-hosted pool without explicit ephemeral marker
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-ENV, ESF-D-PRIV-BUILD

`pool: { name: <agent-pool> }` (or the bare string form `pool: <name>`) targets a self-hosted agent pool. Without an explicit ephemeral arrangement, agents reuse state across jobs. Microsoft-hosted pools (`vmImage:` or the `Azure Pipelines` / `Default` names) are skipped.

**Recommended action**

Configure the agent pool with autoscaling + ephemeral agents (the Azure VM Scale Set agent), and add `demands: [ephemeral -equals true]` on the pool block so this check can verify it.

## ADO-014 — AWS auth uses long-lived access keys
**Severity:** MEDIUM · OWASP CICD-SEC-6 · ESF ESF-D-TOKEN-HYGIENE

Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values in pipeline variables or task inputs can't be rotated on a fine-grained schedule. Prefer OIDC or vault-based credential injection for cross-cloud access.

**Recommended action**

Use workload identity federation or an Azure Key Vault task to inject short-lived AWS credentials at runtime. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from pipeline variables and task parameters.

## ADO-015 — Job has no `timeoutInMinutes` — unbounded build
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-TIMEOUT

Without `timeoutInMinutes`, the job runs until Azure's 60-minute default kills it. Explicit timeouts cap blast radius and the window during which a compromised step has access to service connections.

**Recommended action**

Add `timeoutInMinutes:` to each job, sized to the 95th percentile of historical runtime plus margin. Azure's default is 60 minutes — an explicitly shorter value limits blast radius and agent cost.

## ADO-016 — Remote script piped to shell interpreter
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-VERIFY-DEPS

Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build agent.

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

## ADO-017 — Docker run with insecure flags (privileged/host mount)
**Severity:** CRITICAL · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-ENV

Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a pipeline give the container full access to the build agent, enabling container escape and lateral movement.

**Recommended action**

Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

## ADO-018 — Package install from insecure source
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-VERIFY-DEPS

Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommended action**

Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

## ADO-019 — `extends:` template on PR-validated pipeline points to local path
**Severity:** CRITICAL · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-S-PIN-DEPS

`extends: template: <local-file>` includes another YAML from the CURRENT repo. On PR validation builds, the repo content is the PR branch — letting the PR author swap the template body and inject arbitrary pipeline logic. Cross-repo templates (`template: foo.yml@my-repo`) are version-pinned and not affected.

**Recommended action**

Pin the extends template to a protected repository ref (`template@ref`). Local templates in PR-validated pipelines can be poisoned by the PR author.

## ADO-020 — No vulnerability scanning step
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-VULN-MGMT

Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognises trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommended action**

Add a vulnerability scanning step — trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

## ADO-021 — Package install without lockfile enforcement
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS

Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest — exactly the window a supply-chain attacker exploits.

**Recommended action**

Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

## ADO-022 — Dependency update command bypasses lockfile pins
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS

Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommended action**

Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

## ADO-023 — TLS / certificate verification bypass
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-VERIFY-DEPS

Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommended action**

Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

---

## Adding a new Azure DevOps Pipelines check

1. Create a new module at
   `pipeline_check/core/checks/azure/rules/adoNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) ->
   Finding` function. The orchestrator auto-discovers it.
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
