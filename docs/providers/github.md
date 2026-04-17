# GitHub Actions provider

Parses workflow YAML files under a `.github/workflows` directory — no
network calls, no GitHub API token, no installed Actions runner required.

## Producer workflow

```bash
# --gha-path is auto-detected when .github/workflows exists at cwd;
# the CLI announces the pick on stderr.
pipeline_check --pipeline github

# …or pass it explicitly.
pipeline_check --pipeline github --gha-path .github/workflows
```

A single workflow file can also be passed directly:

```bash
pipeline_check --pipeline github --gha-path .github/workflows/release.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the AWS and Terraform providers.

## What it covers

| Check | Title | Severity |
|-------|-------|----------|
| GHA-001 | Action not pinned to commit SHA | HIGH |
| GHA-002 | pull_request_target checks out PR head | CRITICAL |
| GHA-003 | Script injection via untrusted context | HIGH |
| GHA-004 | Workflow has no explicit permissions block | MEDIUM |
| GHA-005 | AWS auth uses long-lived access keys | MEDIUM |
| GHA-006 | Artifacts not signed (no cosign/sigstore step) | MEDIUM |
| GHA-007 | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | MEDIUM |
| GHA-008 | Credential-shaped literal in workflow body | CRITICAL |
| GHA-009 | workflow_run downloads upstream artifact unverified | CRITICAL |
| GHA-010 | Local action (./path) on untrusted-trigger workflow | HIGH |
| GHA-011 | Cache key derives from attacker-controllable input | MEDIUM |
| GHA-012 | Self-hosted runner without ephemeral marker | MEDIUM |
| GHA-013 | issue_comment trigger without author guard | HIGH |
| GHA-014 | Deploy job missing environment binding | MEDIUM |
| GHA-015 | Job has no `timeout-minutes` — unbounded build | MEDIUM |
| GHA-016 | Remote script piped to shell interpreter | HIGH |
| GHA-017 | Docker run with insecure flags (privileged/host mount) | CRITICAL |
| GHA-018 | Package install from insecure source | HIGH |
| GHA-019 | GITHUB_TOKEN written to persistent storage | CRITICAL |
| GHA-020 | No vulnerability scanning step | MEDIUM |
| GHA-021 | Package install without lockfile enforcement | MEDIUM |
| GHA-022 | Dependency update command bypasses lockfile pins | MEDIUM |
| GHA-023 | TLS / certificate verification bypass | HIGH |
| GHA-024 | No SLSA provenance attestation produced | MEDIUM |
| GHA-025 | Reusable workflow not pinned to commit SHA | HIGH |
| GHA-026 | Container job disables isolation via `options:` | HIGH |
| GHA-027 | Workflow contains indicators of malicious activity | CRITICAL |
| GHA-028 | Dangerous shell idiom (eval, sh -c variable, backtick exec) | HIGH |
| GHA-029 | Package install bypasses registry integrity (git / path / tarball source) | MEDIUM |

---

## GHA-001 — Action not pinned to commit SHA
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-VERIFY-DEPS

Every `uses:` reference should pin a specific 40-char commit SHA. Tag and branch refs (`@v4`, `@main`) can be silently moved to malicious commits by whoever controls the upstream repository — a third-party action compromise will propagate into the pipeline on the next run.

**Recommended action**

Replace tag/branch references (`@v4`, `@main`) with the full 40-char commit SHA. Use Dependabot or StepSecurity to keep the pins fresh.

## GHA-002 — pull_request_target checks out PR head
**Severity:** CRITICAL · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-D-BUILD-ENV

`pull_request_target` runs with a write-scope GITHUB_TOKEN and access to repository secrets — deliberately so, since it's how labelling and comment-bot workflows work. When the same workflow then explicitly checks out the PR head (`ref: ${{ github.event.pull_request.head.sha }}` or `.ref`) it executes attacker-controlled code with those privileges.

**Recommended action**

Use `pull_request` instead of `pull_request_target` for any workflow that must run untrusted code. If you need write scope, split the workflow: a `pull_request_target` job that labels the PR, and a separate `pull_request`-triggered job that builds it with read-only secrets.

## GHA-003 — Script injection via untrusted context
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION

Interpolating attacker-controlled context fields (PR title/body, issue body, comment body, commit message, discussion body, head branch name, `github.ref_name`, `inputs.*`, release metadata, deployment payloads) directly into a `run:` block is shell injection. GitHub expands `${{ ... }}` BEFORE shell quoting, so any backtick, `$()`, or `;` in the source field executes.

**Recommended action**

Pass untrusted values through an intermediate `env:` variable and reference that variable from the shell script. GitHub's expression evaluation happens before shell quoting, so inline `${{ github.event.* }}` is always unsafe.

## GHA-004 — Workflow has no explicit permissions block
**Severity:** MEDIUM · OWASP CICD-SEC-5 · ESF ESF-C-LEAST-PRIV

Without an explicit `permissions:` block (either top-level or per-job), the GITHUB_TOKEN inherits the repository's default scope — typically `write`. A compromised step receives far more privilege than it needs.

**Recommended action**

Add a top-level `permissions:` block (start with `contents: read`) and grant additional scopes only on the specific jobs that need them.

## GHA-005 — AWS auth uses long-lived access keys
**Severity:** MEDIUM · OWASP CICD-SEC-6 · ESF ESF-D-TOKEN-HYGIENE

Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` secrets in GitHub Actions can't be rotated on a fine-grained schedule and remain valid until manually revoked. OIDC with `role-to-assume` yields short-lived credentials per workflow run.

**Recommended action**

Use `aws-actions/configure-aws-credentials` with `role-to-assume` + `permissions: id-token: write` to obtain short-lived credentials via OIDC. Remove the static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY secrets.

## GHA-006 — Artifacts not signed (no cosign/sigstore step)
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-D-SIGN-ARTIFACTS

Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognises cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools.

**Recommended action**

Add a signing step — e.g. `sigstore/cosign-installer` followed by `cosign sign`, or `slsa-framework/slsa-github-generator` for keyless SLSA provenance. Publish the signature alongside the artifact and verify it at consumption time.

## GHA-007 — SBOM not produced (no CycloneDX/syft/Trivy-SBOM step)
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-D-SBOM

Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognises CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

**Recommended action**

Add an SBOM generation step — `anchore/sbom-action`, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the release so consumers can ingest it into their vuln-management pipeline.

## GHA-008 — Credential-shaped literal in workflow body
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Every string in the workflow is scanned against a set of credential patterns (AWS access keys, GitHub tokens, Slack tokens, JWTs, Stripe, Google, Anthropic, etc. — see `--man secrets` for the full catalogue). A match means a secret was pasted into YAML — the value is visible in every fork and every build log and must be treated as compromised.

**Recommended action**

Rotate the exposed credential immediately. Move the value to an encrypted repository or environment secret and reference it via `${{ secrets.NAME }}`. For cloud access, prefer OIDC federation over long-lived keys.

## GHA-009 — workflow_run downloads upstream artifact unverified
**Severity:** CRITICAL · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-S-VERIFY-DEPS

`on: workflow_run` runs in the privileged context of the default branch (write GITHUB_TOKEN, secrets accessible) but consumes artifacts produced by the triggering workflow — which is often a fork PR with no trust boundary. Classic PPE: a malicious PR uploads a tampered artifact, the privileged workflow_run downloads and executes it.

**Recommended action**

Add a verification step BEFORE consuming the artifact: `cosign verify-attestation --type slsaprovenance ...`, `gh attestation verify --owner $OWNER ./artifact`, or publish a checksum manifest from the trusted producer and `sha256sum -c` it. Treat any download from a fork as untrusted input.

## GHA-010 — Local action (./path) on untrusted-trigger workflow
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-S-PIN-DEPS

`uses: ./path/to/action` resolves the action against the CHECKED-OUT workspace. On `pull_request_target` / `workflow_run`, that workspace can be PR-controlled — meaning the attacker supplies the `action.yml` that runs with default-branch privilege.

**Recommended action**

Move the action to a separate repo under your control and reference it by SHA-pinned `uses: org/repo@<sha>`, or split the workflow so the privileged work runs only on `pull_request` (read-only token, no secrets) where PR-controlled action.yml can't escalate.

## GHA-011 — Cache key derives from attacker-controllable input
**Severity:** MEDIUM · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-S-VERIFY-DEPS

`actions/cache` restores by key (and falls through `restore-keys` on miss). When the key includes a value the attacker controls (PR title, head ref, workflow_dispatch input), an attacker can plant a poisoned cache entry that a later default-branch run restores and treats as a clean build cache.

**Recommended action**

Build the cache key from values the attacker can't control: `${{ runner.os }}`, `${{ hashFiles('**/*.lock') }}` (only when the lockfile is enforced by branch protection), and the workflow file path. Never include `github.event.*` PR/issue fields, `github.head_ref`, or `inputs.*` in the key namespace.

## GHA-012 — Self-hosted runner without ephemeral marker
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-ENV, ESF-D-PRIV-BUILD

Self-hosted runners that don't tear down between jobs leak filesystem and process state. A PR-triggered job writes to `/tmp`; a subsequent prod-deploy job on the same runner reads it. The mitigation is the runner's `--ephemeral` mode — the runner exits after one job and re-registers fresh. The check looks for an `ephemeral` label on the `runs-on` value; without one, the runner is presumed reusable. Recognises all three `runs-on` shapes: string, list, and `{ group, labels }` dict form.

**Recommended action**

Configure the self-hosted runner to register with `--ephemeral` (the runner exits after one job and is freshly registered), and add an `ephemeral` label so this check can verify it. Consider actions-runner-controller for ephemeral pools.

## GHA-013 — issue_comment trigger without author guard
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION

`on: issue_comment` (and `discussion_comment`) fires for every comment on every issue or discussion in the repository. On public repos this means any GitHub user can trigger workflow execution. If the workflow runs commands, deploys, or accesses secrets, the attacker controls timing and can inject payloads through the comment body.

**Recommended action**

Add an `if:` condition that checks `github.event.comment.author_association` (e.g. `contains('OWNER MEMBER COLLABORATOR', ...)`), `github.event.sender.login`, or `github.actor` against an allowlist. Without a guard, any GitHub user can trigger the workflow by posting a comment.

## GHA-014 — Deploy job missing environment binding
**Severity:** MEDIUM · OWASP CICD-SEC-1 · ESF ESF-C-APPROVAL, ESF-C-ENV-SEP

Without an `environment:` binding, a deploy job can't be gated by required reviewers, deployment-branch policies, or wait timers. Any push to the triggering branch will deploy immediately.

**Recommended action**

Add `environment: <name>` to jobs that deploy. Configure required reviewers, wait timers, and branch-protection rules on the matching GitHub environment.

## GHA-015 — Job has no `timeout-minutes` — unbounded build
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-TIMEOUT

Without `timeout-minutes`, the job runs until GitHub's 6-hour default kills it. Explicit timeouts cap blast radius, cost, and the window during which a compromised step has access to secrets.

**Recommended action**

Add `timeout-minutes:` to each job, sized to the 95th percentile of historical runtime plus margin. GitHub's default is 360 minutes — an explicitly shorter value limits blast radius and runner cost.

## GHA-016 — Remote script piped to shell interpreter
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-VERIFY-DEPS

Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a workflow. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

## GHA-017 — Docker run with insecure flags (privileged/host mount)
**Severity:** CRITICAL · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-ENV

Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a workflow give the container full access to the runner, enabling container escape and lateral movement.

**Recommended action**

Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

## GHA-018 — Package install from insecure source
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-VERIFY-DEPS

Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a workflow. These patterns allow man-in-the-middle injection of malicious packages.

**Recommended action**

Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

## GHA-019 — GITHUB_TOKEN written to persistent storage
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Detects patterns where `GITHUB_TOKEN` is written to files, environment files (`$GITHUB_ENV`), or piped through `tee`. Persisted tokens survive the step boundary and can be exfiltrated by later steps, uploaded artifacts, or cache entries — turning a scoped credential into a long-lived one.

**Recommended action**

Never write GITHUB_TOKEN to files, artifacts, or GITHUB_ENV. Use the token inline via ${{ secrets.GITHUB_TOKEN }} in the step that needs it.

## GHA-020 — No vulnerability scanning step
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-VULN-MGMT

Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognises trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommended action**

Add a vulnerability scanning step — trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

## GHA-021 — Package install without lockfile enforcement
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS

Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest — exactly the window a supply-chain attacker exploits.

**Recommended action**

Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

## GHA-022 — Dependency update command bypasses lockfile pins
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS

Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommended action**

Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

## GHA-023 — TLS / certificate verification bypass
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-VERIFY-DEPS

Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommended action**

Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

## GHA-024 — No SLSA provenance attestation produced
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-S-PROVENANCE

Provenance generation is distinct from signing. A signed artifact proves ``who`` published it; a provenance attestation proves ``where/how`` it was built. Consumers can then verify the build happened on a trusted runner, from a specific source commit, with known parameters. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance — you need both for the SLSA L3 non-falsifiability guarantee.

**Recommended action**

Call ``slsa-framework/slsa-github-generator`` or ``actions/attest-build-provenance`` after the build step to emit an in-toto attestation alongside the artifact. ``cosign sign`` alone (covered by GHA-006) signs the artifact but doesn't record *how* it was built — SLSA Build L3 requires the provenance statement.

## GHA-025 — Reusable workflow not pinned to commit SHA
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-VERIFY-DEPS

A reusable workflow runs with the caller's ``GITHUB_TOKEN`` and secrets by default. If ``uses: org/repo/.github/workflows/release.yml@v1`` resolves to an attacker-modified commit, their code executes with your repository's permissions. This is the same threat model as unpinned step actions (GHA-001) but over a different ``uses:`` surface.

**Recommended action**

Pin every ``jobs.<id>.uses:`` reference to a 40-char commit SHA (``owner/repo/.github/workflows/foo.yml@<sha>``). Tag refs (``@v1``, ``@main``) can be silently repointed by whoever controls the callee repository.

## GHA-026 — Container job disables isolation via `options:`
**Severity:** HIGH · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-ENV, ESF-D-PRIV-BUILD

GitHub-hosted runners execute ``container:`` jobs inside a Docker container the runner itself manages — normally a hardened, network-namespaced sandbox. ``options:`` is a free-text passthrough to ``docker run``; a flag that breaks the sandbox (shares host network/PID, runs privileged, maps the Docker socket) turns the job into an RCE on the runner VM.

**Recommended action**

Remove ``--network host``, ``--privileged``, ``--cap-add``, ``--user 0``/``--user root``, ``--pid host``, ``--ipc host``, and host ``-v`` bind-mounts from ``container.options`` and ``services.*.options``. If a build genuinely needs one of these, move it to a dedicated self-hosted pool with branch protection so the flag doesn't reach PR runs.

## GHA-027 — Workflow contains indicators of malicious activity
**Severity:** CRITICAL · OWASP CICD-SEC-4, CICD-SEC-7 · ESF ESF-D-INJECTION, ESF-S-VERIFY-DEPS

Distinct from the hygiene checks. GHA-016 flags ``curl | bash`` as a risky default; this rule fires only on concrete indicators — reverse shells, base64-decoded execution, known miner binaries or pool URLs, exfil-channel domains, credential-dump pipes, history-erasure commands. Categories reported: ``obfuscated-exec``, ``reverse-shell``, ``crypto-miner``, ``exfil-channel``, ``credential-exfil``, ``audit-erasure``.

**Recommended action**

Treat this as a potential pipeline compromise. Inspect the matching step(s), identify the author and the PR that introduced them, rotate any credentials the workflow has access to, and audit CloudTrail/AuditLogs for exfil. If the match is a legitimate red-team exercise, whitelist via ``.pipelinecheckignore`` with an ``expires:`` date — never a permanent suppression.

## GHA-028 — Dangerous shell idiom (eval, sh -c variable, backtick exec)
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION

``eval``, ``sh -c "$X"``, and `` `$X` `` all re-parse the variable's value as shell syntax. If the value contains ``;``, ``&&``, ``|``, backticks, or ``$()``, those metacharacters execute. Even when the variable source looks controlled today, relocating the script or adding a new caller can silently expose it to untrusted input.

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec of variables with direct command invocation. If the command really must be dynamic, pass arguments as array members (``"${ARGS[@]}"``) or validate the input against an allow-list before invocation.

## GHA-029 — Package install bypasses registry integrity (git / path / tarball source)
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-VERIFY-DEPS

Package installs that pull from ``git+…`` without a pinned commit, from a local path (``./dir``, ``file:…``, absolute paths), or from a direct tarball URL are invisible to the normal lockfile integrity controls. A moving branch head, a sibling checkout the build assumes exists, or a tarball whose hash isn't verified all give an attacker who controls any of those surfaces the ability to substitute code into the build.

**Recommended action**

Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

---

## Adding a new GitHub Actions check

1. Create a new module at
   `pipeline_check/core/checks/github/rules/ghaNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) ->
   Finding` function. The orchestrator auto-discovers it.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/github/GHA-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py github
   ```
