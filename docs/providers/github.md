# GitHub Actions provider

Parses workflow YAML files under a `.github/workflows` directory. No
GitHub API token or installed Actions runner is required by default;
the scanner stays read-from-disk-only unless `--resolve-remote` opts
in to fetching reusable-workflow callees over HTTPS.

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

## Reusable workflow resolution

`jobs.<id>.uses: owner/repo/.github/workflows/x.yml@<sha>` references
a workflow body that runs with the *caller's* `GITHUB_TOKEN` and
secrets. By default the scanner stops at the call site (it flags the
ref via `GHA-025` when unpinned and emits a one-line nudge listing
how many remote refs were skipped); `--resolve-remote` opts in to
fetching the called body and running the full GHA rule pack against
it with the caller's permissions context.

```bash
# Fetch via raw.githubusercontent.com (works for public repos).
pipeline_check --pipeline github --resolve-remote

# Private callees: pass a token, or set $GITHUB_TOKEN.
pipeline_check --pipeline github --resolve-remote --gh-token "$GH_PAT"

# Fully offline: search a sibling on-disk checkout instead.
pipeline_check --pipeline github --resolve-remote \
    --gha-search-path ../shared-workflows
```

Resolution rules:

- **Only SHA-pinned refs are fetched.** A tag-pinned ref (`@v1`,
  `@main`) is skipped with a warning — resolution against a movable
  upstream tag would defeat `GHA-025`'s value.
- **Recursion** follows transitive `uses:` calls to a depth of 3
  (configurable with `--gha-resolve-depth`; hard ceiling 10). Cycles
  are detected.
- **Cache.** Fetched bodies live under
  `~/.cache/pipeline-check/gha-resolver/` for 7 days. Use `--no-cache`
  to bypass.
- **Failure mode.** Network errors, 404s, and malformed YAML never
  abort the scan — they land in the context's warnings stream.
- **Attribution.** Findings on a resolved callee carry a synthetic
  `<caller-path> -> <owner>/<repo>/<path>@<ref>` resource string so
  the report points at both the call site and the upstream body.
- **Permissions inheritance.** A callee without its own
  `permissions:` runs with the caller's; `GHA-004` doesn't fire on a
  callee whose caller declared one.
- **`secrets: inherit`.** When the call site passes
  `secrets: inherit`, `GHA-019` annotates findings with the inherit
  note so report readers see the full credential surface.

## What it covers

36 checks · 17 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GHA-001](#gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-002](#gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-003](#gha-003) | Script injection via untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-004](#gha-004) | Workflow has no explicit permissions block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-005](#gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-006](#gha-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-007](#gha-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-008](#gha-008) | Credential-shaped literal in workflow body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-009](#gha-009) | workflow_run downloads upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-010](#gha-010) | Local action (./path) on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-011](#gha-011) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-012](#gha-012) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-013](#gha-013) | issue_comment trigger without author guard | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-014](#gha-014) | Deploy job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-015](#gha-015) | Job has no `timeout-minutes` — unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-016](#gha-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-017](#gha-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-018](#gha-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-019](#gha-019) | GITHUB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-020](#gha-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-021](#gha-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-022](#gha-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-023](#gha-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-024](#gha-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-025](#gha-025) | Reusable workflow not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-026](#gha-026) | Container job disables isolation via `options:` | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-027](#gha-027) | Workflow contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-028](#gha-028) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-029](#gha-029) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-030](#gha-030) | OIDC token requested without environment-protected job | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-031](#gha-031) | Workflow uses retired set-output / save-state command | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-032](#gha-032) | run: invokes local script on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-033](#gha-033) | Secret value echoed / printed in a run: block | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-034](#gha-034) | Reusable workflow called with secrets: inherit | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-035](#gha-035) | github-script step interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-036](#gha-036) | runs-on interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

---

<div class="pg-rule pg-rule--high" markdown>

## GHA-001 — Action not pinned to commit SHA { #gha-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Every `uses:` reference should pin a specific 40-char commit SHA. Tag and branch refs (`@v4`, `@main`) can be silently moved to malicious commits by whoever controls the upstream repository — a third-party action compromise will propagate into the pipeline on the next run.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace tag/branch references (`@v4`, `@main`) with the full 40-char commit SHA. Use Dependabot or StepSecurity to keep the pins fresh.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-002 — pull_request_target checks out PR head { #gha-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

`pull_request_target` runs with a write-scope GITHUB_TOKEN and access to repository secrets — deliberately so, since it's how labeling and comment-bot workflows work. When the same workflow then explicitly checks out the PR head (`ref: ${{ github.event.pull_request.head.sha }}` or `.ref`) it executes attacker-controlled code with those privileges.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use `pull_request` instead of `pull_request_target` for any workflow that must run untrusted code. If you need write scope, split the workflow: a `pull_request_target` job that labels the PR, and a separate `pull_request`-triggered job that builds it with read-only secrets.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-003 — Script injection via untrusted context { #gha-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

Interpolating attacker-controlled context fields (PR title/body, issue body, comment body, commit message, discussion body, head branch name, `github.ref_name`, `inputs.*`, release metadata, deployment payloads) directly into a `run:` block is shell injection. GitHub expands `${{ ... }}` BEFORE shell quoting, so any backtick, `$()`, or `;` in the source field executes.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pass untrusted values through an intermediate `env:` variable and reference that variable from the shell script. GitHub's expression evaluation happens before shell quoting, so inline `${{ github.event.* }}` is always unsafe.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-004 — Workflow has no explicit permissions block { #gha-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Without an explicit `permissions:` block (either top-level or per-job), the GITHUB_TOKEN inherits the repository's default scope — typically `write`. A compromised step receives far more privilege than it needs.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a top-level `permissions:` block (start with `contents: read`) and grant additional scopes only on the specific jobs that need them.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-005 — AWS auth uses long-lived access keys { #gha-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-TOKEN-HYGIENE</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` secrets in GitHub Actions can't be rotated on a fine-grained schedule and remain valid until manually revoked. OIDC with `role-to-assume` yields short-lived credentials per workflow run.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use `aws-actions/configure-aws-credentials` with `role-to-assume` + `permissions: id-token: write` to obtain short-lived credentials via OIDC. Remove the static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY secrets.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-006 — Artifacts not signed (no cosign/sigstore step) { #gha-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognises cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a signing step — e.g. `sigstore/cosign-installer` followed by `cosign sign`, or `slsa-framework/slsa-github-generator` for keyless SLSA provenance. Publish the signature alongside the artifact and verify it at consumption time.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-007 — SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) { #gha-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognises CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an SBOM generation step — `anchore/sbom-action`, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the release so consumers can ingest it into their vuln-management pipeline.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-008 — Credential-shaped literal in workflow body { #gha-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Every string in the workflow is scanned against a set of credential patterns (AWS access keys, GitHub tokens, Slack tokens, JWTs, Stripe, Google, Anthropic, etc. — see `--man secrets` for the full catalog). A match means a secret was pasted into YAML — the value is visible in every fork and every build log and must be treated as compromised.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the exposed credential immediately. Move the value to an encrypted repository or environment secret and reference it via `${{ secrets.NAME }}`. For cloud access, prefer OIDC federation over long-lived keys.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-009 — workflow_run downloads upstream artifact unverified { #gha-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

`on: workflow_run` runs in the privileged context of the default branch (write GITHUB_TOKEN, secrets accessible) but consumes artifacts produced by the triggering workflow — which is often a fork PR with no trust boundary. Classic PPE: a malicious PR uploads a tampered artifact, the privileged workflow_run downloads and executes it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a verification step BEFORE consuming the artifact: `cosign verify-attestation --type slsaprovenance ...`, `gh attestation verify --owner $OWNER ./artifact`, or publish a checksum manifest from the trusted producer and `sha256sum -c` it. Treat any download from a fork as untrusted input.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-010 — Local action (./path) on untrusted-trigger workflow { #gha-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

`uses: ./path/to/action` resolves the action against the CHECKED-OUT workspace. On `pull_request_target` / `workflow_run`, that workspace can be PR-controlled — meaning the attacker supplies the `action.yml` that runs with default-branch privilege.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the action to a separate repo under your control and reference it by SHA-pinned `uses: org/repo@<sha>`, or split the workflow so the privileged work runs only on `pull_request` (read-only token, no secrets) where PR-controlled action.yml can't escalate.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-011 — Cache key derives from attacker-controllable input { #gha-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

`actions/cache` restores by key (and falls through `restore-keys` on miss). When the key includes a value the attacker controls (PR title, head ref, workflow_dispatch input), an attacker can plant a poisoned cache entry that a later default-branch run restores and treats as a clean build cache.

<div class="pg-rule__rec" markdown>

**Recommended action**

Build the cache key from values the attacker can't control: `${{ runner.os }}`, `${{ hashFiles('**/*.lock') }}` (only when the lockfile is enforced by branch protection), and the workflow file path. Never include `github.event.*` PR/issue fields, `github.head_ref`, or `inputs.*` in the key namespace.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-012 — Self-hosted runner without ephemeral marker { #gha-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Self-hosted runners that don't tear down between jobs leak filesystem and process state. A PR-triggered job writes to `/tmp`; a subsequent prod-deploy job on the same runner reads it. The mitigation is the runner's `--ephemeral` mode — the runner exits after one job and re-registers fresh. The check looks for an `ephemeral` label on the `runs-on` value; without one, the runner is presumed reusable. Recognises all three `runs-on` shapes: string, list, and `{ group, labels }` dict form.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure the self-hosted runner to register with `--ephemeral` (the runner exits after one job and is freshly registered), and add an `ephemeral` label so this check can verify it. Consider actions-runner-controller for ephemeral pools.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-013 — issue_comment trigger without author guard { #gha-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

`on: issue_comment` (and `discussion_comment`) fires for every comment on every issue or discussion in the repository. On public repos this means any GitHub user can trigger workflow execution. If the workflow runs commands, deploys, or accesses secrets, the attacker controls timing and can inject payloads through the comment body.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an `if:` condition that checks `github.event.comment.author_association` (e.g. `contains('OWNER MEMBER COLLABORATOR', ...)`), `github.event.sender.login`, or `github.actor` against an allowlist. Without a guard, any GitHub user can trigger the workflow by posting a comment.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-014 — Deploy job missing environment binding { #gha-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--esf">ESF-C-ENV-SEP</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Without an `environment:` binding, a deploy job can't be gated by required reviewers, deployment-branch policies, or wait timers. Any push to the triggering branch will deploy immediately.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `environment: <name>` to jobs that deploy. Configure required reviewers, wait timers, and branch-protection rules on the matching GitHub environment.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-015 — Job has no `timeout-minutes` — unbounded build { #gha-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-TIMEOUT</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Without `timeout-minutes`, the job runs until GitHub's 6-hour default kills it. Explicit timeouts cap blast radius, cost, and the window during which a compromised step has access to secrets.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `timeout-minutes:` to each job, sized to the 95th percentile of historical runtime plus margin. GitHub's default is 360 minutes — an explicitly shorter value limits blast radius and runner cost.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-016 — Remote script piped to shell interpreter { #gha-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a workflow. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

<div class="pg-rule__rec" markdown>

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-017 — Docker run with insecure flags (privileged/host mount) { #gha-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a workflow give the container full access to the runner, enabling container escape and lateral movement.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-018 — Package install from insecure source { #gha-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a workflow. These patterns allow man-in-the-middle injection of malicious packages.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-019 — GITHUB_TOKEN written to persistent storage { #gha-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Detects patterns where `GITHUB_TOKEN` is written to files, environment files (`$GITHUB_ENV`), or piped through `tee`. Persisted tokens survive the step boundary and can be exfiltrated by later steps, uploaded artifacts, or cache entries — turning a scoped credential into a long-lived one.

<div class="pg-rule__rec" markdown>

**Recommended action**

Never write GITHUB_TOKEN to files, artifacts, or GITHUB_ENV. Use the token inline via ${{ secrets.GITHUB_TOKEN }} in the step that needs it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-020 — No vulnerability scanning step { #gha-020 }

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

## GHA-021 — Package install without lockfile enforcement { #gha-021 }

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

## GHA-022 — Dependency update command bypasses lockfile pins { #gha-022 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-023 — TLS / certificate verification bypass { #gha-023 }

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

## GHA-024 — No SLSA provenance attestation produced { #gha-024 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Provenance generation is distinct from signing. A signed artifact proves ``who`` published it; a provenance attestation proves ``where/how`` it was built. Consumers can then verify the build happened on a trusted runner, from a specific source commit, with known parameters. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance — you need both for the SLSA L3 non-falsifiability guarantee.

<div class="pg-rule__rec" markdown>

**Recommended action**

Call ``slsa-framework/slsa-github-generator`` or ``actions/attest-build-provenance`` after the build step to emit an in-toto attestation alongside the artifact. ``cosign sign`` alone (covered by GHA-006) signs the artifact but doesn't record *how* it was built — SLSA Build L3 requires the provenance statement.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-025 — Reusable workflow not pinned to commit SHA { #gha-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

A reusable workflow runs with the caller's ``GITHUB_TOKEN`` and secrets by default. If ``uses: org/repo/.github/workflows/release.yml@v1`` resolves to an attacker-modified commit, their code executes with your repository's permissions. This is the same threat model as unpinned step actions (GHA-001) but over a different ``uses:`` surface.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every ``jobs.<id>.uses:`` reference to a 40-char commit SHA (``owner/repo/.github/workflows/foo.yml@<sha>``). Tag refs (``@v1``, ``@main``) can be silently repointed by whoever controls the callee repository.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-026 — Container job disables isolation via `options:` { #gha-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-250</span> <span class="pg-tag pg-tag--cwe">CWE-276</span>
</div>

GitHub-hosted runners execute ``container:`` jobs inside a Docker container the runner itself manages — normally a hardened, network-namespaced sandbox. ``options:`` is a free-text passthrough to ``docker run``; a flag that breaks the sandbox (shares host network/PID, runs privileged, maps the Docker socket) turns the job into an RCE on the runner VM.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``--network host``, ``--privileged``, ``--cap-add``, ``--user 0``/``--user root``, ``--pid host``, ``--ipc host``, and host ``-v`` bind-mounts from ``container.options`` and ``services.*.options``. If a build genuinely needs one of these, move it to a dedicated self-hosted pool with branch protection so the flag doesn't reach PR runs.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-027 — Workflow contains indicators of malicious activity { #gha-027 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-506</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Distinct from the hygiene checks. GHA-016 flags ``curl | bash`` as a risky default; this rule fires only on concrete indicators — reverse shells, base64-decoded execution, known miner binaries or pool URLs, exfil-channel domains, credential-dump pipes, history-erasure commands. Categories reported: ``obfuscated-exec``, ``reverse-shell``, ``crypto-miner``, ``exfil-channel``, ``credential-exfil``, ``audit-erasure``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat this as a potential pipeline compromise. Inspect the matching step(s), identify the author and the PR that introduced them, rotate any credentials the workflow has access to, and audit CloudTrail/AuditLogs for exfil. If the match is a legitimate red-team exercise, whitelist via ``.pipelinecheckignore`` with an ``expires:`` date — never a permanent suppression.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-028 — Dangerous shell idiom (eval, sh -c variable, backtick exec) { #gha-028 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-95</span>
</div>

``eval``, ``sh -c "$X"``, and `` `$X` `` all re-parse the variable's value as shell syntax. If the value contains ``;``, ``&&``, ``|``, backticks, or ``$()``, those metacharacters execute. Even when the variable source looks controlled today, relocating the script or adding a new caller can silently expose it to untrusted input.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec of variables with direct command invocation. If the command really must be dynamic, pass arguments as array members (``"${ARGS[@]}"``) or validate the input against an allow-list before invocation.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-029 — Package install bypasses registry integrity (git / path / tarball source) { #gha-029 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Package installs that pull from ``git+…`` without a pinned commit, from a local path (``./dir``, ``file:…``, absolute paths), or from a direct tarball URL are invisible to the normal lockfile integrity controls. A moving branch head, a sibling checkout the build assumes exists, or a tarball whose hash isn't verified all give an attacker who controls any of those surfaces the ability to substitute code into the build.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-030 — OIDC token requested without environment-protected job { #gha-030 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Pairs with IAM-008 — IAM-008 verifies the AWS-side trust policy pins audience + subject; this rule verifies the GitHub-side workflow can't request the token from any branch without a deployment gate. A misconfiguration on either side defeats the OIDC story.

<div class="pg-rule__rec" markdown>

**Recommended action**

Bind every job that exchanges the GHA OIDC token for cloud credentials to a protected ``environment:`` (e.g. ``environment: production``). Environment protections layer in branch restrictions, required reviewers, and deployment windows that the IdP-side trust policy cannot enforce alone.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-031 — Workflow uses retired set-output / save-state command { #gha-031 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-77</span>
</div>

GitHub deprecated ``::set-output::`` and ``::save-state::`` in October 2022 because they read from the runner's stdout as a control channel. Any tool whose output happens to contain ``::set-output…`` (a CI job's own diagnostic, a downloaded log, an upstream test framework) silently sets a step output. The replacement workflow commands (``$GITHUB_OUTPUT`` / ``$GITHUB_STATE`` files) close that injection channel. Workflows still using the retired commands also depend on a deprecation timer that GitHub has extended several times — they will eventually break.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``echo "::set-output name=X::$VALUE"`` with ``echo "X=$VALUE" >> "$GITHUB_OUTPUT"`` and ``echo "::save-state name=X::$VALUE"`` with ``echo "X=$VALUE" >> "$GITHUB_STATE"``. The old commands stream through the runner's stdout, which lets any log line that happens to start with ``::`` inject into the command channel. The file-redirect forms write to a private file the runner reads after the step exits — no log-line interleaving, no injection.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-032 — run: invokes local script on untrusted-trigger workflow { #gha-032 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

GHA-010 flags ``uses: ./action`` — the *action* form of the same threat. This rule extends to direct shell invocation: ``run: ./scripts/setup.sh`` / ``run: bash scripts/setup.sh`` / ``run: python tools/build.py`` resolve against the checked-out workspace, which on ``pull_request_target`` / ``workflow_run`` is PR-controlled. The attacker ships an edited script and gets a default-branch-privileged shell.

<div class="pg-rule__rec" markdown>

**Recommended action**

Either don't run the script under an untrusted trigger, or split the workflow: keep the privileged work on the default branch (``push`` / ``release`` triggers, no PR fork content), and run untrusted-trigger steps in a separate workflow with no secrets and a minimal ``GITHUB_TOKEN`` scope. Pinning the script via ``uses: org/repo@<sha>`` from a separate trusted repo is the canonical fix.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-033 — Secret value echoed / printed in a run: block { #gha-033 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-532</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Two distinct shapes are flagged: (1) printing a secret context expression directly, e.g. ``echo "${{ secrets.X }}"`` or ``cat <<<${{ secrets.X }}``; (2) printing an env var whose value comes from a secret, when the surrounding step's ``env:`` declares it as ``X: ${{ secrets.X }}``. The first is the obvious foot-gun; the second is the indirect form that slips past lint passes that only scan for ``${{ secrets...}}`` literals.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't print secret values from a script. GitHub's log redaction is a best-effort string match — it doesn't catch base64 / urlencoded / partial substrings, and any caller that retrieves the raw log via the API gets the unredacted stream. If you need to confirm the secret exists, log a boolean (``[ -n "$X" ] && echo set || echo unset``) or a fingerprint (``echo "$X" | sha256sum | head -c8``), never the value itself.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-034 — Reusable workflow called with secrets: inherit { #gha-034 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-272</span>
</div>

Fires on a ``jobs.<id>.uses: ...`` reference whose sibling ``secrets:`` value is the literal string ``inherit``. This is distinct from GHA-025 (which gates on the *pin* of the called workflow): inheritance is a problem even when the call is SHA-pinned, because the surface a compromised callee sees is every caller secret instead of just the named ones. Explicit lists also document the contract — reviewers see exactly which secrets cross the workflow boundary.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``secrets: inherit`` with an explicit list of just the secrets the called workflow actually needs (``secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }``). ``inherit`` passes every secret the caller can see — including ones the downstream workflow has no business reading. A compromised or buggy reusable workflow can then exfiltrate credentials the caller never intended to share.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-035 — github-script step interpolates untrusted context { #gha-035 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

GHA-003 covers ``run:`` blocks where shell expansion is the injection surface. ``actions/github-script@<ref>`` runs the ``script:`` input as Node.js inside an authenticated Octokit context — same threat model, different language. The rule fires when ``script:`` (or the legacy ``previews:`` companion for inline JS) contains a ``${{ github.event.* }}``, ``${{ inputs.* }}``, ``${{ github.head_ref }}``, ``${{ github.ref_name }}``, or any other untrusted context expression — exactly the same catalog GHA-003 uses.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pass attacker-controllable values through ``env:`` and read them inside the script via ``process.env.X`` instead of interpolating ``${{ ... }}`` directly into the script body. GitHub expands the expression *before* the JavaScript engine parses the source, so backticks, quotes, and ``${...}`` characters in the source field break out of the surrounding string and execute as JavaScript with the workflow's GITHUB_TOKEN in scope.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-036 — runs-on interpolates untrusted context { #gha-036 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

GHA-012 catches self-hosted runners that aren't ephemeral; this rule catches the upstream targeting choice. When ``runs-on`` is computed from an untrusted expression, the caller picks where the workflow runs — including any self-hosted label the org owns. A reusable workflow that declares ``runs-on: ${{ inputs.runner }}`` lets a downstream caller route the job onto the production-deploy fleet (or any other privileged label) and execute arbitrary code with the privileges that fleet inherits. The same surface exists via ``workflow_dispatch`` inputs and any ``${{ github.event.* }}`` field that an attacker can populate. The rule walks all three ``runs-on`` shapes — string scalar, list of labels, and the long-form ``{ group, labels }`` dict — and matches the same untrusted-context regex GHA-003 / GHA-035 use.

<div class="pg-rule__rec" markdown>

**Recommended action**

Hard-code ``runs-on:`` to a specific runner label or list of labels. If the choice has to be parameterised across callers, validate the input against an allowlist of known-good labels before the job runs (a small ``if:`` guard at job level), and never accept ``${{ inputs.* }}`` or any ``${{ github.event.* }}`` field as the ``runs-on`` value directly.

</div>

</div>

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
