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
