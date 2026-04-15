# GitHub Actions provider

Parses workflow YAML files under a ``.github/workflows`` directory — no
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

| Check    | Title                                           | Severity |
|----------|-------------------------------------------------|----------|
| GHA-001  | Action not pinned to commit SHA                 | HIGH     |
| GHA-002  | `pull_request_target` checks out PR head        | CRITICAL |
| GHA-003  | Script injection via untrusted context          | HIGH     |
| GHA-004  | Workflow has no explicit permissions block      | MEDIUM   |
| GHA-005  | AWS auth uses long-lived access keys            | MEDIUM   |

---

## GHA-001 — Action not pinned to commit SHA
**Severity:** HIGH · CICD-SEC-3 Dependency Chain Abuse

Every `uses:` reference should pin a specific 40-char commit SHA. Tag and
branch refs (`@v4`, `@main`) can be silently moved to malicious commits by
whoever controls the upstream repository — a third-party action
compromise will propagate into the pipeline on the next run.

**Recommended actions**
- Replace tag/branch refs with the full commit SHA of the target release.
- Use Dependabot or StepSecurity `pin-github-action` to keep the pins fresh.
- Add a comment next to the SHA indicating the intended tag for human review.

## GHA-002 — `pull_request_target` checks out PR head
**Severity:** CRITICAL · CICD-SEC-4 Poisoned Pipeline Execution

`pull_request_target` runs with a write-scope GITHUB_TOKEN and access to
repository secrets — deliberately so, since it's how labeling and
comment-bot workflows work. When the same workflow then explicitly
checks out the PR head (`ref: ${{ github.event.pull_request.head.sha }}`
or `.ref`) it executes attacker-controlled code with those privileges.

**Recommended actions**
- Switch to `pull_request` for any workflow that must build untrusted code.
- Split privileged work into a separate `pull_request_target` job that only
  labels or comments; do the build in a `pull_request`-triggered job.
- If PR-head code must run under `pull_request_target`, restrict the job
  to the minimum secrets it needs and require manual approval via
  environments.

## GHA-003 — Script injection via untrusted context
**Severity:** HIGH · CICD-SEC-4 Poisoned Pipeline Execution

Interpolating attacker-controlled context fields (PR title/body, issue
body, comment body, commit message, discussion body, head branch name)
directly into a `run:` block is shell injection. GitHub expands
`${{ github.event.* }}` *before* shell quoting, so any backtick, `$()`,
or `;` in the source field executes.

**Recommended actions**
- Pass the untrusted value through an intermediate `env:` variable, then
  reference that variable from the shell script — environment variables
  are quoted by the shell, expressions are not.
- Prefer `actions/github-script` over shell interpolation when handling
  event metadata.

## GHA-004 — Workflow has no explicit permissions block
**Severity:** MEDIUM · CICD-SEC-5 Insufficient PBAC

Without an explicit `permissions:` block (either top-level or per-job),
the GITHUB_TOKEN inherits the repository's default scope — typically
`write`. A compromised step receives far more privilege than it needs.

**Recommended actions**
- Add `permissions: { contents: read }` at the top level of every workflow.
- Grant additional scopes (`issues: write`, `pull-requests: write`,
  `id-token: write`, …) only on the specific jobs that need them.

## GHA-005 — AWS auth uses long-lived access keys
**Severity:** MEDIUM · CICD-SEC-6 Insufficient Credential Hygiene

Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` secrets in
GitHub Actions can't be rotated on a fine-grained schedule and remain
valid until manually revoked. OIDC with `role-to-assume` yields
short-lived credentials per workflow run.

**Recommended actions**
- Configure GitHub as an OIDC IdP in AWS IAM.
- Use `aws-actions/configure-aws-credentials` with `role-to-assume` and
  `permissions: { id-token: write }`.
- Remove the static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY repository
  secrets once OIDC is in place.

---

## Adding a new GitHub Actions check

1. Add a check method to `pipeline_check/core/checks/github/workflows.py`
   returning a `Finding`. Give it an ID of the form `GHA-<NNN>` and
   register the call in `_check_workflow`.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py`.
3. Add tests under `tests/github/test_workflows.py`.

Similar YAML-based providers exist for **GitLab CI** and **Bitbucket
Pipelines** — see [gitlab.md](gitlab.md) and [bitbucket.md](bitbucket.md).
For a new provider (Azure Pipelines, Jenkins, …) follow the contract
documented in `docs/providers/README.md`.
