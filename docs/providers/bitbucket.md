# Bitbucket Pipelines provider

Parses a `bitbucket-pipelines.yml` from disk — no network calls, no
Bitbucket API token, no runner required.

## Producer workflow

```bash
# --bitbucket-path is auto-detected when bitbucket-pipelines.yml is present
# at cwd; the CLI announces the pick on stderr.
pipeline_check --pipeline bitbucket

# …or pass it explicitly.
pipeline_check --pipeline bitbucket --bitbucket-path bitbucket-pipelines.yml
```

A directory is also accepted; the loader picks up every
`bitbucket-pipelines.yml` / `bitbucket-pipelines.yaml` found under it.

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Step coverage

Steps are walked across every pipeline category Bitbucket supports:

- `pipelines.default`
- `pipelines.branches.<pattern>`
- `pipelines.pull-requests.<pattern>`
- `pipelines.tags.<pattern>`
- `pipelines.custom.<name>`

…and through both the list form and dict form of `parallel:` (incl.
`fail-fast`), plus `stage:` wrappers. Each step's location is reported
as e.g. `default[0]`, `branches.main[1].parallel[0]`.

## What it covers

| Check   | Title                                                         | Severity |
|---------|---------------------------------------------------------------|----------|
| BB-001  | `pipe:` action not pinned to exact version                    | HIGH     |
| BB-002  | Script injection via attacker-controllable context            | HIGH     |
| BB-003  | Variables / definitions contain literal secrets               | CRITICAL |
| BB-004  | Deploy step missing `deployment:` environment gate            | MEDIUM   |
| BB-005  | Step has no `max-time` — unbounded build                      | MEDIUM   |
| BB-006  | Artifacts not signed                                          | MEDIUM   |
| BB-007  | SBOM not produced                                             | MEDIUM   |

---

## BB-001 — `pipe:` action not pinned to exact version
**Severity:** HIGH · CICD-SEC-3 Dependency Chain Abuse

Pipes published to the Atlassian marketplace are versioned Docker
images. Floating major tags (`atlassian/aws-s3-deploy:1`) can roll
forward silently; full semver (`:1.4.0`) or a digest (`@sha256:…`) is
pinned.

**Recommended actions**
- Pin every `pipe:` to a full semver tag or an immutable SHA.
- Track pipe updates explicitly (Dependabot-style) rather than letting
  `:1` drift.

## BB-002 — Script injection via attacker-controllable context
**Severity:** HIGH · CICD-SEC-4 Poisoned Pipeline Execution

Bitbucket exposes predefined variables whose values can be controlled
by anyone who can push a ref or open a PR: `$BITBUCKET_BRANCH`,
`$BITBUCKET_TAG`, `$BITBUCKET_PR_DESTINATION_BRANCH`, `$BITBUCKET_PR_ID`,
`$BITBUCKET_BOOKMARK`. Inlining them into shell commands allows a
crafted branch/tag name to execute.

**Recommended actions**
- Always double-quote the interpolation (`"$BITBUCKET_BRANCH"`); bare
  `$BITBUCKET_BRANCH` is flagged.
- Avoid passing these values to `eval`, `sh -c`, or unquoted command
  arguments.
- Quoted assignment (`BRANCH="$BITBUCKET_BRANCH"`) is exempt — it
  captures the value without executing it.

## BB-003 — Variables / definitions contain literal secrets
**Severity:** CRITICAL for AWS access keys, else HIGH · CICD-SEC-6

Scans `definitions.variables` and any step `variables:` for AWS keys
(`AKIA…`) and string values under secret-like keys (`password`,
`secret`, `token`, `api_key`, `apikey`, `private_key`, etc.).

**Recommended actions**
- Store credentials as **Repository** or **Deployment** Variables in
  Bitbucket's Pipelines settings with the **Secured** flag set; the
  YAML references them by name.
- Prefer short-lived OIDC for cloud access.

## BB-004 — Deploy step missing `deployment:` environment gate
**Severity:** MEDIUM · CICD-SEC-1 Insufficient Flow Control

A step whose name matches `deploy / release / publish / promote`, or
whose script contains a deploy-style pipe, is flagged unless it declares
`deployment: production` (or `staging` / `test`). Without it, Bitbucket
cannot enforce deployment-scoped variables, approvals, or history.

**Recommended actions**
- Add `deployment: production` (or the appropriate tier) to the step.
- Configure the matching environment in the repo's **Deployments**
  settings with required reviewers and secured variables.

## BB-005 — Step has no `max-time` — unbounded build
**Severity:** MEDIUM · CICD-SEC-7 Insecure System Configuration

Steps without `max-time:` run until Bitbucket's 120-minute default
kills them. Bounded runtime limits the blast radius of a compromised
build and prevents runaway minute consumption.

**Recommended actions**
- Add `max-time: <minutes>` to each step, sized to the 95th percentile
  of historical runtime plus margin.
- Track budget overruns rather than silently doubling limits.

---

## Adding a new Bitbucket Pipelines check

1. Add a method to `pipeline_check/core/checks/bitbucket/pipelines.py`
   returning a `Finding` with ID `BB-<NNN>`; register the call in
   `_check_doc`.
2. Add mappings for the new ID in the relevant standards under
   `pipeline_check/core/standards/data/*.py`.
3. Add tests under `tests/bitbucket/test_pipelines.py` plus an insecure
   / secure fixture pair under `tests/fixtures/workflows/bitbucket/` and
   an expected-ID entry in `tests/test_workflow_fixtures.py`.
