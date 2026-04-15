# CI gate

`pipeline_check` exits with a non-zero code when the gate fails, so you
can wire it directly into a pipeline step and let the pipeline block the
merge. The gate has four orthogonal fail conditions plus two subtractive
filters; any tripped condition fails the gate (logical OR), and filters
run before the conditions are evaluated.

| Condition        | Flag                      | Fails when…                                             |
|------------------|---------------------------|---------------------------------------------------------|
| Severity         | `--fail-on SEV`           | any effective finding's severity is ≥ `SEV`             |
| Grade            | `--min-grade A\|B\|C\|D`  | overall grade is worse than the bar                     |
| Count cap        | `--max-failures N`        | more than `N` effective failing findings                |
| Specific check   | `--fail-on-check ID`      | a named check is in the effective set (repeat for many) |

**Default gate** when no flag is set: equivalent to `--fail-on CRITICAL`
— a single CRITICAL finding fails the gate, everything else passes.
This replaces the earlier "grade == D → fail" fallback, which muddled
severity with total-count and let CRITICAL findings pass silently on
sparsely-populated repos. Tighten with `--fail-on HIGH` or loosen by
setting any explicit condition (e.g. `--max-failures 9999`) that takes
precedence.

Two subtractive filters narrow what "effective" means:

| Filter       | Flag              | Effect                                                            |
|--------------|-------------------|-------------------------------------------------------------------|
| Baseline     | `--baseline PATH` | Drops every current finding that was already failing in a prior JSON report. |
| Ignore file  | `--ignore-file PATH` | Drops hand-curated suppressions. Defaults to `.pipelinecheckignore`. |

Exit codes are unchanged: `0` pass, `1` gate fail, `2` scanner error.

## Recipes

### Block CRITICAL only (lenient rollout)

```bash
pipeline_check --pipeline aws --fail-on CRITICAL
```

### Enforce a B-or-better grade

```bash
pipeline_check --pipeline aws --min-grade B
```

### Zero-tolerance on specific checks

```bash
pipeline_check --pipeline github --gha-path .github/workflows \
    --fail-on-check GHA-002 --fail-on-check GHA-005
```

### Cap total failures while the team paydown debt

```bash
pipeline_check --pipeline aws --max-failures 5
```

### Only block on *new* regressions (baseline diff)

```bash
# One-time: capture today's state as the baseline (run on main, store as artifact).
pipeline_check --pipeline aws --output json > baseline.json

# Per-PR: fail only on findings not present in the baseline.
pipeline_check --pipeline aws --fail-on HIGH --baseline baseline.json
```

When a finding is in the baseline, it is still reported in the terminal
/ HTML / SARIF output — the baseline affects only the gate decision, so
teams see the whole picture without blocking on it.

### Curate accepted tech debt

Create a `.pipelinecheckignore` file at the repo root:

```
# Shared secrets are rotated OOB, tracked in INFRA-4123.
CB-001:my-legacy-build-project

# We intentionally use AllAtOnce on this canary-only deployment group.
CD-002:my-canary-dg

# Whole check suppressed — being decommissioned this quarter.
PBAC-001
```

Lines are `CHECK_ID` (suppress everywhere) or `CHECK_ID:RESOURCE`
(exact match). `#` starts a comment.

The file is discovered automatically when present; override with
`--ignore-file path/to/file`.

#### Expiring suppressions (YAML format)

Pass `--ignore-file .pipelineguard-ignore.yml` (or any `.yml` / `.yaml`
extension) to use the structured format:

```yaml
- check_id: GHA-001
  resource: .github/workflows/release.yml
  expires: 2026-06-30
  reason: waiting on upstream Dependabot config

- check_id: GL-003
```

`expires` (ISO date) is optional; past the date the suppression no
longer applies and the gate summary emits:

```
[gate] ignore rule expired on 2026-06-30: GHA-001:.github/workflows/release.yml (no longer suppressing)
```

This forces a review rather than letting suppressions rot silently.
`reason` is free-form metadata for reviewers.

### Combine: new findings only, CRITICAL blocks, debt tracked explicitly

```bash
pipeline_check --pipeline aws \
    --baseline artifacts/baseline.json \
    --ignore-file .pipelinecheckignore \
    --fail-on CRITICAL
```

Evaluation order:
1. Failing findings are collected.
2. Baseline suppresses `(check_id, resource)` pairs already failing there.
3. Ignore file suppresses curated entries.
4. Remaining findings are the **effective** set.
5. Gate conditions evaluate against that set.

## Gate summary on stderr

Unless `--output json` is active (stdout must stay clean), every run
prints a short summary to **stderr**:

```
[gate] FAIL
        - 3 finding(s) at or above HIGH (CRITICAL, HIGH) — --fail-on HIGH
        - 7 failing findings exceed --max-failures 5
[gate] 12 finding(s) suppressed by baseline
[gate] 2 finding(s) suppressed by ignore file
```

This makes failure diagnosis immediate without parsing the full JSON.

## How the default interacts with filters

The default `--fail-on CRITICAL` applies to the **effective** set —
after baseline + ignore-file filtering. So a CRITICAL already in the
baseline (or explicitly ignored) does not trip the default gate. Only
as-yet-unacknowledged CRITICALs fail CI.

As soon as any of `--fail-on`, `--min-grade`, `--max-failures`, or
`--fail-on-check` is passed, those govern and the implicit default is
suppressed.

## Scoping to changed files — `--diff-base`

PR pipelines often only want to scan workflows the PR actually touches.
`--diff-base REF` runs `git diff --name-only <REF>...HEAD` and filters
the workflow/pipeline documents down to the changed set before checks
run.

```bash
pipeline_check --pipeline github --diff-base origin/main --fail-on HIGH
```

If git is unavailable or the ref can't be resolved, the flag no-ops
and a full scan runs — over-scanning is safer than silently skipping
everything in CI.

**Provider support:**

- **Workflow providers** (`github`, `gitlab`, `bitbucket`, `azure`) —
  filters the loaded workflow documents to just the changed files.
- **`terraform`** — filters planned resources to those whose module
  directory is touched by the diff. A change in `modules/vpc/main.tf`
  keeps `module.vpc.*` resources, drops unrelated modules. A change
  in a root `*.tf` file keeps root-level resources.
- **`aws`** — rejected with a clear error. Live AWS resources aren't
  bound to git refs; narrow the scope with `--target NAME` instead.

## Baseline from a git ref — `--baseline-from-git REF:PATH`

`--baseline` reads a JSON report from disk. When baselines are stored
in the repo itself (committed artifact) or on a merge-base branch,
`--baseline-from-git REF:PATH` pulls them via `git show`:

```bash
# Gate only on findings not already present on origin/main's baseline.json.
pipeline_check --pipeline github \
    --baseline-from-git origin/main:artifacts/baseline.json \
    --fail-on HIGH
```

Mirrors `--diff-base`: a git failure (unreachable ref, missing path)
degrades to "no baseline" instead of raising. `--baseline` (file path)
takes precedence if both are set.

## Autofix — `--fix`

For a subset of checks, `pipeline_check` can emit the exact source
edit that would remediate the finding. The output is a standard
unified diff on stdout, so it composes with `git apply`:

```bash
pipeline_check --pipeline github --fix | git apply
```

The tool never modifies files directly by default — review the patch,
apply or discard. Currently registered fixers:

| Check    | Fix                                                                  |
|----------|----------------------------------------------------------------------|
| GHA-002  | Adds `persist-credentials: false` under every `actions/checkout` step; handles both `- uses: ...` and named (`- name: ... / uses: ...`) forms. |
| GHA-004  | Inserts `permissions: contents: read` at the top of the workflow.    |
| GHA-008  | Replaces credential-shaped literals with `"<REDACTED>"` and a `TODO(pipelineguard)` marker. Preserves any operator comment on the line. |

Fixers are idempotent — re-running against already-remediated content
emits nothing for that finding. A broken fixer logs to stderr and is
skipped; the rest of the run continues.

### Applying patches directly — `--fix --apply`

When you trust the fixer catalogue, skip the `git apply` round-trip:

```bash
pipeline_check --pipeline github --fix --apply
# [autofix] 3 file(s) modified.
```

`--apply` is opt-in (dry-run by default), only valid with `--fix`, and
reports the modified-file count on stderr. Stdout is untouched by
`--apply` so the rest of the report (terminal / JSON / SARIF) still
behaves the same.

When `--output` is `json`, `sarif`, `html`, or `both`, patches from
plain `--fix` (without `--apply`) route to stderr automatically so
the machine-readable stream on stdout stays valid.

## Selecting checks — globs

`--checks` accepts glob patterns (`fnmatch` syntax), not just exact IDs:

```bash
# All secret-scanning checks across every provider
pipeline_check --pipeline github --checks '*-008'

# Every GitHub check
pipeline_check --pipeline github --checks 'GHA-*'

# A range
pipeline_check --pipeline gitlab --checks 'GL-00[12]'
```

Exact IDs (`--checks GHA-001`) still work unchanged.

## Custom secret patterns

The secret-scanning checks (`GHA-008`, `GL-008`, `BB-008`, `ADO-008`,
`JF-008`) ship with named detectors for **16 vendor token shapes**:

| Detector              | Matches                                                          |
|-----------------------|------------------------------------------------------------------|
| `aws_access_key`      | `AKIA…` / `ASIA…` (16 trailing chars)                            |
| `github_token`        | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` (36+ trailing)        |
| `slack_token`         | `xoxa-` / `xoxb-` / `xoxp-` / `xoxr-` / `xoxs-`                  |
| `jwt`                 | `eyJ…` three-segment header.payload.signature                    |
| `stripe_secret`       | `sk_live_` / `sk_test_` / `rk_live_` / `rk_test_` (24+ payload)  |
| `stripe_publishable`  | `pk_live_` / `pk_test_` (24+ payload)                            |
| `google_api_key`      | `AIza…` (35 trailing chars)                                      |
| `npm_token`           | `npm_…` (36 chars)                                               |
| `pypi_token`          | `pypi-AgEIcHlwaS5vcmc…` (50+ trailing)                           |
| `docker_hub_pat`      | `dckr_pat_…` (20+ trailing)                                      |
| `gitlab_pat`          | `glpat-…` (20 trailing)                                          |
| `gitlab_deploy_token` | `gldt-…` (20+ trailing)                                          |
| `sendgrid`            | `SG.<22>.<43>`                                                   |
| `anthropic_api_key`   | `sk-ant-api03-…` (90+ trailing)                                  |
| `digitalocean_token`  | `dop_v1_…` (64 hex)                                              |
| `hashicorp_vault`     | `hvs.…` (24+ trailing)                                           |

Plus a multi-line `private_key` detector that fires on any
`-----BEGIN PRIVATE KEY-----` block (RSA, EC, OPENSSH, PGP).

Each hit is labelled with the matched detector — finding descriptions
read like ``aws_access_key:AKIA…LE, stripe_secret:sk_l…23`` so
operators can write **targeted** ignore rules per-detector instead of
suppressing the whole `*-008` check.

**Placeholder suppression**: tokens containing obvious documentation
markers (`<your-key>`, `XXXXX`, `replace_me`, `dummy_key`, …) are
silently skipped before reaching the user. The canonical AWS docs
example `AKIAIOSFODNN7EXAMPLE` is **deliberately NOT** suppressed —
if it shows up in a real workflow it almost always means someone
copy-pasted from docs and forgot to substitute.

Add org-specific patterns with `--secret-pattern REGEX` (repeat for
multiple) or a `secret_patterns:` list in the config file. User
patterns share a single `custom:` label:

```bash
pipeline_check --pipeline github \
    --secret-pattern '^acme_[a-f0-9]{32}$' \
    --secret-pattern '^xoxo-[A-Z0-9]{20,}$'
```

Patterns are Python regex syntax; anchor with `^...$` to whole-token
match. Tokens are extracted from every string in the workflow, split
on whitespace and common shell separators. See
[config.md](config.md#schema) for the config-file form.
