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
everything in CI. `--diff-base` only affects workflow-style providers
(`github`, `gitlab`, `bitbucket`, `azure`); AWS and Terraform builds
scan their full context regardless.

## Autofix — `--fix`

For a subset of checks, `pipeline_check` can emit the exact source
edit that would remediate the finding. The output is a standard
unified diff on stdout, so it composes with `git apply`:

```bash
pipeline_check --pipeline github --fix | git apply
```

The tool never modifies files directly — review the patch, apply or
discard. Currently registered fixers:

| Check    | Fix                                                |
|----------|----------------------------------------------------|
| GHA-004  | Inserts `permissions: contents: read` at the top   |

Fixers are idempotent — re-running against already-remediated content
emits nothing for that finding.

## Custom secret patterns

The secret-scanning checks (`GHA-008`, `GL-008`, `BB-008`, `ADO-008`)
ship with detectors for AWS access keys, GitHub tokens, Slack tokens,
and JWTs. Add org-specific patterns with `--secret-pattern REGEX`
(repeat for multiple) or a `secret_patterns:` list in the config file:

```bash
pipeline_check --pipeline github \
    --secret-pattern '^acme_[a-f0-9]{32}$' \
    --secret-pattern '^xoxo-[A-Z0-9]{20,}$'
```

Patterns are Python regex syntax; anchor with `^...$` to whole-token
match. Tokens are extracted from every string in the workflow, split
on whitespace and common shell separators. See
[config.md](config.md#schema) for the config-file form.
