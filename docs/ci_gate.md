# CI gate

`pipeline_check` exits with a non-zero code when the gate fails, so you
can wire it directly into a pipeline step and let the pipeline block the
merge. The gate has six orthogonal conditions; any tripped condition
fails the gate (logical OR).

| Condition        | Flag                      | Fails when…                                             |
|------------------|---------------------------|---------------------------------------------------------|
| Severity         | `--fail-on SEV`           | any effective finding's severity is ≥ `SEV`             |
| Grade            | `--min-grade A\|B\|C\|D`  | overall grade is worse than the bar                     |
| Count cap        | `--max-failures N`        | more than `N` effective failing findings                |
| Specific check   | `--fail-on-check ID`      | a named check is in the effective set (repeat for many) |
| Legacy default   | _(no gate flags)_         | grade is `D` (preserved for backward compatibility)     |

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

## Interaction with the legacy default

If **no** explicit gate flag is set and no filters are applied,
pipeline_check falls back to the original behavior: fail iff grade is
`D`. As soon as any of `--fail-on`, `--min-grade`, `--max-failures`,
`--fail-on-check`, `--baseline`, or `--ignore-file` is passed, the
legacy default is off — the explicit gate governs.
