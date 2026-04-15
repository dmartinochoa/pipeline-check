# Scoring model

Every finding is weighted by severity. The overall grade is a function of
the weighted pass rate, with an extra penalty for CRITICAL failures so a
single critical issue cannot be masked by many low-severity passes.

## Weights

| Severity  | Weight |
|-----------|--------|
| CRITICAL  | 20     |
| HIGH      | 10     |
| MEDIUM    | 5      |
| LOW       | 2      |
| INFO      | 0      |

INFO findings are informational and do not move the score.

## Formula

```
base          = (sum of weights for passing checks) / (sum of all weights) * 100
critical_pen  = 5 points per CRITICAL failure
score         = clamp(round(base - critical_pen), 0, 100)
```

If every finding is INFO (or there are none), the score is 100.

## Grade bands

| Score   | Grade |
|---------|-------|
| ≥ 90    | A     |
| ≥ 75    | B     |
| ≥ 60    | C     |
| < 60    | D     |

## Exit codes

| Code | Meaning        |
|------|----------------|
| `0`  | Gate passed    |
| `1`  | Gate failed    |
| `2`  | Scanner error  |

The default gate is `--fail-on CRITICAL` — one CRITICAL finding in the
effective set (after baseline + ignore filtering) fails CI. The grade
is *not* the default gate criterion; use `--min-grade` to gate on it
explicitly. See [ci_gate.md](ci_gate.md) for the full gate contract.

The implementation lives in
[`pipeline_check/core/scorer.py`](../pipeline_check/core/scorer.py) and
[`pipeline_check/core/gate.py`](../pipeline_check/core/gate.py).
