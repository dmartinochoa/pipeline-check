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

`pipeline_check` exits non-zero on grade D so it works as a CI gate:

| Code | Meaning        |
|------|----------------|
| `0`  | Grade A/B/C    |
| `1`  | Grade D        |
| `2`  | AWS API error  |

The implementation lives in
[`pipeline_check/core/scorer.py`](../pipeline_check/core/scorer.py).
