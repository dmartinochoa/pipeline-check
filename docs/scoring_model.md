## Scoring Model

| Severity | Weight |
|---|---|
| CRITICAL | 20 |
| HIGH | 10 |
| MEDIUM | 5 |
| LOW | 2 |
| INFO | 0 |

**Base score** = `(sum of weights for passing checks) / (total weights) × 100`

An additional **−5 points** is deducted per CRITICAL failure to prevent critical issues being masked by many low-severity passes.

| Grade | Score |
|---|---|
| A | ≥ 90 |
| B | ≥ 75 |
| C | ≥ 60 |
| D | < 60 |