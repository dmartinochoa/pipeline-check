# Cross-scanner comparison matrix

The matrix that evaluates pipeline-check vs Zizmor, Poutine,
Checkov, KICS, and Trivy on the same vulnerable-by-design cases.
Not yet built.

## Status

`run.py` evaluates pipeline-check's recall against each case. The
cross-scanner harness — installing the four other scanners,
running each against the same fixture set, normalizing their
outputs into a comparable shape — is its own surface and not
shipped here.

## What it will look like

Per-case rows × per-scanner columns. The cell is the recall
percentage for that scanner on that case's expected check IDs
(after normalizing the rule IDs to a common attack-pattern
taxonomy — neither Trivy's `AVD-AWS-*` nor Checkov's `CKV2_*`
match pipeline-check's `GHA-001` directly).

```
Case                          PC%  Zizmor%  Poutine%  Checkov%  KICS%  Trivy%
unpinned-supply-chain         100  …
pwn-request                   100
literal-credentials           100
kubernetes-blast-radius       100
```

Columns where a scanner doesn't cover the case at all (e.g.,
Zizmor only scans GHA workflows; the K8s case is N/A) get a
`—` rather than 0%.

## Why we're not shipping it yet

  * **Maintenance surface.** Each scanner brings its own install
    quirks, version churn, and SARIF-shape weirdness. The
    cross-scanner harness has to track every one of those.
  * **Honesty cost.** Picking the cases unilaterally puts a
    thumb on the scale. The benchmark only earns credibility
    when the case selection is defensible — typically by being
    sourced from advisory write-ups rather than from "what
    pipeline-check happens to fire on."
  * **CI cost.** Running five scanners on every PR turns a
    15-second test suite into a multi-minute build with multiple
    Docker pulls. The harness probably wants to run on a
    schedule rather than on every commit.

## When to ship it

Three signals would justify the build:

  1. Adopters consistently asking "why should I pick this over
     Zizmor / Poutine?" (the case-selection question stops being
     speculative).
  2. A new pipeline-check feature whose value claim depends on a
     comparison ("the only OSS scanner that catches X" — needs
     proof).
  3. A second person willing to maintain the harness. Until
     then, it's a single point of churn and arguably worse than
     no comparison at all.

In the meantime, `bench/run.py` carries pipeline-check's
own coverage proof and is the single source the README's recall
claims pull from.
