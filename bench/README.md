# pipeline-check-bench

Vulnerable-by-design benchmark fixtures. Each case folder under
`cases/` is a self-contained intentionally-vulnerable repo (or
slice of one) anchored to a real attack pattern from the OWASP
CI/CD Top 10. Each case ships:

  * Fixture files — workflows, Dockerfiles, manifests, the actual
    bytes a vulnerable repo would have.
  * `expected.txt` — newline-delimited list of `check_id` values
    pipeline-check is asserted to fire on, one per line. Order
    doesn't matter; comments (`#` prefix) and blank lines are
    skipped. **Chain check_ids** (`AC-NNN` / `XPC-NNN`) are valid
    entries: the runner evaluates the chain engine over the
    union of per-provider findings, so a case that exercises a
    multi-finding correlation can assert the chain fires
    alongside the rules. Asserting the chain proves the case
    exercises pipeline-check's correlation tier — the project's
    wedge — not just the rule pack.
  * (Optional) `notes.md` — narrative explaining the vulnerability,
    the real-world incident the case is anchored to, and what a
    fix would look like.
  * (Optional) `scm_config.json` + `scm/` directory — SCM provider
    fixtures for cases that exercise the GitHub-API-driven
    rules. `scm_config.json` declares
    `{"owner": "...", "name": "..."}`; `scm/` carries JSON files
    matching the API endpoint paths with `/` collapsed to `_`
    (e.g. `repos_octocat_demo-app.json`). The runner uses
    `DiskSCMFetcher` so the bench stays hermetic — no network,
    no token. Omitting an endpoint's file means the fetcher
    returns `None`, which most rules treat as "feature not
    enabled" (the same behavior as a real 404).

## Running

From the repo root:

    python bench/run.py                 # all cases, recall table
    python bench/run.py --case <name>   # one case
    python bench/run.py --json          # machine-readable output

The runner iterates each case, invokes pipeline-check via the
Python API (no subprocess overhead), compares the emitted
`check_id`s against `expected.txt`, and prints:

  * Per-case recall (fraction of expected check IDs that fired).
  * Per-case extras (check IDs that fired but weren't in the
    expected list — usually fine, sometimes a sign the case is
    over-broad).
  * A coverage table summing the union across cases.

Exit code is zero when every case hits 100 % recall. Used as a
regression gate in `tests/test_bench.py`.

## Why this exists

A scanner's catalog count is meaningless without coverage proof.
"450+ checks" answers the wrong question; the right question is
"do you fire on the attacks that actually happen in the wild?"
This benchmark is the answer pipeline-check ships with.

The same case fixtures will eventually power a comparison matrix
(pipeline-check vs Zizmor, Poutine, Checkov, KICS, Trivy) so
adopters can verify the wedge claim before installing rather
than taking the README's word for it. That harness lives outside
this directory; tracking under `COMPARISON.md`.

## Adding a case

1. Create `bench/cases/<slug>/` with the vulnerable fixture(s).
2. Run `python bench/run.py --case <slug> --suggest` to get a
   pre-populated `expected.txt` from the current scan output.
3. Hand-edit `expected.txt` to keep ONLY the check IDs the case
   is intended to demonstrate (drop incidental fires from
   unrelated rules).
4. Add a `notes.md` if the vulnerability has a real-world
   anchor worth citing.
5. Open a PR. The `tests/test_bench.py` regression test will
   auto-pick the new case up.

The case slug should describe the attack pattern, not the
fix or the rule ID — `unpinned-supply-chain` ages better than
`gha-001-fix`.

## Non-goals

  * Not a real-world repo simulator. Cases are minimal —
    enough to trigger the rule, not enough to clone and run.
  * Not a fuzz target. The expected list is hand-curated; rule
    drift is caught deliberately, not statistically.
  * Not a security advisory database. Real-world incidents are
    cited under each case's `notes.md` for context, but the
    canonical source for incident detail is the cited
    advisory / write-up.
