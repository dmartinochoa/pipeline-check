# PR-time finding delta: `--pr-diff`

`--pr-diff REF` re-scans both sides of a pull request and emits a
Markdown summary of which findings the branch *introduced*,
*resolved*, or left *preserved* against the base ref. The output is
shaped for a single PR-review comment body: one verdict line, one
counts line (`+N` / `-N` / `=N`), then the introduced findings
grouped by severity.

Use this when you want PR review to focus on the new posture damage
the branch is doing, not the whole legacy backlog. For scoping which
*files* get scanned in the first place (a different concern), see
[`--diff-base`](ci_gate.md#scoping-to-changed-files-diff-base).

## How it works

1. **HEAD** is scanned in-process. The findings you would normally
   gate on become one half of the comparison, no subprocess overhead.
2. **BASE** is materialized in a throwaway
   [`git worktree`](https://git-scm.com/docs/git-worktree) under the
   system temp dir and scanned out of process via
   `python -m pipeline_check --output json`. The subprocess inherits
   the parent's `--pipeline` / path / `--checks` / `--standard` /
   `--custom-rules` / `--severity-threshold` / `--min-confidence` /
   `--ignore-file` flags through an explicit forwarder, so each side
   runs the same rule set against its own tree.
3. The two finding sets pair on a `(check_id, resource)` fingerprint
   with **multiset semantics**: if base has one `GHA-001` on
   `ci.yml` and HEAD has two, the count of new findings is one, not
   zero. The resource is POSIX-normalized and lowercased so a base
   scan on Linux and a HEAD scan on Windows still match.
4. Line numbers are deliberately excluded from the fingerprint, so
   line shifts on otherwise-unchanged code do not produce false
   "introduced" rows. This is the same convention `--baseline` and
   `--baseline-from-git` already use.

## Basic invocation

Local diff vs. `main`:

```bash
pipeline_check --pipeline github --pr-diff origin/main
```

Markdown goes to stdout by default. Pass `--output-file PATH` to
write it to disk instead; a one-line stats summary still prints to
stderr either way.

In a GitHub Actions PR job, fan the output into the run summary so
reviewers see the delta without having to click into logs:

```yaml
on:
  pull_request:

permissions:
  contents: read

jobs:
  pipeline-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # required so the base ref is in the local repo
      - run: pip install pipeline-check
      - run: |
          pipeline_check --pipeline github \
            --pr-diff origin/${{ github.base_ref }} \
            --output-file pr-diff.md \
            --fail-on HIGH
          cat pr-diff.md >> "$GITHUB_STEP_SUMMARY"
```

`fetch-depth: 0` matters: `actions/checkout@v4` defaults to a
shallow clone, and a base ref that wasn't in the fetched slice
degrades the diff (see *Degraded modes* below).

## Gating on introduced findings

`--pr-diff` is informational by default (exits 0 regardless of what
the branch added). Combine it with `--fail-on SEV` to gate the PR
on new posture damage only:

```bash
pipeline_check --pipeline github --pr-diff origin/main --fail-on HIGH
```

The gate evaluates against the **introduced** set only. Preserved
findings explicitly do not gate, that's the point of running diff
mode: the contributor isn't on the hook for problems they didn't
add. Resolved findings are reported but never gate either.

`--pr-diff` is mutually exclusive with `--inventory-only`, `--fix`,
the `--baseline*` family, and `--diff-base` (each carries a
competing notion of "what to compare").

## Degraded modes

The mode is total: it never raises on git or subprocess failure.
When the base side can't be produced cleanly, every HEAD finding
shows up as introduced and the comment carries a `[!WARNING]`
callout naming what failed. Common cases:

- **Shallow clone, base ref not fetched.** The hint surfaced by the
  warning names the actionable fix per CI platform
  (`fetch-depth: 0` for `actions/checkout`, `GIT_DEPTH: 0` for
  GitLab CI, `git fetch --unshallow` locally).
- **`git worktree add` failure.** Surfaced verbatim from git's
  stderr so the user has a concrete error to grep for.
- **Base subprocess JSON parse failure.** A stderr warning that
  leaked into stdout, a non-zero exit code 2 or 3, or a missing
  `findings` array all show up as a single named warning.

Every degraded mode still produces *some* Markdown output, so a CI
lane behind a shallow fetch still posts a useful PR comment rather
than aborting silently.

## Limits

| Limit | Value | Why |
|---|---|---|
| Base subprocess timeout | 600s | Caps the runaway worst case; the HEAD scan has no cap because the parent process doesn't either. |
| Preserved-findings render cap | 50 | A long-lived branch can accumulate hundreds of preserved findings; embedding them all risks the GitHub 65k-char comment-body ceiling. Past the cap the rendered subset is the 50 most severe and a `+N more` footer carries the omitted count. |

Neither limit is configurable today; if either bites, file an issue
with the scenario so the cap can be revisited.

## See also

- **[`--diff-base REF`](ci_gate.md#scoping-to-changed-files-diff-base)**
  scopes a *single* scan to files the branch touched. Use it to make
  the scan itself faster on a feature branch; use `--pr-diff` to
  reason about the *delta* between two scans.
- **[`--baseline-from-git REF:PATH`](ci_gate.md#baseline-from-a-git-ref-baseline-from-git-refpath)**
  suppresses findings already failing in a committed baseline from
  the gate. It runs one scan against HEAD and compares against a
  prior JSON report; `--pr-diff` runs two scans (one per ref) and
  produces a Markdown delta report.
- **[`pipeline-check-pr` composite action](https://github.com/dmartinochoa/pipeline-check/tree/master/.github/actions/pipeline-check-pr)**
  posts *one review comment per finding* inline on the changed
  lines via the GitHub review API. Use it when you want per-line
  discussion; use `--pr-diff` when you want a single delta summary
  in the PR thread.
