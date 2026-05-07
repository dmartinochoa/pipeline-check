# pipeline-check (PR review)

Composite GitHub Action that runs `pipeline_check` on a pull request
and posts review comments on the changed lines.

## Usage

```yaml
name: pipeline-check
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write   # required for review comments

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dmartinochoa/pipeline-check/.github/actions/pipeline-check-pr@v1
        with:
          # All inputs are optional. Defaults are sensible for most repos.
          pipeline: auto
          severity-threshold: MEDIUM
          comment-mode: per-finding
```

## What it does

1. Runs the scanner with `--output json`.
2. Lists the lines this PR added or modified via `gh api repos/.../pulls/{n}/files`.
3. For every failing finding, looks up its `locations[]` (line-precise
   when the rule supports it).
4. Posts one PR review comment per finding/location whose `(path, line)`
   matches a touched line.
5. Anything without a matching diff line — and any rule that didn't
   emit structured locations — lands in a single PR-level summary
   comment, which is upserted (never duplicated) on subsequent runs.

## Idempotency

Each review comment carries a hidden marker:

```
<!-- pipeline-check-id: <check_id>:<sha1(path:line:check_id)> -->
```

On re-run, the entrypoint:

- finds existing bot comments by their marker,
- patches comments whose body changed,
- deletes comments whose finding disappeared,
- creates only genuinely new comments.

The summary uses a single fixed marker so it's also upserted.

## Failure modes

- **Fork PRs / read-only token.** Posting comments fails. The action
  always also writes the same content to `$GITHUB_STEP_SUMMARY`, so
  the finding list is visible on the job page even when the PR can't
  be commented on.
- **`gh api` rate limit.** Same fallback — step summary survives.
- **No line precision.** Findings without `locations[]` fall through
  to the summary comment automatically.

## Inputs

| Input                | Default                  | Notes                                                                           |
|----------------------|--------------------------|---------------------------------------------------------------------------------|
| `pipeline`           | `auto`                   | Provider name. `auto` lets the scanner detect from cwd.                         |
| `path`               | `.`                      | Forwarded to `--<provider>-path`.                                               |
| `severity-threshold` | `MEDIUM`                 | Comments only fire at this severity or above.                                   |
| `resolve-remote`     | `false`                  | Pass `--resolve-remote` to scan reusable workflow callees.                      |
| `comment-mode`       | `per-finding`            | `per-finding` posts one comment per location; `summary` posts a single comment. |
| `gh-token`           | `${{ github.token }}`    | Token used to post comments. Needs `pull-requests: write`.                      |

## Outputs

| Output           | Description                                |
|------------------|--------------------------------------------|
| `findings-count` | Total findings emitted (passing + failing).|
| `failed-count`   | Findings whose `passed=false`.             |

## Trigger choice

Use `pull_request`, not `pull_request_target`. The latter runs with
elevated permissions on PRs from forks, which the entrypoint doesn't
need — and which would let untrusted YAML influence what gets posted
back to the PR. The default `GITHUB_TOKEN` from a `pull_request`
trigger on a fork is read-only, which is fine: the action falls back
to the job summary in that case.

## Privacy

The action does not phone home. The only network calls it makes are
to the GitHub API for the repository it's already running on, plus
(if `resolve-remote: true`) to `raw.githubusercontent.com` for the
reusable-workflow callees the scanner is asked to follow.
