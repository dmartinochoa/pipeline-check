# Findings-history dashboard

`pipeline_check history` renders a self-contained HTML page that
visualizes posture over time from a directory of past scan outputs.
No JavaScript, no CDN, no server — the output is a single static
`.html` file you can open locally, email, or commit to a
posture-history branch.

```bash
# Snapshot a scan into the history directory.
pipeline_check --output json \
    --output-file .pipeline-check-history/scan-$(date +%Y%m%d-%H%M%S).json

# Render the dashboard over the entire history.
pipeline_check history
```

The default reads `.pipeline-check-history/` and writes
`pipeline-check-history.html` next to the working directory.

## What's on the page

- **Per-severity trend graphs** — inline SVG line charts, one line
  per severity (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`), showing
  failing-finding counts over the history window.
- **Score-over-time trace** — the 0-100 grade input plotted across
  the same time axis so trend graphs and score line up.
- **Top-N firing rules** — a burn-down table ranking rules by total
  failed findings across the window. `--top-rules N` adjusts the
  cardinality (default 15, range 1-100).
- **Resource heatmap** — most-burdened resources (files / accounts /
  repos) inferred from the `resource` field on failing findings.

## CLI options

```bash
pipeline_check history --dir .pipeline-check-history \
                       --output pipeline-check-history.html \
                       --top-rules 15
```

| Flag         | Default                          | Notes |
|--------------|----------------------------------|-------|
| `--dir`      | `.pipeline-check-history`        | Directory of timestamped scan-output JSON files. |
| `--output`   | `pipeline-check-history.html`    | Destination for the rendered HTML page. |
| `--top-rules`| `15` (range 1-100)               | Number of rules to show in the burn-down table. |

## Snapshot file naming

The renderer extracts a timestamp from each file in this order:

1. `YYYYMMDD-HHMMSS` substring anywhere in the filename. Matches
   the recommended convention `scan-20260519-120000.json`.
2. `YYYY-MM-DD` or `YYYY-MM-DDTHH-MM-SS` (the ISO-style alternative).
3. File modification time (fallback).

Files without a parseable timestamp via 1 or 2 use mtime; files whose
JSON can't be parsed are skipped with a warning printed to stderr so
the dashboard renders the clean subset and you see what was dropped.

## Wiring it into CI

Run a scan in CI and commit the snapshot to a long-lived history
branch (or upload to an artifact / S3 prefix):

```yaml
# .github/workflows/posture-history.yml
on:
  schedule:
    - cron: "0 6 * * *"   # daily at 06:00 UTC

jobs:
  snapshot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install pipeline-check
      - run: |
          mkdir -p .pipeline-check-history
          pipeline_check --pipeline github --output json \
              --output-file ".pipeline-check-history/scan-$(date +%Y%m%d-%H%M%S).json"
      - run: pipeline_check history
      - uses: actions/upload-artifact@v4
        with:
          name: pipeline-check-history
          path: pipeline-check-history.html
```

The dashboard input is the standard `--output json` payload. Any
existing JSON archive (S3 bucket, posture-history branch, artifact
store) can feed it — `history` does not require the snapshots to
have been produced on the same machine.
