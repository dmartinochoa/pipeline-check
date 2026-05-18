# goats/

Per-goat curation slots for `bench/goat_runner.py`. The runner reads
three files per goat:

  * **`expected.txt`** — hand-curated check IDs the goat is intended
    to demonstrate. One per line; lines starting with `#` are
    comments. The runner fails if a listed ID does not fire.
    Empty file means "no recall claim yet"; the goat still
    contributes drift signal vs `baseline.json`.

  * **`allowlist.txt`** — known false-positives. Format:
    `CHECK-ID  # justification`. Allowlisted IDs that fire don't
    count against the FP rate and don't gate the bench.

  * **`baseline.json`** — last committed scan output (failing
    findings only, trimmed to `check_id` + `severity` + `resource`).
    The runner regenerates this on `--update-baseline` and treats
    every commit of it as a deliberate posture update.

`findings.json` (latest per-run scan output) is gitignored.

## Seeding a new goat

1. Add the goat to `bench/goats.yml`.
2. Run `python bench/goat_runner.py --goat <slug> --suggest` to
   write a starting `expected.txt` populated with every check ID
   the current scan fires.
3. Hand-edit `expected.txt` down to the IDs the goat *intends* to
   teach. Drop incidental fires from unrelated rules.
4. Run `python bench/goat_runner.py --goat <slug> --update-baseline`
   to record the current scan as the drift reference.
5. Commit `expected.txt`, `allowlist.txt` (empty is fine), and
   `baseline.json`.

The CI workflow `.github/workflows/goat-bench.yml` runs the whole
corpus on a nightly cron and on every PR that touches the rule
pack or the bench code.

## Curation policy

`expected.txt` arrives incrementally. A goat with an empty
`expected.txt` is a valid corpus entry on day one — the
drift-vs-baseline signal alone catches accidental rule regressions.
The recall claim ("we catch what the goat is teaching") is a
separate, slower investment per goat.

`allowlist.txt` should always carry a justification per entry. If
the justification can't be written in one short line, the FP
deserves a rule fix instead of an allowlist entry.
