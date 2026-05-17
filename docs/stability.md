# Stability and compatibility contract

This document pins what's covered by semantic versioning so downstream
users (CI integrations, dashboards, audit pipelines) can build on
pipeline-check without re-validating on every minor release.

Anything described as **stable** below changes only on a major-version
bump and gets a deprecation period of at least one minor release
beforehand. Anything described as **unstable** can change on any
release; do not depend on it.

## TL;DR for CI integrations

If you only have a minute, this is what's safe to build on and what
isn't. The rest of the page is the long version.

**Safe to depend on:**

1. `--output json --output-file <path>` writes a parseable JSON file
   whose `schema_version` you can branch on.
2. `--output sarif` writes a SARIF 2.1.0 file uploadable to GitHub
   Code Scanning.
3. Exit codes `0` / `1` / `2` / `3` / `4` keep their meanings (see
   the canonical table in [`usage.md`](usage.md#exit-codes)).
4. `check_id` values (`GHA-001`, `JF-033`, `AC-001`, `XPC-008`, …)
   are stable identifiers across releases.

**Don't depend on:**

1. The terminal report for failure counts or scores — it's rendered
   for humans. Use JSON.
2. Specific `[scan]` / `[warn]` / `[gate]` stderr lines for
   programmatic decisions. Use JSON + exit codes.
3. The exact wording of `description` or `recommendation` strings.
   Refined every release.
4. Severity downgrades / upgrades within the rule's logical scope.
   Wire the gate to `--fail-on` or `--fail-on-check`, not to a hard
   severity expectation per rule.

## CLI flags and subcommands — stable

Every flag listed by `pipeline_check --help` is stable. That includes:

- Long names (`--pipeline`, `--output`, `--severity-threshold`,
  `--fail-on`, `--baseline`, `--diff-base`, `--checks`, `--standard`,
  …) and their values.
- Short names (`-p`, `-o`, `-f`, `-c`, `-O`, `-v`, `-q`).
- The `init` subcommand and the `--list-*` / `--explain` family.
- Default values shown in `--help`.
- Provider-path flags (`--gha-path`, `--gitlab-path`,
  `--jenkinsfile-path`, …) and their auto-detect contracts.

**Stability promises:**

- A new flag may be added in any minor release.
- A flag's behavior may be expanded (new values accepted, new
  side effects gated behind opt-in) in any minor release.
- A flag's existing accepted values keep working for the rest of the
  current major.
- Deprecation marks an option with a warning at least one minor
  release before removal.

**Not stable:**

- Wording of help text. Flag descriptions are refined freely.
- The exact text of error messages emitted by `click`. Programs that
  parse stderr should match against the structured signal (exit code,
  JSON output) instead.

## Finding identity — stable

A "finding ID" is one of:

- A rule ID like `GHA-001`, `JF-033`, `K8S-042`, `DF-021`.
- A taint marker like `TAINT-001`.
- A chain ID like `AC-001`, `XPC-008`.

**Stable contracts on a finding ID:**

- An ID, once published in a release, never gets reused for a
  different rule.
- An ID's severity may be raised or lowered, but the ID itself stays
  attached to the same logical security concern.
- A rule may be deprecated in a minor release (still emits findings,
  but marked deprecated in `--explain` output) and removed in the
  next major.

**Not stable:**

- The exact wording of `title`, `description`, `recommendation`. Prose
  is refined every release. CI scripts that key off finding identity
  should match on `check_id`, not title text.
- The exact set of `controls` mapped to a finding. Standards mappings
  (OWASP CICD, NIST CSF, SLSA, etc.) are corrected and extended every
  release. The set is additive on minor releases unless a mapping was
  factually wrong.
- The `incident_refs` and `exploit_example` fields.

## JSON output — stable per schema_version

The JSON report emitted by `--output json` carries a top-level
`schema_version` field. The current version is `1.1` (see
`pipeline_check.core.reporter.JSON_SCHEMA_VERSION`).

**Stable contracts for `schema_version="1.x"`:**

- Top-level keys: `schema_version`, `tool_version`, `score`,
  `findings`, `chains`. `inventory` appears when `--inventory` was
  passed. Consumers should ignore keys they don't recognize so
  additive changes (new top-level keys) are non-breaking.
- Each `findings[]` entry has at minimum: `check_id`, `title`,
  `severity`, `confidence`, `resource`, `description`,
  `recommendation`, `passed`, `controls`, `cwe`. New optional
  fields are added on minor releases.
- `severity` is one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
- `passed` is a boolean: `false` means the rule fired.
- `score` shape: `{score: int, grade: "A"|"B"|"C"|"D",
  summary: {<SEVERITY>: {passed: int, failed: int}}}`.
- `tool_version` is the released pipeline-check version (PEP 440
  string).

**Breaking JSON changes bump `schema_version`.** A new major version
of the schema (`2.0`) ships alongside an opt-in flag for at least one
minor release before the old format is dropped, so consumers can
migrate without coordinating with their pipeline owners.

## SARIF output — stable

`--output sarif` emits SARIF 2.1.0 conforming to the GitHub Advanced
Security upload contract. Key contracts:

- `runs[].tool.driver.version` is the pipeline-check release.
- `runs[].results[].ruleId` matches the finding's `check_id`.
- `runs[].results[].partialFingerprints.pipelineCheckV1` is stable
  per-finding across runs (same input → same fingerprint), so
  GitHub's deduplication works correctly. The fingerprint algorithm
  itself is internal; only the property name is contracted.
- Standard slugs go in `tags`; control IDs go in
  `properties.controls`. GitHub caps `tags` at 20 entries.

**Not stable:**

- The exact contents of `properties.controls` track the finding's
  control list, which is itself stable only at the standards-slug
  level (see "Finding identity" above).

## JUnit output — stable

`--output junit` emits JUnit XML readable by every major CI test
viewer (Jenkins, GitHub Actions, GitLab CI). The contract:

- One `<testcase>` per finding, classname=`pipeline-check.<provider>`,
  name=`<check_id>: <title>`.
- Failures use `<failure>` with `type="<severity>"`.
- `<testsuite>` aggregates the total/failed counts.

## Markdown output — unstable

`--output markdown` is intended for PR-comment rendering. The exact
formatting is refined release-to-release. Consumers should not parse
it; use JSON or SARIF for machine-readable output.

## Threat-model output — unstable

`--output threatmodel` (STRIDE table) is similarly prose-shaped and
subject to release-to-release refinement.

## Terminal output — explicitly not stable

The Rich-rendered terminal report exists to be read by a human at the
end of a scan. Its layout, color palette, severity glyphs, and
per-finding panel shape change freely. CI scripts must not parse
terminal output — use `--output json` (or SARIF / JUnit) instead.

The `[auto]`, `[scan]`, `[warn]`, `[gate]`, `[debug]`, `[hint]`,
`[autofix]`, `[ingest]` log lines on stderr are also unstable. The
prefix shape is intentional (so `grep -E '^\[(warn|gate)\]' filters
work), but the message wording is not contracted.

## Exit codes — stable

| Code | Meaning |
|------|---------|
| `0`  | Scan completed; gate passed (or `--quiet --gate-off`). |
| `1`  | Scan completed; gate failed (`--fail-on` / `--min-grade` / `--max-failures` / `--fail-on-check` / `--fail-on-chain` / `--fail-on-any-chain` tripped). |
| `2`  | Bad invocation or unexpected scan exception. Click `UsageError` (bad flag value, missing required path, mutually-exclusive conflict) and uncaught scanner exceptions both surface here. The error and any traceback are on stderr. |
| `3`  | Operational failure on a non-scan action: `--list-checks` / `--explain` for an unknown ID, `--apply` without `--fix`, MCP support not installed, malformed `--ignore-file`, unparseable `--baseline`. |
| `4`  | `--ai-explain` request failure (missing SDK, missing API key, unknown provider, request error). |

Code `1` is what users gate CI runs on. Codes `2`, `3`, and `4` mean
the scan didn't complete usefully; treating them as failures is the
safe default but distinct semantically from `1`. The full table is
the canonical one in [`usage.md`](usage.md#exit-codes); the same
contract applies here and is covered by the stability promise.

## Gate semantics — stable

The default gate fails on any CRITICAL finding. Passing any explicit
gate option (`--fail-on`, `--min-grade`, `--max-failures`,
`--fail-on-check`, `--fail-on-chain`, `--fail-on-any-chain`)
**suppresses** the default and only the explicit options govern.
Loosen with e.g. `--max-failures 999999`; tighten with
`--fail-on HIGH`. Severity ranking is `CRITICAL > HIGH > MEDIUM > LOW
> INFO`. INFO-severity findings never count toward the score.

Degraded-mode findings (`<PREFIX>-000`, emitted when an AWS API call
fails) are INFO-severity and never trip the gate. A `[warn]` line on
stderr surfaces them.

## Scoring model — stable

The weighted score formula (CRITICAL=20, HIGH=10, MEDIUM=5, LOW=2,
INFO=0) and the A/B/C/D grade thresholds (A ≥ 90, B ≥ 75, C ≥ 60,
D < 60) are stable. They will not change without a major version
bump.

## Python API — stable for the documented surface

The `pipeline_check` package surface listed under
[docs/usage.md](usage.md) (Scanner, ScanMetadata, Finding, Severity,
Confidence, score, evaluate_gate, ReporterRegistry) is stable.
Internal modules (`pipeline_check.core.checks.*`, `_primitives`,
provider helpers) are not part of the public surface — they can
change freely between minor releases.

## Configuration file — stable

`.pipeline-check.yml` keys documented in [docs/config.md](config.md)
are stable. Unknown keys log a warning but don't fail the load, so
adding new options in newer pipeline-check releases doesn't break
older configs.

## See also

The short list at the top of this page ("TL;DR for CI integrations")
restates the safe-to-depend-on contract for readers who just need
the punch list.
