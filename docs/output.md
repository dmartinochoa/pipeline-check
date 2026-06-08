# Output formats

`pipeline_check --output <format>` selects the report format. Every
format carries the same finding set, only the rendering differs.

| Format     | Where it lands               | Use case                                             |
|------------|------------------------------|------------------------------------------------------|
| `terminal` | stdout (rich-formatted)      | Human reading in a local shell / CI log              |
| `json`     | stdout                       | Machine parsing (`jq`, artifact archival)            |
| `html`     | `--output-file` (required)   | Emailed / attached reports, screenshots              |
| `sarif`    | stdout or `--output-file`    | GitHub code scanning, GitLab SAST, any SARIF UI      |
| `markdown` | stdout or `--output-file`    | PR comments / Slack-style consumers; Attack Chains H2 sits between summary and the Failures table |
| `junit`    | stdout or `--output-file`    | Test-runner UIs (Jenkins, Bamboo, GitLab pipelines) that natively render JUnit XML |
| `codequality` | stdout or `--output-file` | GitLab Code Quality JSON. Annotates Merge Request diffs natively via the `codequality` artifact report |
| `threatmodel` | stdout or `--output-file` | STRIDE-mapped Markdown threat-model document. Auto-runs `--inventory`. SOC 2 / PCI / NIST SSDF evidence packages, architecture-review docs |
| `cyclonedx` | stdout or `--output-file`  | CycloneDX 1.6 JSON SBOM of build-time dependencies (actions, base images, packages). PURL identifiers on every component |
| `spdx` | stdout or `--output-file`  | SPDX 2.3 JSON SBOM of the same build-time dependencies. Each package carries a PURL `externalRef`; the document `DESCRIBES` every package |
| `both`     | terminal → **stderr**, JSON → stdout | Pipe `jq` while still seeing a human report |

`--pr-diff REF` is the diff-mode counterpart to the formats above: it
runs two scans (HEAD + base) and emits Markdown shaped for a single
PR-review comment, with introduced / resolved / preserved sections
rather than the full failures table the `markdown` format renders.
See [`pr_diff.md`](pr_diff.md) for the mechanism and recipes.

## Inline exploit examples

```bash
pipeline_check --inline-explain
```

`--inline-explain` surfaces each failing finding's recorded
`exploit_example` so the operator sees a concrete attacker scenario
without piping the check ID into `pipeline_check explain`. It honors
every text format that doesn't already carry the field:

| `--output` | Where the example lands |
|---|---|
| `terminal` / `both` | Under the Recommendation block in the panel |
| `sarif` | The rule's `help.text` and `help.markdown` |
| `junit` | The `<failure>` element body |
| `markdown` | A collapsible "Proof of exploit" section after the failures table |
| `codequality` | The issue `description` (the fingerprint is unchanged, so dismissed MR threads don't churn) |

`--output json` and `--output html` always include `exploit_example`
as a structured attribute regardless of the flag, so it has nothing to
add there. All surfaces share the canonical label "Proof of exploit".

## JSON

```bash
pipeline_check --output json | jq '.score'
```

Shape:

```json
{
  "schema_version": "1.1",
  "tool_version": "1.12.0",
  "score": {"grade": "B", "summary": {...}, "score": 82},
  "findings": [
    {
      "check_id": "GHA-001",
      "title": "Action not pinned to commit SHA",
      "severity": "HIGH",
      "resource": ".github/workflows/release.yml",
      "description": "…",
      "recommendation": "…",
      "passed": false,
      "controls": [
        {"standard": "owasp_cicd_top_10", "control_id": "CICD-SEC-3", …}
      ]
    }
  ],
  "chains": [
    {
      "chain_id": "AC-001",
      "title": "Fork-PR Credential Theft (pull_request_target)",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "summary": "...",
      "narrative": "...",
      "mitre_attack": ["T1078.004", "T1195.002", "T1552.001"],
      "kill_chain_phase": "initial-access -> credential-access -> exfiltration",
      "triggering_check_ids": ["GHA-002", "GHA-005"],
      "triggering_findings": [
        {"check_id": "GHA-002", "resource": ".github/workflows/release.yml"},
        {"check_id": "GHA-005", "resource": ".github/workflows/release.yml"}
      ],
      "resources": [".github/workflows/release.yml"],
      "references": ["https://..."],
      "recommendation": "..."
    }
  ]
}
```

Present as an empty list (`"chains": []`) when chain detection ran
and matched nothing; absent entirely when `--no-chains` was passed.
That lets consumers distinguish "nothing matched" from "not asked
for". See [attack_chains.md](attack_chains.md) for the full
chain-output contract.

- The **`findings`** array carries the **failing** findings only by
  default, matching the terminal table and SARIF (a real repo runs ~100
  checks per file, almost all passing). The per-severity `passed` /
  `failed` tallies live in `score.summary` regardless, so the grade and
  counts are unaffected. Pass `--show-passed` to emit every check (passed
  and failed) as the full audit record.
- **`schema_version`** is bumped on breaking format changes. Adding a
  new optional field does not require a bump; renaming or removing one
  does. Consumers should branch on the major component.
- **`tool_version`** is the `pipeline_check` release that produced the
  report, useful for attributing baseline drift to a specific upgrade.

The JSON schema used by `--output json` is committed as
`tests/report_schema.json` and exercised by `tests/test_json_schema.py`
on every run.

## SARIF 2.1.0

SARIF is the OASIS standard consumed by GitHub Advanced Security, GitLab
SAST, Azure DevOps, and most SAST aggregators. Emitting SARIF turns
every failing finding into a code-scanning alert, inline on the pull
request, no custom integration needed.

```bash
# Stream to stdout (redirect yourself)
pipeline_check --pipeline github --gha-path .github/workflows \
    --output sarif > pipeline-check.sarif

# Or write directly to a file
pipeline_check --pipeline github --gha-path .github/workflows \
    --output sarif --output-file pipeline-check.sarif
```

### Shape highlights

- Only **failed** findings become `results`. Every distinct `check_id` is
  declared once under `runs[0].tool.driver.rules`; duplicates across
  resources share the rule and emit separate results.
- Severity is expressed two ways:
  - `level`: `error` (CRITICAL / HIGH), `warning` (MEDIUM / LOW), `note` (INFO)
  - `security-severity` (0.0–10.0 CVSS-style): `9.5` / `7.5` / `5.5` / `3.0` / `1.0` respectively: this is the field GitHub's code-scanning alert filter uses.
- Compliance controls are surfaced two ways:
  - `rule.properties.tags`: a flat list including `"security"`, the
    standard slugs, and every control ID mapped to the check.
    Searchable in the GitHub code-scanning UI.
  - `result.properties.controls`: the structured `ControlRef` list for
    programmatic consumers.
- Locations:
  - File-path resources (YAML paths) become `artifactLocation.uri`.
  - For file-based findings, `physicalLocation.region` (`startLine`, and
    `endLine` / `startColumn` / `endColumn` when known) is emitted from each
    rule's structured `Finding.locations`, so GitHub PR annotations land on
    the offending line, not just the file header. This is the primary path
    and covers the providers that carry structured locations (the YAML CI
    providers, Kubernetes, Tekton, Argo, and the rest of the retrofitted
    pack). For findings with no structured location (AWS / Terraform /
    CloudFormation and rules not yet retrofitted), a legacy best-effort
    fallback regex-greps the source for the signature line. When neither
    yields a line, the region is omitted (GitHub falls back to file-level).
  - AWS resource names (bucket names, project names) become
    `resource:///<name>` opaque URIs.
  - Both always carry a `logicalLocations` entry with the raw handle.
- AWS resources surface an **ARN** on two places: the result's
  `logicalLocations[0].fullyQualifiedName` (standard SARIF field) and
  `result.properties.arn` for quick programmatic access. `result.properties.region`
  is parsed from the ARN so filtering SARIF by region doesn't need a
  separate lookup.

### Uploading to GitHub code scanning

```yaml
# .github/workflows/security.yml
- name: Run pipeline_check
  run: |
    pipeline_check --pipeline github --gha-path .github/workflows \
        --output sarif --output-file pipeline-check.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pipeline-check.sarif
    category: pipeline-check
```

Findings then appear under **Security → Code scanning alerts** and
annotate diffs on every PR.

## HTML

```bash
pipeline_check --output html --output-file report.html
```

Standalone HTML, embedded CSS and JavaScript, no external CDN calls.
The report ships with:

- **Score card** at the top (overall grade, severity breakdown).
- **Attack Chains panel** between the score card and the heatmap.
  Each matched chain renders as a bordered card with severity,
  confidence, narrative, triggering checks, MITRE techniques, and
  references.
- **Blast-radius heatmap** between the chains panel and the findings
  table. One inline-SVG tile per resource with at least one failing
  finding, color-coded by worst severity, sized by failing-finding
  count (sqrt-scaled), tooltip on hover shows the per-severity
  breakdown. Pure inline SVG so the report stays a single offline
  file.
- **Filter bar** (severity / standard / provider / status / free-text)
  that hides rows client-side. Dropdowns auto-populate from the values
  actually present in the result set, so an all-AWS scan doesn't show
  a phantom "github" option.
- **"copy ignore" button** on every finding that copies the flat
  `CHECK_ID:RESOURCE` ignore-file line to the clipboard, paste
  straight into `.pipelinecheckignore` to suppress.

See [scoring_model.md](scoring_model.md) for how the grade and severity
breakdown are computed.

## Threat model

```bash
pipeline_check --pipeline gitlab --gitlab-path .gitlab-ci.yml \
    --output threatmodel --output-file threatmodel.md
```

Self-contained Markdown threat-model document. Selecting
`--output threatmodel` auto-enables the inventory pass so the
Assets and trust-boundary sections are populated.

Section layout:

- **Scope** — providers in scope (from inventory), region / target,
  scorer summary (grade, score, severity breakdown).
- **Trust boundaries** — heuristic list keyed off the provider mix
  (e.g. "PR author → CI runner" surfaces whenever a Git-hosted CI
  provider is in scope; "CI identity → cloud account" surfaces
  whenever AWS / Terraform / CloudFormation are).
- **Assets** — the inventory itself, grouped by `(provider, type)`.
- **STRIDE analysis** — failing findings grouped under one of six
  categories (Spoofing / Tampering / Repudiation / Information
  Disclosure / Denial of Service / Elevation of Privilege).
- **Implemented controls** — passing-check counts per STRIDE bucket,
  evidence that the corresponding controls are in place.
- **Risk register** — top-25 failing findings as a flat table with
  severity, STRIDE codes, check id, resource. The unbounded set
  lives in `--output json`.
- **Methodology** — short footer that points readers at the
  classification policy and capping rules.

### How STRIDE classification works

The OWASP CICD Top 10 mapping every rule already carries is the
right vocabulary for a CI/CD audience but not the one auditors /
threat modelers prefer. STRIDE has been the lingua franca of
threat-modeling docs since Microsoft introduced it in 1999, and
most compliance frameworks (SOC 2 CC, PCI 6.5, NIST SSDF PW.1)
speak it natively.

The mapping is mechanical:

1. Each OWASP CICD-SEC-N maps to one or more STRIDE codes
   (e.g. `CICD-SEC-6` → `Information Disclosure` + `Spoofing`).
2. A small CWE prepend table refines the head when an exact CWE
   is more specific than the OWASP fallback (`CWE-200` → `I`,
   `CWE-269` → `E`, `CWE-778` → `R`, `CWE-345` → `T`).
3. Findings with no OWASP and no CWE tags default to Tampering,
   the most common CI/CD failure mode.

Both tables live in
`pipeline_check/core/threatmodel_reporter.py`. Re-policing is a
pure-function swap, no rule registry changes.

### Use cases

- **SOC 2 / PCI evidence package**: attach `threatmodel.md` next
  to the scan JSON. Auditors get a STRIDE-shaped narrative they
  can read directly; engineers get the JSON for tooling.
- **Architecture review**: paste into a Confluence / Notion
  page as a starting draft. The Assets and trust-boundary
  sections give reviewers a concrete map of what's in scope.
- **Quarterly posture review**: regenerate against the latest
  scan, diff against the prior quarter to see which STRIDE
  buckets gained / lost open risks.

## GitLab Code Quality

```bash
pipeline_check --output codequality -O gl-code-quality-report.json
```

Emits a Code Climate `gl-code-quality-report` JSON array, the format
GitLab CI renders inline against the Merge Request diff when uploaded
as a `reports: codequality:` artifact:

```yaml
# .gitlab-ci.yml
pipeline-check:
  script:
    - pipeline_check --pipeline gitlab --output codequality
        --output-file gl-code-quality-report.json
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
```

Shape highlights:

- One entry per `(failing finding, location)` pair. A single aggregate
  finding that lists ten offending lines becomes ten MR annotations.
- Severity maps as `CRITICAL -> blocker`, `HIGH -> critical`,
  `MEDIUM -> major`, `LOW -> minor`, `INFO -> info`.
- `fingerprint` is a SHA-1 over `(check_id, normalized_path, line)`,
  deliberately *not* over the description, so cosmetic prose tweaks
  across releases don't churn previously-dismissed MR threads.
- Passing findings are skipped (the format has no "passed" concept).

## CycloneDX 1.6

```bash
pipeline_check --pipeline github --gha-path .github/workflows \
    --output cyclonedx --output-file sbom.json
```

Emits a CycloneDX 1.6 JSON BOM of every build-time dependency the
pipeline consumes. Each component carries a
[Package URL](https://github.com/package-url/purl-spec) and
``pipeline-check:`` namespaced properties (provider, kind, source
file, pinned status).

V1 extracts dependencies from four providers: GitHub Actions (action
refs, reusable workflows, docker steps), Dockerfile (``FROM`` base
images), npm (``package.json`` dependencies), and PyPI
(``requirements.txt`` entries). Providers without a
``build_dependencies()`` override contribute no components.

The BOM format follows the
[CycloneDX 1.6 specification](https://cyclonedx.org/docs/1.6/json/).
No external library is required; the JSON is emitted directly.

## SPDX 2.3

```bash
pipeline_check --pipeline github --gha-path .github/workflows \
    --output spdx --output-file sbom.spdx.json
```

Emits the same build-dependency inventory as the CycloneDX output, in
the [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) JSON format that
some toolchains and procurement processes require instead of CycloneDX.
Each dependency becomes an SPDX ``package`` with a ``purl``
``externalRef``; a digest (when known) is emitted as a ``checksums``
entry, and the provider / kind / source / pinned metadata goes in the
package ``comment``. The document ``DESCRIBES`` every package via a
relationship. No external library is required; the JSON is emitted
directly.

## Exit codes are independent of format

The output format never affects the exit code. Gating is governed by
the CI gate, not by the output format; see [ci_gate.md](ci_gate.md).
The full exit-code contract is documented once in
[`usage.md`](usage.md#exit-codes).
