# Output formats

`pipeline_check --output <format>` selects the report format. Every
format carries the same finding set — only the rendering differs.

| Format     | Where it lands               | Use case                                             |
|------------|------------------------------|------------------------------------------------------|
| `terminal` | stdout (rich-formatted)      | Human reading in a local shell / CI log              |
| `json`     | stdout                       | Machine parsing (`jq`, artifact archival)            |
| `html`     | `--output-file` (required)   | Emailed / attached reports, screenshots              |
| `sarif`    | stdout or `--output-file`    | GitHub code scanning, GitLab SAST, any SARIF UI      |
| `both`     | terminal → **stderr**, JSON → stdout | Pipe `jq` while still seeing a human report |

## JSON

```bash
pipeline_check --output json | jq '.score'
```

Shape:

```json
{
  "schema_version": "1.0",
  "tool_version": "0.7.0",
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
  ]
}
```

- **`schema_version`** is bumped on breaking format changes. Adding a
  new optional field does not require a bump; renaming or removing one
  does. Consumers should branch on the major component.
- **`tool_version`** is the `pipeline_check` release that produced the
  report — useful for attributing baseline drift to a specific upgrade.

The JSON schema used by `--output json` is committed as
`tests/report_schema.json` and exercised by `tests/test_json_schema.py`
on every run.

## SARIF 2.1.0

SARIF is the OASIS standard consumed by GitHub Advanced Security, GitLab
SAST, Azure DevOps, and most SAST aggregators. Emitting SARIF turns
every failing finding into a code-scanning alert — inline on the pull
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
  - `security-severity` (0.0–10.0 CVSS-style): `9.5` / `7.5` / `5.5` / `3.0` / `1.0` respectively — this is the field GitHub's code-scanning alert filter uses.
- Compliance controls are surfaced two ways:
  - `rule.properties.tags` — a flat list including `"security"`, the
    standard slugs, and every control ID mapped to the check.
    Searchable in the GitHub code-scanning UI.
  - `result.properties.controls` — the structured `ControlRef` list for
    programmatic consumers.
- Locations:
  - File-path resources (YAML paths) become `artifactLocation.uri`.
  - For file-based findings, a best-effort `physicalLocation.region.startLine`
    is emitted — per-check regexes grep the source for the signature line
    so GitHub PR annotations land on the offending line, not just the file
    header. Supported today: `GHA-001/002/003/008`, `GL-001/008`,
    `BB-001/008`, `ADO-001/005/008`. When no pattern matches, the region
    is omitted (GitHub falls back to file-level).
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

Standalone HTML — embedded CSS and JavaScript, no external CDN calls.
The report ships with:

- **Filter bar** (severity / standard / provider / status / free-text)
  that hides rows client-side. Dropdowns auto-populate from the values
  actually present in the result set, so an all-AWS scan doesn't show
  a phantom "github" option.
- **"copy ignore" button** on every finding that copies the flat
  `CHECK_ID:RESOURCE` ignore-file line to the clipboard — paste
  straight into `.pipelinecheckignore` to suppress.

See [scoring_model.md](scoring_model.md) for how the grade and severity
breakdown are computed.

## Exit codes are independent of format

Regardless of output format, the process exits with:

| Code | Meaning        |
|------|----------------|
| `0`  | Gate passed    |
| `1`  | Gate failed    |
| `2`  | Scanner error  |

Gating is governed by the CI gate, not by the output format — see
[ci_gate.md](ci_gate.md).
