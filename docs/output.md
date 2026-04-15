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
  "score": {"grade": "B", "total": 47, "failed": 8, "passed": 39, "score": 82},
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
  - AWS resource names (bucket names, project names) become
    `resource:///<name>` opaque URIs.
  - Both always carry a `logicalLocations` entry with the raw handle.

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

Standalone HTML — embedded CSS, no JavaScript. See
[scoring_model.md](scoring_model.md) for how the grade and severity
breakdown are computed.

## Exit codes are independent of format

Regardless of output format, the process exits with:

| Code | Meaning        |
|------|----------------|
| `0`  | Grade A/B/C    |
| `1`  | Grade D        |
| `2`  | Scanner error  |

so gating a CI job on `pipeline_check`'s exit code works identically
whether you also request SARIF or JSON for archival.
