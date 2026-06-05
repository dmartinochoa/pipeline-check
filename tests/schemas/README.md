# Vendored report schemas

These are official, unmodified upstream schema documents. The reporter
tests (`test_sarif_schema.py`, `test_cyclonedx_schema.py`,
`test_junit_schema.py`) validate generated output against them so a
structurally-valid-looking but spec-noncompliant field is caught before
it ships to a downstream consumer (GitHub code scanning, an SBOM tool, a
CI test publisher).

Do not hand-edit these files. To refresh, re-download from the sources
below and re-run the suite.

| File | Spec | Version | Source |
|------|------|---------|--------|
| `sarif-2.1.0.schema.json` | SARIF | 2.1.0 | https://json.schemastore.org/sarif-2.1.0.json |
| `cyclonedx-1.6.schema.json` | CycloneDX BOM | 1.6 | https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json |
| `spdx.schema.json` | SPDX license expr (CycloneDX sub-schema) | 1.6 | https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/spdx.schema.json |
| `jsf-0.82.schema.json` | JSON Signature Format (CycloneDX sub-schema) | 0.82 | https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/jsf-0.82.schema.json |

The CycloneDX BOM schema references the SPDX and JSF documents by
relative URL; `tests/schema_validators.py` registers all three by `$id`
so the `$ref`s resolve locally with no network access.

There is intentionally no vendored JUnit schema. JUnit is a de-facto
interchange format with several mutually-incompatible XSD variants (the
strict Ant/surefire one rejects even the universally-emitted `name` /
`tests` / `failures` attributes on `<testsuites>` and demands synthetic
`hostname` / `timestamp` / `id` on every suite). Validating against any
single variant would force output that real CI consumers (Jenkins,
GitLab, Azure DevOps) do not expect. `test_junit_schema.py` instead
asserts well-formedness plus the structural contract the format
actually relies on, using only the standard library.
