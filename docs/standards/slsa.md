# SLSA Build Track v1.0

- **Version:** 1.0
- **URL:** https://slsa.dev/spec/v1.0/
- **Scope:** Build track requirements (L1–L3). The Source and
  Dependency tracks require SCM and registry introspection that this
  scanner does not perform.

## Requirements evidenced

| Control                   | Description                                                              |
|---------------------------|--------------------------------------------------------------------------|
| Build.L1.Scripted         | Build process is fully defined and automated                             |
| Build.L1.Provenance       | Provenance describing how the artifact was produced is generated         |
| Build.L2.Hosted           | Builds run on a hosted build platform, not a developer workstation       |
| Build.L2.Signed           | Provenance is authenticated and cannot be forged by tenants              |
| Build.L3.Isolated         | Build runs in an isolated environment not influenced by other builds     |
| Build.L3.Ephemeral        | Build environment is ephemeral and provisioned fresh for each run        |
| Build.L3.NonFalsifiable   | Provenance cannot be falsified by the build's own tenant                 |

## Mapping to checks

Each row below pairs a `check_id` with the SLSA Build-Track requirements
its passing state evidences. Source of truth:
`pipeline_check/core/standards/data/slsa.py` — regenerate with
`python scripts/gen_standards_mappings.py slsa`.

| Check | Control(s) |
|-------|------------|
| `ADO-001` | `Build.L3.NonFalsifiable` |
| `ADO-002` | `Build.L3.Isolated` |
| `ADO-005` | `Build.L3.NonFalsifiable` |
| `ADO-006` | `Build.L2.Signed` |
| `ADO-007` | `Build.L1.Provenance` |
| `ADO-008` | `Build.L3.NonFalsifiable` |
| `ADO-009` | `Build.L3.NonFalsifiable` |
| `ADO-010` | `Build.L3.Isolated` |
| `ADO-011` | `Build.L3.Isolated` |
| `ADO-012` | `Build.L3.Isolated` |
| `ADO-013` | `Build.L2.Hosted` · `Build.L3.Ephemeral` |
| `ADO-015` | `Build.L3.Ephemeral` |
| `ADO-016` | `Build.L3.Isolated` |
| `ADO-017` | `Build.L3.Isolated` |
| `ADO-019` | `Build.L3.Isolated` |
| `ADO-021` | `Build.L3.Isolated` |
| `ADO-023` | `Build.L3.Isolated` |
| `ADO-024` | `Build.L1.Provenance` · `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| `ADO-025` | `Build.L3.NonFalsifiable` |
| `ADO-027` | `Build.L3.Isolated` |
| `ADO-028` | `Build.L3.Isolated` |
| `BB-001` | `Build.L3.NonFalsifiable` |
| `BB-002` | `Build.L3.Isolated` |
| `BB-005` | `Build.L3.Ephemeral` |
| `BB-006` | `Build.L2.Signed` |
| `BB-007` | `Build.L1.Provenance` |
| `BB-008` | `Build.L3.NonFalsifiable` |
| `BB-009` | `Build.L3.NonFalsifiable` |
| `BB-010` | `Build.L3.Isolated` |
| `BB-012` | `Build.L3.Isolated` |
| `BB-013` | `Build.L3.Isolated` |
| `BB-016` | `Build.L2.Hosted` · `Build.L3.Ephemeral` |
| `BB-017` | `Build.L3.NonFalsifiable` |
| `BB-018` | `Build.L3.Isolated` |
| `BB-021` | `Build.L3.Isolated` |
| `BB-023` | `Build.L3.Isolated` |
| `BB-024` | `Build.L1.Provenance` · `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| `BB-026` | `Build.L3.Isolated` |
| `BB-027` | `Build.L3.Isolated` |
| `CB-002` | `Build.L3.Isolated` |
| `CB-004` | `Build.L3.Ephemeral` |
| `CB-007` | `Build.L3.Isolated` · `Build.L3.Ephemeral` |
| `CC-001` | `Build.L3.NonFalsifiable` |
| `CC-002` | `Build.L3.Isolated` |
| `CC-003` | `Build.L3.NonFalsifiable` |
| `CC-004` | `Build.L3.NonFalsifiable` |
| `CC-006` | `Build.L2.Signed` |
| `CC-007` | `Build.L1.Provenance` |
| `CC-008` | `Build.L3.NonFalsifiable` |
| `CC-010` | `Build.L2.Hosted` · `Build.L3.Ephemeral` |
| `CC-012` | `Build.L3.Isolated` |
| `CC-014` | `Build.L3.Isolated` |
| `CC-015` | `Build.L3.Ephemeral` |
| `CC-016` | `Build.L3.Isolated` |
| `CC-017` | `Build.L3.Isolated` |
| `CC-021` | `Build.L3.Isolated` |
| `CC-023` | `Build.L3.Isolated` |
| `CC-024` | `Build.L1.Provenance` · `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| `CC-025` | `Build.L3.Isolated` |
| `CC-027` | `Build.L3.Isolated` |
| `CC-028` | `Build.L3.Isolated` |
| `CP-001` | `Build.L3.NonFalsifiable` |
| `CP-002` | `Build.L1.Provenance` · `Build.L2.Signed` |
| `ECR-002` | `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| `GHA-001` | `Build.L3.NonFalsifiable` |
| `GHA-002` | `Build.L3.NonFalsifiable` · `Build.L3.Isolated` |
| `GHA-003` | `Build.L3.Isolated` |
| `GHA-004` | `Build.L3.NonFalsifiable` |
| `GHA-006` | `Build.L2.Signed` |
| `GHA-007` | `Build.L1.Provenance` |
| `GHA-008` | `Build.L3.NonFalsifiable` |
| `GHA-009` | `Build.L3.Isolated` |
| `GHA-010` | `Build.L3.Isolated` |
| `GHA-011` | `Build.L3.Isolated` |
| `GHA-012` | `Build.L2.Hosted` · `Build.L3.Ephemeral` |
| `GHA-013` | `Build.L3.Isolated` |
| `GHA-015` | `Build.L3.Ephemeral` |
| `GHA-016` | `Build.L3.Isolated` |
| `GHA-017` | `Build.L3.Isolated` |
| `GHA-019` | `Build.L3.NonFalsifiable` |
| `GHA-021` | `Build.L3.Isolated` |
| `GHA-023` | `Build.L3.Isolated` |
| `GHA-024` | `Build.L1.Provenance` · `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| `GHA-025` | `Build.L3.NonFalsifiable` |
| `GHA-026` | `Build.L3.Isolated` |
| `GHA-028` | `Build.L3.Isolated` |
| `GHA-029` | `Build.L3.Isolated` |
| `GL-001` | `Build.L3.NonFalsifiable` |
| `GL-002` | `Build.L3.Isolated` |
| `GL-005` | `Build.L3.NonFalsifiable` |
| `GL-006` | `Build.L2.Signed` |
| `GL-007` | `Build.L1.Provenance` |
| `GL-008` | `Build.L3.NonFalsifiable` |
| `GL-009` | `Build.L3.NonFalsifiable` |
| `GL-010` | `Build.L3.Isolated` |
| `GL-011` | `Build.L3.Isolated` |
| `GL-012` | `Build.L3.Isolated` |
| `GL-014` | `Build.L2.Hosted` · `Build.L3.Ephemeral` |
| `GL-015` | `Build.L3.Ephemeral` |
| `GL-016` | `Build.L3.Isolated` |
| `GL-017` | `Build.L3.Isolated` |
| `GL-020` | `Build.L3.NonFalsifiable` |
| `GL-021` | `Build.L3.Isolated` |
| `GL-023` | `Build.L3.Isolated` |
| `GL-024` | `Build.L1.Provenance` · `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| `GL-026` | `Build.L3.Isolated` |
| `GL-027` | `Build.L3.Isolated` |
| `IAM-001` | `Build.L3.NonFalsifiable` |
| `IAM-002` | `Build.L3.NonFalsifiable` |
| `IAM-004` | `Build.L3.NonFalsifiable` |
| `IAM-006` | `Build.L3.NonFalsifiable` |
| `JF-001` | `Build.L3.NonFalsifiable` |
| `JF-002` | `Build.L3.Isolated` |
| `JF-003` | `Build.L3.Isolated` |
| `JF-006` | `Build.L2.Signed` |
| `JF-007` | `Build.L1.Provenance` |
| `JF-008` | `Build.L3.NonFalsifiable` |
| `JF-009` | `Build.L3.NonFalsifiable` |
| `JF-012` | `Build.L3.Isolated` |
| `JF-013` | `Build.L3.Isolated` |
| `JF-014` | `Build.L2.Hosted` · `Build.L3.Ephemeral` |
| `JF-015` | `Build.L3.Ephemeral` |
| `JF-016` | `Build.L3.Isolated` |
| `JF-017` | `Build.L3.Isolated` |
| `JF-019` | `Build.L3.Isolated` |
| `JF-021` | `Build.L3.Isolated` |
| `JF-023` | `Build.L3.Isolated` |
| `JF-028` | `Build.L1.Provenance` · `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| `JF-030` | `Build.L3.Isolated` |
| `JF-031` | `Build.L3.Isolated` |
| `PBAC-001` | `Build.L3.Isolated` |
| `PBAC-002` | `Build.L3.Isolated` |

## Not covered

- **Source track** (branch protection, 2-reviewer, retained history) —
  requires GitHub/GitLab policy inspection beyond Actions workflows.
- **Dependency track** — requires package-manifest and lockfile
  analysis across the dependency graph.
