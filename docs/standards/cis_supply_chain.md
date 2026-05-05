# CIS Software Supply Chain Security Guide v1.0

- **Version:** 1.0
- **URL:** https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide
- **Scope:** Sub-controls from sections 1 (Source Code), 2 (Build
  Pipelines), 3 (Build Dependencies), 4 (Artifacts), and 5
  (Deployment) that this scanner can evidence from AWS, GitHub Actions,
  and Terraform state.

## Sections

- **1 Source Code** — contribution identity, 3rd-party verification
- **2 Build Pipelines** — build env hardening, worker isolation,
  pipeline integrity, audit logs
- **3 Build Dependencies** — signed metadata, trusted package managers
- **4 Artifacts** — signing, access controls, registry auth, SBOM
- **5 Deployment** — manifest review, env separation, audit

## Mapping to checks

Each row below pairs a `check_id` with the CIS Supply Chain sub-controls
its passing state evidences. Source of truth:
`pipeline_check/core/standards/data/cis_supply_chain.py` — regenerate
with `python scripts/gen_standards_mappings.py cis_supply_chain`.

| Check | Control(s) |
|-------|------------|
| `ADO-001` | `1.4.1` · `3.1.5` |
| `ADO-002` | `2.1.3` · `2.3.8` |
| `ADO-003` | `2.3.4` · `2.4.3` |
| `ADO-004` | `5.1.4` · `5.2.1` |
| `ADO-005` | `1.4.1` · `3.1.5` |
| `ADO-006` | `4.1.1` |
| `ADO-007` | `4.4.1` |
| `BB-001` | `1.4.1` · `3.1.5` |
| `BB-002` | `2.1.3` · `2.3.8` |
| `BB-003` | `2.3.4` · `2.4.3` |
| `BB-004` | `5.1.4` · `5.2.1` |
| `BB-005` | `2.2.2` |
| `BB-006` | `4.1.1` |
| `BB-007` | `4.4.1` |
| `CB-001` | `2.3.4` · `2.4.3` |
| `CB-002` | `2.1.3` · `2.1.6` |
| `CB-003` | `2.3.7` |
| `CB-004` | `2.2.2` |
| `CB-005` | `2.1.3` · `1.4.1` |
| `CB-006` | `1.3.4` |
| `CB-007` | `2.3.8` |
| `CC-001` | `1.4.1` · `3.1.5` |
| `CC-002` | `2.1.3` |
| `CC-003` | `1.4.1` · `3.1.5` |
| `CC-004` | `2.3.4` · `2.4.3` |
| `CC-005` | `1.3.4` |
| `CC-006` | `4.1.1` |
| `CC-007` | `4.4.1` |
| `CC-008` | `2.3.4` · `2.4.3` |
| `CC-009` | `2.3.8` · `5.1.4` |
| `CC-010` | `2.1.3` · `2.1.6` |
| `CC-011` | `2.3.7` |
| `CC-012` | `2.1.3` |
| `CC-013` | `2.3.8` |
| `CC-014` | `2.1.6` |
| `CC-015` | `2.2.2` |
| `CC-016` | `1.4.1` · `3.1.5` |
| `CC-017` | `2.1.3` |
| `CC-018` | `3.1.5` |
| `CC-019` | `1.3.4` |
| `CC-020` | `1.4.1` · `3.1.3` |
| `CC-021` | `3.1.3` |
| `CC-022` | `3.1.3` |
| `CC-023` | `3.1.5` |
| `CD-001` | `5.1.4` |
| `CD-002` | `5.1.4` · `5.2.1` |
| `CD-003` | `5.2.3` |
| `CP-001` | `2.3.8` · `5.1.4` |
| `CP-002` | `2.4.2` · `4.1.1` |
| `CP-003` | `2.3.8` |
| `CP-004` | `1.3.4` |
| `ECR-001` | `1.4.1` · `3.1.3` |
| `ECR-002` | `4.1.1` · `4.4.1` |
| `ECR-003` | `4.2.1` · `4.3.3` |
| `ECR-004` | `2.1.3` |
| `ECR-005` | `4.1.1` |
| `GHA-001` | `1.4.1` · `3.1.5` |
| `GHA-002` | `2.1.3` · `2.3.8` |
| `GHA-003` | `2.1.3` |
| `GHA-004` | `2.4.3` |
| `GHA-005` | `1.3.4` |
| `GHA-006` | `4.1.1` |
| `GHA-007` | `4.4.1` |
| `GL-001` | `1.4.1` · `3.1.5` |
| `GL-002` | `2.1.3` · `2.3.8` |
| `GL-003` | `2.3.4` · `2.4.3` |
| `GL-004` | `5.1.4` · `5.2.1` |
| `GL-005` | `1.4.1` · `3.1.3` · `3.1.5` |
| `GL-006` | `4.1.1` |
| `GL-007` | `4.4.1` |
| `IAM-001` | `2.4.3` |
| `IAM-002` | `2.4.3` |
| `IAM-003` | `2.4.3` |
| `IAM-004` | `2.4.3` |
| `IAM-005` | `2.4.3` · `1.3.4` |
| `IAM-006` | `2.4.3` |
| `PBAC-001` | `2.1.6` |
| `PBAC-002` | `2.2.2` · `2.4.3` |
| `S3-001` | `4.2.1` |
| `S3-002` | `4.1.1` |
| `S3-003` | `4.1.1` · `4.4.1` |
| `S3-004` | `2.3.7` · `5.2.3` |
| `S3-005` | `4.2.1` |

## Not covered

- 1.1 / 1.2 repository protection rules (requires SCM policy read)
- 2.1.1 / 2.1.2 build infra versioning (requires infra git history)
- 3.2.x dependency-graph SBOM verification (requires lockfile analysis)
- 5.1.1 / 5.1.2 deployment workflow review (requires SCM review-policy)
