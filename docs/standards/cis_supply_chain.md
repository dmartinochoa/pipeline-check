# CIS Software Supply Chain Security Guide v1.0

- **Version:** 1.0
- **URL:** https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide
- **Scope:** Sub-controls from sections 1 (Source Code), 2 (Build
  Pipelines), 3 (Build Dependencies), 4 (Artifacts), and 5
  (Deployment) that this scanner can evidence from AWS, GitHub Actions,
  and Terraform state.

## Sections

- **1 Source Code**: contribution identity, 3rd-party verification
- **2 Build Pipelines**: build env hardening, worker isolation,
  pipeline integrity, audit logs
- **3 Build Dependencies**: signed metadata, trusted package managers
- **4 Artifacts**: signing, access controls, registry auth, SBOM
- **5 Deployment**: manifest review, env separation, audit

## Mapping to checks

Each row below pairs a `check_id` with the CIS Supply Chain sub-controls
its passing state evidences. Source of truth:
`pipeline_check/core/standards/data/cis_supply_chain.py`, regenerate
with `python scripts/gen_standards_mappings.py cis_supply_chain`.

| Check | Control(s) |
|-------|------------|
| [`ADO-001`](../providers/azure.md#ado-001) | `1.4.1` · `3.1.5` |
| [`ADO-002`](../providers/azure.md#ado-002) | `2.1.3` · `2.3.8` |
| [`ADO-003`](../providers/azure.md#ado-003) | `2.3.4` · `2.4.3` |
| [`ADO-004`](../providers/azure.md#ado-004) | `5.1.4` · `5.2.1` |
| [`ADO-005`](../providers/azure.md#ado-005) | `1.4.1` · `3.1.5` |
| [`ADO-006`](../providers/azure.md#ado-006) | `4.1.1` |
| [`ADO-007`](../providers/azure.md#ado-007) | `4.4.1` |
| [`BB-001`](../providers/bitbucket.md#bb-001) | `1.4.1` · `3.1.5` |
| [`BB-002`](../providers/bitbucket.md#bb-002) | `2.1.3` · `2.3.8` |
| [`BB-003`](../providers/bitbucket.md#bb-003) | `2.3.4` · `2.4.3` |
| [`BB-004`](../providers/bitbucket.md#bb-004) | `5.1.4` · `5.2.1` |
| [`BB-005`](../providers/bitbucket.md#bb-005) | `2.2.2` |
| [`BB-006`](../providers/bitbucket.md#bb-006) | `4.1.1` |
| [`BB-007`](../providers/bitbucket.md#bb-007) | `4.4.1` |
| [`CB-001`](../providers/aws.md) | `2.3.4` · `2.4.3` |
| [`CB-002`](../providers/aws.md) | `2.1.3` · `2.1.6` |
| [`CB-003`](../providers/aws.md) | `2.3.7` |
| [`CB-004`](../providers/aws.md) | `2.2.2` |
| [`CB-005`](../providers/aws.md) | `2.1.3` · `1.4.1` |
| [`CB-006`](../providers/aws.md) | `1.3.4` |
| [`CB-007`](../providers/aws.md) | `2.3.8` |
| [`CC-001`](../providers/circleci.md#cc-001) | `1.4.1` · `3.1.5` |
| [`CC-002`](../providers/circleci.md#cc-002) | `2.1.3` |
| [`CC-003`](../providers/circleci.md#cc-003) | `1.4.1` · `3.1.5` |
| [`CC-004`](../providers/circleci.md#cc-004) | `2.3.4` · `2.4.3` |
| [`CC-005`](../providers/circleci.md#cc-005) | `1.3.4` |
| [`CC-006`](../providers/circleci.md#cc-006) | `4.1.1` |
| [`CC-007`](../providers/circleci.md#cc-007) | `4.4.1` |
| [`CC-008`](../providers/circleci.md#cc-008) | `2.3.4` · `2.4.3` |
| [`CC-009`](../providers/circleci.md#cc-009) | `2.3.8` · `5.1.4` |
| [`CC-010`](../providers/circleci.md#cc-010) | `2.1.3` · `2.1.6` |
| [`CC-011`](../providers/circleci.md#cc-011) | `2.3.7` |
| [`CC-012`](../providers/circleci.md#cc-012) | `2.1.3` |
| [`CC-013`](../providers/circleci.md#cc-013) | `2.3.8` |
| [`CC-014`](../providers/circleci.md#cc-014) | `2.1.6` |
| [`CC-015`](../providers/circleci.md#cc-015) | `2.2.2` |
| [`CC-016`](../providers/circleci.md#cc-016) | `1.4.1` · `3.1.5` |
| [`CC-017`](../providers/circleci.md#cc-017) | `2.1.3` |
| [`CC-018`](../providers/circleci.md#cc-018) | `3.1.5` |
| [`CC-019`](../providers/circleci.md#cc-019) | `1.3.4` |
| [`CC-020`](../providers/circleci.md#cc-020) | `1.4.1` · `3.1.3` |
| [`CC-021`](../providers/circleci.md#cc-021) | `3.1.3` |
| [`CC-022`](../providers/circleci.md#cc-022) | `3.1.3` |
| [`CC-023`](../providers/circleci.md#cc-023) | `3.1.5` |
| [`CD-001`](../providers/aws.md) | `5.1.4` |
| [`CD-002`](../providers/aws.md) | `5.1.4` · `5.2.1` |
| [`CD-003`](../providers/aws.md) | `5.2.3` |
| [`CP-001`](../providers/aws.md) | `2.3.8` · `5.1.4` |
| [`CP-002`](../providers/aws.md) | `2.4.2` · `4.1.1` |
| [`CP-003`](../providers/aws.md) | `2.3.8` |
| [`CP-004`](../providers/aws.md) | `1.3.4` |
| [`ECR-001`](../providers/aws.md) | `1.4.1` · `3.1.3` |
| [`ECR-002`](../providers/aws.md) | `4.1.1` · `4.4.1` |
| [`ECR-003`](../providers/aws.md) | `4.2.1` · `4.3.3` |
| [`ECR-004`](../providers/aws.md) | `2.1.3` |
| [`ECR-005`](../providers/aws.md) | `4.1.1` |
| [`GHA-001`](../providers/github.md#gha-001) | `1.4.1` · `3.1.5` |
| [`GHA-002`](../providers/github.md#gha-002) | `2.1.3` · `2.3.8` |
| [`GHA-003`](../providers/github.md#gha-003) | `2.1.3` |
| [`GHA-004`](../providers/github.md#gha-004) | `2.4.3` |
| [`GHA-005`](../providers/github.md#gha-005) | `1.3.4` |
| [`GHA-006`](../providers/github.md#gha-006) | `4.1.1` |
| [`GHA-007`](../providers/github.md#gha-007) | `4.4.1` |
| [`GL-001`](../providers/gitlab.md#gl-001) | `1.4.1` · `3.1.5` |
| [`GL-002`](../providers/gitlab.md#gl-002) | `2.1.3` · `2.3.8` |
| [`GL-003`](../providers/gitlab.md#gl-003) | `2.3.4` · `2.4.3` |
| [`GL-004`](../providers/gitlab.md#gl-004) | `5.1.4` · `5.2.1` |
| [`GL-005`](../providers/gitlab.md#gl-005) | `1.4.1` · `3.1.3` · `3.1.5` |
| [`GL-006`](../providers/gitlab.md#gl-006) | `4.1.1` |
| [`GL-007`](../providers/gitlab.md#gl-007) | `4.4.1` |
| [`IAM-001`](../providers/aws.md) | `2.4.3` |
| [`IAM-002`](../providers/aws.md) | `2.4.3` |
| [`IAM-003`](../providers/aws.md) | `2.4.3` |
| [`IAM-004`](../providers/aws.md) | `2.4.3` |
| [`IAM-005`](../providers/aws.md) | `2.4.3` · `1.3.4` |
| [`IAM-006`](../providers/aws.md) | `2.4.3` |
| [`PBAC-001`](../providers/aws.md) | `2.1.6` |
| [`PBAC-002`](../providers/aws.md) | `2.2.2` · `2.4.3` |
| [`S3-001`](../providers/aws.md) | `4.2.1` |
| [`S3-002`](../providers/aws.md) | `4.1.1` |
| [`S3-003`](../providers/aws.md) | `4.1.1` · `4.4.1` |
| [`S3-004`](../providers/aws.md) | `2.3.7` · `5.2.3` |
| [`S3-005`](../providers/aws.md) | `4.2.1` |

## Not covered

- 1.1 / 1.2 repository protection rules (requires SCM policy read)
- 2.1.1 / 2.1.2 build infra versioning (requires infra git history)
- 3.2.x dependency-graph SBOM verification (requires lockfile analysis)
- 5.1.1 / 5.1.2 deployment workflow review (requires SCM review-policy)
