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
`pipeline_check/core/standards/data/slsa.py`, regenerate with
`python scripts/gen_standards_mappings.py slsa`.

| Check | Control(s) |
|-------|------------|
| [`ADO-001`](../providers/azure.md#ado-001) | `Build.L3.NonFalsifiable` |
| [`ADO-002`](../providers/azure.md#ado-002) | `Build.L3.Isolated` |
| [`ADO-005`](../providers/azure.md#ado-005) | `Build.L3.NonFalsifiable` |
| [`ADO-006`](../providers/azure.md#ado-006) | `Build.L2.Signed` |
| [`ADO-007`](../providers/azure.md#ado-007) | `Build.L1.Provenance` |
| [`ADO-008`](../providers/azure.md#ado-008) | `Build.L3.NonFalsifiable` |
| [`ADO-009`](../providers/azure.md#ado-009) | `Build.L3.NonFalsifiable` |
| [`ADO-010`](../providers/azure.md#ado-010) | `Build.L3.Isolated` |
| [`ADO-011`](../providers/azure.md#ado-011) | `Build.L3.Isolated` |
| [`ADO-012`](../providers/azure.md#ado-012) | `Build.L3.Isolated` |
| [`ADO-013`](../providers/azure.md#ado-013) | `Build.L2.Hosted` · `Build.L3.Ephemeral` |
| [`ADO-015`](../providers/azure.md#ado-015) | `Build.L3.Ephemeral` |
| [`ADO-016`](../providers/azure.md#ado-016) | `Build.L3.Isolated` |
| [`ADO-017`](../providers/azure.md#ado-017) | `Build.L3.Isolated` |
| [`ADO-019`](../providers/azure.md#ado-019) | `Build.L3.Isolated` |
| [`ADO-021`](../providers/azure.md#ado-021) | `Build.L3.Isolated` |
| [`ADO-023`](../providers/azure.md#ado-023) | `Build.L3.Isolated` |
| [`ADO-024`](../providers/azure.md#ado-024) | `Build.L1.Provenance` · `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| [`ADO-025`](../providers/azure.md#ado-025) | `Build.L3.NonFalsifiable` |
| [`ADO-027`](../providers/azure.md#ado-027) | `Build.L3.Isolated` |
| [`ADO-028`](../providers/azure.md#ado-028) | `Build.L3.Isolated` |
| [`BB-001`](../providers/bitbucket.md#bb-001) | `Build.L3.NonFalsifiable` |
| [`BB-002`](../providers/bitbucket.md#bb-002) | `Build.L3.Isolated` |
| [`BB-005`](../providers/bitbucket.md#bb-005) | `Build.L3.Ephemeral` |
| [`BB-006`](../providers/bitbucket.md#bb-006) | `Build.L2.Signed` |
| [`BB-007`](../providers/bitbucket.md#bb-007) | `Build.L1.Provenance` |
| [`BB-008`](../providers/bitbucket.md#bb-008) | `Build.L3.NonFalsifiable` |
| [`BB-009`](../providers/bitbucket.md#bb-009) | `Build.L3.NonFalsifiable` |
| [`BB-010`](../providers/bitbucket.md#bb-010) | `Build.L3.Isolated` |
| [`BB-012`](../providers/bitbucket.md#bb-012) | `Build.L3.Isolated` |
| [`BB-013`](../providers/bitbucket.md#bb-013) | `Build.L3.Isolated` |
| [`BB-016`](../providers/bitbucket.md#bb-016) | `Build.L2.Hosted` · `Build.L3.Ephemeral` |
| [`BB-017`](../providers/bitbucket.md#bb-017) | `Build.L3.NonFalsifiable` |
| [`BB-018`](../providers/bitbucket.md#bb-018) | `Build.L3.Isolated` |
| [`BB-021`](../providers/bitbucket.md#bb-021) | `Build.L3.Isolated` |
| [`BB-023`](../providers/bitbucket.md#bb-023) | `Build.L3.Isolated` |
| [`BB-024`](../providers/bitbucket.md#bb-024) | `Build.L1.Provenance` · `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| [`BB-026`](../providers/bitbucket.md#bb-026) | `Build.L3.Isolated` |
| [`BB-027`](../providers/bitbucket.md#bb-027) | `Build.L3.Isolated` |
| [`CB-002`](../providers/aws.md) | `Build.L3.Isolated` |
| [`CB-004`](../providers/aws.md) | `Build.L3.Ephemeral` |
| [`CB-007`](../providers/aws.md) | `Build.L3.Isolated` · `Build.L3.Ephemeral` |
| [`CC-001`](../providers/circleci.md#cc-001) | `Build.L3.NonFalsifiable` |
| [`CC-002`](../providers/circleci.md#cc-002) | `Build.L3.Isolated` |
| [`CC-003`](../providers/circleci.md#cc-003) | `Build.L3.NonFalsifiable` |
| [`CC-004`](../providers/circleci.md#cc-004) | `Build.L3.NonFalsifiable` |
| [`CC-006`](../providers/circleci.md#cc-006) | `Build.L2.Signed` |
| [`CC-007`](../providers/circleci.md#cc-007) | `Build.L1.Provenance` |
| [`CC-008`](../providers/circleci.md#cc-008) | `Build.L3.NonFalsifiable` |
| [`CC-010`](../providers/circleci.md#cc-010) | `Build.L2.Hosted` · `Build.L3.Ephemeral` |
| [`CC-012`](../providers/circleci.md#cc-012) | `Build.L3.Isolated` |
| [`CC-014`](../providers/circleci.md#cc-014) | `Build.L3.Isolated` |
| [`CC-015`](../providers/circleci.md#cc-015) | `Build.L3.Ephemeral` |
| [`CC-016`](../providers/circleci.md#cc-016) | `Build.L3.Isolated` |
| [`CC-017`](../providers/circleci.md#cc-017) | `Build.L3.Isolated` |
| [`CC-021`](../providers/circleci.md#cc-021) | `Build.L3.Isolated` |
| [`CC-023`](../providers/circleci.md#cc-023) | `Build.L3.Isolated` |
| [`CC-024`](../providers/circleci.md#cc-024) | `Build.L1.Provenance` · `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| [`CC-025`](../providers/circleci.md#cc-025) | `Build.L3.Isolated` |
| [`CC-027`](../providers/circleci.md#cc-027) | `Build.L3.Isolated` |
| [`CC-028`](../providers/circleci.md#cc-028) | `Build.L3.Isolated` |
| [`CP-001`](../providers/aws.md) | `Build.L3.NonFalsifiable` |
| [`CP-002`](../providers/aws.md) | `Build.L1.Provenance` · `Build.L2.Signed` |
| [`ECR-002`](../providers/aws.md) | `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| [`GHA-001`](../providers/github.md#gha-001) | `Build.L3.NonFalsifiable` |
| [`GHA-002`](../providers/github.md#gha-002) | `Build.L3.NonFalsifiable` · `Build.L3.Isolated` |
| [`GHA-003`](../providers/github.md#gha-003) | `Build.L3.Isolated` |
| [`GHA-004`](../providers/github.md#gha-004) | `Build.L3.NonFalsifiable` |
| [`GHA-006`](../providers/github.md#gha-006) | `Build.L2.Signed` |
| [`GHA-007`](../providers/github.md#gha-007) | `Build.L1.Provenance` |
| [`GHA-008`](../providers/github.md#gha-008) | `Build.L3.NonFalsifiable` |
| [`GHA-009`](../providers/github.md#gha-009) | `Build.L3.Isolated` |
| [`GHA-010`](../providers/github.md#gha-010) | `Build.L3.Isolated` |
| [`GHA-011`](../providers/github.md#gha-011) | `Build.L3.Isolated` |
| [`GHA-012`](../providers/github.md#gha-012) | `Build.L2.Hosted` · `Build.L3.Ephemeral` |
| [`GHA-013`](../providers/github.md#gha-013) | `Build.L3.Isolated` |
| [`GHA-015`](../providers/github.md#gha-015) | `Build.L3.Ephemeral` |
| [`GHA-016`](../providers/github.md#gha-016) | `Build.L3.Isolated` |
| [`GHA-017`](../providers/github.md#gha-017) | `Build.L3.Isolated` |
| [`GHA-019`](../providers/github.md#gha-019) | `Build.L3.NonFalsifiable` |
| [`GHA-021`](../providers/github.md#gha-021) | `Build.L3.Isolated` |
| [`GHA-023`](../providers/github.md#gha-023) | `Build.L3.Isolated` |
| [`GHA-024`](../providers/github.md#gha-024) | `Build.L1.Provenance` · `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| [`GHA-025`](../providers/github.md#gha-025) | `Build.L3.NonFalsifiable` |
| [`GHA-026`](../providers/github.md#gha-026) | `Build.L3.Isolated` |
| [`GHA-028`](../providers/github.md#gha-028) | `Build.L3.Isolated` |
| [`GHA-029`](../providers/github.md#gha-029) | `Build.L3.Isolated` |
| [`GL-001`](../providers/gitlab.md#gl-001) | `Build.L3.NonFalsifiable` |
| [`GL-002`](../providers/gitlab.md#gl-002) | `Build.L3.Isolated` |
| [`GL-005`](../providers/gitlab.md#gl-005) | `Build.L3.NonFalsifiable` |
| [`GL-006`](../providers/gitlab.md#gl-006) | `Build.L2.Signed` |
| [`GL-007`](../providers/gitlab.md#gl-007) | `Build.L1.Provenance` |
| [`GL-008`](../providers/gitlab.md#gl-008) | `Build.L3.NonFalsifiable` |
| [`GL-009`](../providers/gitlab.md#gl-009) | `Build.L3.NonFalsifiable` |
| [`GL-010`](../providers/gitlab.md#gl-010) | `Build.L3.Isolated` |
| [`GL-011`](../providers/gitlab.md#gl-011) | `Build.L3.Isolated` |
| [`GL-012`](../providers/gitlab.md#gl-012) | `Build.L3.Isolated` |
| [`GL-014`](../providers/gitlab.md#gl-014) | `Build.L2.Hosted` · `Build.L3.Ephemeral` |
| [`GL-015`](../providers/gitlab.md#gl-015) | `Build.L3.Ephemeral` |
| [`GL-016`](../providers/gitlab.md#gl-016) | `Build.L3.Isolated` |
| [`GL-017`](../providers/gitlab.md#gl-017) | `Build.L3.Isolated` |
| [`GL-020`](../providers/gitlab.md#gl-020) | `Build.L3.NonFalsifiable` |
| [`GL-021`](../providers/gitlab.md#gl-021) | `Build.L3.Isolated` |
| [`GL-023`](../providers/gitlab.md#gl-023) | `Build.L3.Isolated` |
| [`GL-024`](../providers/gitlab.md#gl-024) | `Build.L1.Provenance` · `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| [`GL-026`](../providers/gitlab.md#gl-026) | `Build.L3.Isolated` |
| [`GL-027`](../providers/gitlab.md#gl-027) | `Build.L3.Isolated` |
| [`IAM-001`](../providers/aws.md) | `Build.L3.NonFalsifiable` |
| [`IAM-002`](../providers/aws.md) | `Build.L3.NonFalsifiable` |
| [`IAM-004`](../providers/aws.md) | `Build.L3.NonFalsifiable` |
| [`IAM-006`](../providers/aws.md) | `Build.L3.NonFalsifiable` |
| [`JF-001`](../providers/jenkins.md#jf-001) | `Build.L3.NonFalsifiable` |
| [`JF-002`](../providers/jenkins.md#jf-002) | `Build.L3.Isolated` |
| [`JF-003`](../providers/jenkins.md#jf-003) | `Build.L3.Isolated` |
| [`JF-006`](../providers/jenkins.md#jf-006) | `Build.L2.Signed` |
| [`JF-007`](../providers/jenkins.md#jf-007) | `Build.L1.Provenance` |
| [`JF-008`](../providers/jenkins.md#jf-008) | `Build.L3.NonFalsifiable` |
| [`JF-009`](../providers/jenkins.md#jf-009) | `Build.L3.NonFalsifiable` |
| [`JF-012`](../providers/jenkins.md#jf-012) | `Build.L3.Isolated` |
| [`JF-013`](../providers/jenkins.md#jf-013) | `Build.L3.Isolated` |
| [`JF-014`](../providers/jenkins.md#jf-014) | `Build.L2.Hosted` · `Build.L3.Ephemeral` |
| [`JF-015`](../providers/jenkins.md#jf-015) | `Build.L3.Ephemeral` |
| [`JF-016`](../providers/jenkins.md#jf-016) | `Build.L3.Isolated` |
| [`JF-017`](../providers/jenkins.md#jf-017) | `Build.L3.Isolated` |
| [`JF-019`](../providers/jenkins.md#jf-019) | `Build.L3.Isolated` |
| [`JF-021`](../providers/jenkins.md#jf-021) | `Build.L3.Isolated` |
| [`JF-023`](../providers/jenkins.md#jf-023) | `Build.L3.Isolated` |
| [`JF-028`](../providers/jenkins.md#jf-028) | `Build.L1.Provenance` · `Build.L2.Signed` · `Build.L3.NonFalsifiable` |
| [`JF-030`](../providers/jenkins.md#jf-030) | `Build.L3.Isolated` |
| [`JF-031`](../providers/jenkins.md#jf-031) | `Build.L3.Isolated` |
| [`PBAC-001`](../providers/aws.md) | `Build.L3.Isolated` |
| [`PBAC-002`](../providers/aws.md) | `Build.L3.Isolated` |

## Not covered

- **Source track** (branch protection, 2-reviewer, retained history),
  requires GitHub/GitLab policy inspection beyond Actions workflows.
- **Dependency track**: requires package-manifest and lockfile
  analysis across the dependency graph.
