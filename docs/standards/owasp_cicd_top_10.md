# OWASP Top 10 CI/CD Security Risks

- **Version:** 2022
- **URL:** https://owasp.org/www-project-top-10-ci-cd-security-risks/
- **Source of truth:** `pipeline_check/core/standards/data/owasp_cicd_top_10.py`
- **Scope:** The OWASP CI/CD Top 10 is the canonical risk taxonomy
  this scanner organises around. Every other compliance standard's
  ``check_id`` set is a subset of OWASP's; the cross-standard
  integrity test in ``tests/test_standards.py`` enforces it.

## Controls

| ID           | Title                                      |
|--------------|--------------------------------------------|
| CICD-SEC-1   | Insufficient Flow Control Mechanisms       |
| CICD-SEC-2   | Inadequate Identity and Access Management  |
| CICD-SEC-3   | Dependency Chain Abuse                     |
| CICD-SEC-4   | Poisoned Pipeline Execution                |
| CICD-SEC-5   | Insufficient PBAC                          |
| CICD-SEC-6   | Insufficient Credential Hygiene            |
| CICD-SEC-7   | Insecure System Configuration              |
| CICD-SEC-8   | Ungoverned Usage of 3rd-Party Services     |
| CICD-SEC-9   | Improper Artifact Integrity Validation     |
| CICD-SEC-10  | Insufficient Logging and Visibility        |

## Coverage summary

Number of distinct ``check_id`` values mapping to each risk. The
scanner's catalog is intentionally weighted toward dependency-chain
abuse (CICD-SEC-3) and poisoned-pipeline-execution (CICD-SEC-4),
which together account for the bulk of real-world CI/CD incidents.

| Control      | Description                                | Checks |
|--------------|--------------------------------------------|-------:|
| CICD-SEC-1   | Insufficient Flow Control Mechanisms       |     15 |
| CICD-SEC-2   | Inadequate Identity and Access Management  |     16 |
| CICD-SEC-3   | Dependency Chain Abuse                     |     77 |
| CICD-SEC-4   | Poisoned Pipeline Execution                |     45 |
| CICD-SEC-5   | Insufficient PBAC                          |     10 |
| CICD-SEC-6   | Insufficient Credential Hygiene            |     43 |
| CICD-SEC-7   | Insecure System Configuration              |     52 |
| CICD-SEC-8   | Ungoverned Usage of 3rd-Party Services     |      7 |
| CICD-SEC-9   | Improper Artifact Integrity Validation     |     37 |
| CICD-SEC-10  | Insufficient Logging and Visibility        |     31 |

## Mapping (check -> control)

The full per-check mapping. Regenerate with:

```bash
python scripts/gen_standards_mappings.py owasp_cicd_top_10     --out docs/standards/_owasp_table.md
```

| Check | Control(s) |
|-------|------------|
| [`ADO-001`](../providers/azure.md#ado-001) | `CICD-SEC-3` |
| [`ADO-002`](../providers/azure.md#ado-002) | `CICD-SEC-4` |
| [`ADO-003`](../providers/azure.md#ado-003) | `CICD-SEC-6` |
| [`ADO-004`](../providers/azure.md#ado-004) | `CICD-SEC-1` |
| [`ADO-005`](../providers/azure.md#ado-005) | `CICD-SEC-3` |
| [`ADO-006`](../providers/azure.md#ado-006) | `CICD-SEC-9` |
| [`ADO-007`](../providers/azure.md#ado-007) | `CICD-SEC-9` |
| [`ADO-008`](../providers/azure.md#ado-008) | `CICD-SEC-6` |
| [`ADO-009`](../providers/azure.md#ado-009) | `CICD-SEC-3` |
| [`ADO-010`](../providers/azure.md#ado-010) | `CICD-SEC-4` |
| [`ADO-011`](../providers/azure.md#ado-011) | `CICD-SEC-4` |
| [`ADO-012`](../providers/azure.md#ado-012) | `CICD-SEC-4` |
| [`ADO-013`](../providers/azure.md#ado-013) | `CICD-SEC-7` |
| [`ADO-014`](../providers/azure.md#ado-014) | `CICD-SEC-6` |
| [`ADO-015`](../providers/azure.md#ado-015) | `CICD-SEC-7` |
| [`ADO-016`](../providers/azure.md#ado-016) | `CICD-SEC-3` |
| [`ADO-017`](../providers/azure.md#ado-017) | `CICD-SEC-7` |
| [`ADO-018`](../providers/azure.md#ado-018) | `CICD-SEC-3` |
| [`ADO-019`](../providers/azure.md#ado-019) | `CICD-SEC-4` |
| [`ADO-020`](../providers/azure.md#ado-020) | `CICD-SEC-3` |
| [`ADO-021`](../providers/azure.md#ado-021) | `CICD-SEC-3` |
| [`ADO-022`](../providers/azure.md#ado-022) | `CICD-SEC-3` |
| [`ADO-023`](../providers/azure.md#ado-023) | `CICD-SEC-3` |
| [`ADO-024`](../providers/azure.md#ado-024) | `CICD-SEC-9` |
| [`ADO-025`](../providers/azure.md#ado-025) | `CICD-SEC-3` |
| [`ADO-026`](../providers/azure.md#ado-026) | `CICD-SEC-4` |
| [`ADO-027`](../providers/azure.md#ado-027) | `CICD-SEC-4` |
| [`ADO-028`](../providers/azure.md#ado-028) | `CICD-SEC-3` |
| [`BB-001`](../providers/bitbucket.md#bb-001) | `CICD-SEC-3` |
| [`BB-002`](../providers/bitbucket.md#bb-002) | `CICD-SEC-4` |
| [`BB-003`](../providers/bitbucket.md#bb-003) | `CICD-SEC-6` |
| [`BB-004`](../providers/bitbucket.md#bb-004) | `CICD-SEC-1` |
| [`BB-005`](../providers/bitbucket.md#bb-005) | `CICD-SEC-7` |
| [`BB-006`](../providers/bitbucket.md#bb-006) | `CICD-SEC-9` |
| [`BB-007`](../providers/bitbucket.md#bb-007) | `CICD-SEC-9` |
| [`BB-008`](../providers/bitbucket.md#bb-008) | `CICD-SEC-6` |
| [`BB-009`](../providers/bitbucket.md#bb-009) | `CICD-SEC-3` |
| [`BB-010`](../providers/bitbucket.md#bb-010) | `CICD-SEC-4` |
| [`BB-011`](../providers/bitbucket.md#bb-011) | `CICD-SEC-6` |
| [`BB-012`](../providers/bitbucket.md#bb-012) | `CICD-SEC-3` |
| [`BB-013`](../providers/bitbucket.md#bb-013) | `CICD-SEC-7` |
| [`BB-014`](../providers/bitbucket.md#bb-014) | `CICD-SEC-3` |
| [`BB-015`](../providers/bitbucket.md#bb-015) | `CICD-SEC-3` |
| [`BB-016`](../providers/bitbucket.md#bb-016) | `CICD-SEC-7` |
| [`BB-017`](../providers/bitbucket.md#bb-017) | `CICD-SEC-6` |
| [`BB-018`](../providers/bitbucket.md#bb-018) | `CICD-SEC-4` |
| [`BB-019`](../providers/bitbucket.md#bb-019) | `CICD-SEC-6` |
| [`BB-020`](../providers/bitbucket.md#bb-020) | `CICD-SEC-7` |
| [`BB-021`](../providers/bitbucket.md#bb-021) | `CICD-SEC-3` |
| [`BB-022`](../providers/bitbucket.md#bb-022) | `CICD-SEC-3` |
| [`BB-023`](../providers/bitbucket.md#bb-023) | `CICD-SEC-3` |
| [`BB-024`](../providers/bitbucket.md#bb-024) | `CICD-SEC-9` |
| [`BB-025`](../providers/bitbucket.md#bb-025) | `CICD-SEC-4` |
| [`BB-026`](../providers/bitbucket.md#bb-026) | `CICD-SEC-4` |
| [`BB-027`](../providers/bitbucket.md#bb-027) | `CICD-SEC-3` |
| [`CA-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`CA-001`](../providers/aws.md) | `CICD-SEC-9` |
| [`CA-002`](../providers/aws.md) | `CICD-SEC-3` |
| [`CA-003`](../providers/aws.md) | `CICD-SEC-8` |
| [`CA-004`](../providers/aws.md) | `CICD-SEC-2` |
| [`CB-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`CB-001`](../providers/aws.md) | `CICD-SEC-6` |
| [`CB-002`](../providers/aws.md) | `CICD-SEC-7` |
| [`CB-003`](../providers/aws.md) | `CICD-SEC-10` |
| [`CB-004`](../providers/aws.md) | `CICD-SEC-7` |
| [`CB-005`](../providers/aws.md) | `CICD-SEC-7` |
| [`CB-006`](../providers/aws.md) | `CICD-SEC-6` |
| [`CB-007`](../providers/aws.md) | `CICD-SEC-1` |
| [`CB-008`](../providers/aws.md) | `CICD-SEC-4` |
| [`CB-009`](../providers/aws.md) | `CICD-SEC-3` |
| [`CB-010`](../providers/aws.md) | `CICD-SEC-4` |
| [`CB-011`](../providers/aws.md) | `CICD-SEC-4` |
| [`CC-001`](../providers/circleci.md#cc-001) | `CICD-SEC-3` |
| [`CC-002`](../providers/circleci.md#cc-002) | `CICD-SEC-4` |
| [`CC-003`](../providers/circleci.md#cc-003) | `CICD-SEC-3` |
| [`CC-004`](../providers/circleci.md#cc-004) | `CICD-SEC-6` |
| [`CC-005`](../providers/circleci.md#cc-005) | `CICD-SEC-6` |
| [`CC-006`](../providers/circleci.md#cc-006) | `CICD-SEC-9` |
| [`CC-007`](../providers/circleci.md#cc-007) | `CICD-SEC-9` |
| [`CC-008`](../providers/circleci.md#cc-008) | `CICD-SEC-6` |
| [`CC-009`](../providers/circleci.md#cc-009) | `CICD-SEC-1` |
| [`CC-010`](../providers/circleci.md#cc-010) | `CICD-SEC-7` |
| [`CC-011`](../providers/circleci.md#cc-011) | `CICD-SEC-10` |
| [`CC-012`](../providers/circleci.md#cc-012) | `CICD-SEC-4` |
| [`CC-013`](../providers/circleci.md#cc-013) | `CICD-SEC-1` |
| [`CC-014`](../providers/circleci.md#cc-014) | `CICD-SEC-5` |
| [`CC-015`](../providers/circleci.md#cc-015) | `CICD-SEC-7` |
| [`CC-016`](../providers/circleci.md#cc-016) | `CICD-SEC-3` |
| [`CC-017`](../providers/circleci.md#cc-017) | `CICD-SEC-7` |
| [`CC-018`](../providers/circleci.md#cc-018) | `CICD-SEC-3` |
| [`CC-019`](../providers/circleci.md#cc-019) | `CICD-SEC-6` |
| [`CC-020`](../providers/circleci.md#cc-020) | `CICD-SEC-3` |
| [`CC-021`](../providers/circleci.md#cc-021) | `CICD-SEC-3` |
| [`CC-022`](../providers/circleci.md#cc-022) | `CICD-SEC-3` |
| [`CC-023`](../providers/circleci.md#cc-023) | `CICD-SEC-3` |
| [`CC-024`](../providers/circleci.md#cc-024) | `CICD-SEC-9` |
| [`CC-025`](../providers/circleci.md#cc-025) | `CICD-SEC-4` |
| [`CC-026`](../providers/circleci.md#cc-026) | `CICD-SEC-4` |
| [`CC-027`](../providers/circleci.md#cc-027) | `CICD-SEC-4` |
| [`CC-028`](../providers/circleci.md#cc-028) | `CICD-SEC-3` |
| [`CC-029`](../providers/circleci.md#cc-029) | `CICD-SEC-3` |
| [`CC-030`](../providers/circleci.md#cc-030) | `CICD-SEC-6` |
| [`CCM-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`CCM-001`](../providers/aws.md) | `CICD-SEC-1` |
| [`CCM-002`](../providers/aws.md) | `CICD-SEC-9` |
| [`CCM-003`](../providers/aws.md) | `CICD-SEC-8` |
| [`CD-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`CD-001`](../providers/aws.md) | `CICD-SEC-1` |
| [`CD-002`](../providers/aws.md) | `CICD-SEC-1` |
| [`CD-003`](../providers/aws.md) | `CICD-SEC-10` |
| [`CF-001`](../providers/cloudformation.md) | `CICD-SEC-6` |
| [`CF-002`](../providers/cloudformation.md) | `CICD-SEC-6` |
| [`CF-003`](../providers/cloudformation.md) | `CICD-SEC-7` |
| [`CP-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`CP-001`](../providers/aws.md) | `CICD-SEC-1` |
| [`CP-002`](../providers/aws.md) | `CICD-SEC-9` |
| [`CP-003`](../providers/aws.md) | `CICD-SEC-4` |
| [`CP-004`](../providers/aws.md) | `CICD-SEC-6` |
| [`CP-005`](../providers/aws.md) | `CICD-SEC-1` |
| [`CP-007`](../providers/aws.md) | `CICD-SEC-4` |
| [`CT-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`CT-001`](../providers/aws.md) | `CICD-SEC-10` |
| [`CT-002`](../providers/aws.md) | `CICD-SEC-10` |
| [`CT-003`](../providers/aws.md) | `CICD-SEC-10` |
| [`CW-001`](../providers/aws.md) | `CICD-SEC-10` |
| [`CWL-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`CWL-001`](../providers/aws.md) | `CICD-SEC-10` |
| [`CWL-002`](../providers/aws.md) | `CICD-SEC-9` |
| [`DF-001`](../providers/dockerfile.md#df-001) | `CICD-SEC-3` |
| [`DF-002`](../providers/dockerfile.md#df-002) | `CICD-SEC-7` |
| [`DF-003`](../providers/dockerfile.md#df-003) | `CICD-SEC-3` |
| [`DF-004`](../providers/dockerfile.md#df-004) | `CICD-SEC-3` |
| [`DF-005`](../providers/dockerfile.md#df-005) | `CICD-SEC-4` |
| [`DF-006`](../providers/dockerfile.md#df-006) | `CICD-SEC-6` |
| [`DF-007`](../providers/dockerfile.md#df-007) | `CICD-SEC-10` |
| [`DF-008`](../providers/dockerfile.md#df-008) | `CICD-SEC-7` |
| [`DF-009`](../providers/dockerfile.md#df-009) | `CICD-SEC-3` |
| [`DF-010`](../providers/dockerfile.md#df-010) | `CICD-SEC-3` |
| [`DF-011`](../providers/dockerfile.md#df-011) | `CICD-SEC-7` |
| [`DF-012`](../providers/dockerfile.md#df-012) | `CICD-SEC-7` |
| [`DF-013`](../providers/dockerfile.md#df-013) | `CICD-SEC-7` |
| [`DF-014`](../providers/dockerfile.md#df-014) | `CICD-SEC-7` |
| [`DF-015`](../providers/dockerfile.md#df-015) | `CICD-SEC-7` |
| [`DF-016`](../providers/dockerfile.md#df-016) | `CICD-SEC-9` |
| [`EB-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`EB-001`](../providers/aws.md) | `CICD-SEC-10` |
| [`EB-002`](../providers/aws.md) | `CICD-SEC-8` |
| [`ECR-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`ECR-001`](../providers/aws.md) | `CICD-SEC-3` |
| [`ECR-002`](../providers/aws.md) | `CICD-SEC-9` |
| [`ECR-003`](../providers/aws.md) | `CICD-SEC-8` |
| [`ECR-004`](../providers/aws.md) | `CICD-SEC-7` |
| [`ECR-005`](../providers/aws.md) | `CICD-SEC-9` |
| [`ECR-006`](../providers/aws.md) | `CICD-SEC-3` |
| [`ECR-007`](../providers/aws.md) | `CICD-SEC-3` |
| [`GCB-001`](../providers/cloudbuild.md#gcb-001) | `CICD-SEC-3` |
| [`GCB-002`](../providers/cloudbuild.md#gcb-002) | `CICD-SEC-2` |
| [`GCB-003`](../providers/cloudbuild.md#gcb-003) | `CICD-SEC-6` |
| [`GCB-004`](../providers/cloudbuild.md#gcb-004) | `CICD-SEC-4` |
| [`GCB-005`](../providers/cloudbuild.md#gcb-005) | `CICD-SEC-7` |
| [`GCB-006`](../providers/cloudbuild.md#gcb-006) | `CICD-SEC-4` |
| [`GCB-007`](../providers/cloudbuild.md#gcb-007) | `CICD-SEC-6` |
| [`GCB-008`](../providers/cloudbuild.md#gcb-008) | `CICD-SEC-3` |
| [`GCB-009`](../providers/cloudbuild.md#gcb-009) | `CICD-SEC-9` |
| [`GCB-010`](../providers/cloudbuild.md#gcb-010) | `CICD-SEC-3` |
| [`GCB-011`](../providers/cloudbuild.md#gcb-011) | `CICD-SEC-3` |
| [`GCB-012`](../providers/cloudbuild.md#gcb-012) | `CICD-SEC-6` |
| [`GCB-013`](../providers/cloudbuild.md#gcb-013) | `CICD-SEC-3` |
| [`GCB-014`](../providers/cloudbuild.md#gcb-014) | `CICD-SEC-10` |
| [`GCB-015`](../providers/cloudbuild.md#gcb-015) | `CICD-SEC-9` |
| [`GCB-016`](../providers/cloudbuild.md#gcb-016) | `CICD-SEC-7` |
| [`GCB-017`](../providers/cloudbuild.md#gcb-017) | `CICD-SEC-9` · `CICD-SEC-10` |
| [`GCB-018`](../providers/cloudbuild.md#gcb-018) | `CICD-SEC-6` |
| [`GHA-001`](../providers/github.md#gha-001) | `CICD-SEC-3` |
| [`GHA-002`](../providers/github.md#gha-002) | `CICD-SEC-4` |
| [`GHA-003`](../providers/github.md#gha-003) | `CICD-SEC-4` |
| [`GHA-004`](../providers/github.md#gha-004) | `CICD-SEC-5` |
| [`GHA-005`](../providers/github.md#gha-005) | `CICD-SEC-6` |
| [`GHA-006`](../providers/github.md#gha-006) | `CICD-SEC-9` |
| [`GHA-007`](../providers/github.md#gha-007) | `CICD-SEC-9` |
| [`GHA-008`](../providers/github.md#gha-008) | `CICD-SEC-6` |
| [`GHA-009`](../providers/github.md#gha-009) | `CICD-SEC-4` |
| [`GHA-010`](../providers/github.md#gha-010) | `CICD-SEC-4` |
| [`GHA-011`](../providers/github.md#gha-011) | `CICD-SEC-4` |
| [`GHA-012`](../providers/github.md#gha-012) | `CICD-SEC-7` |
| [`GHA-013`](../providers/github.md#gha-013) | `CICD-SEC-4` |
| [`GHA-014`](../providers/github.md#gha-014) | `CICD-SEC-1` |
| [`GHA-015`](../providers/github.md#gha-015) | `CICD-SEC-7` |
| [`GHA-016`](../providers/github.md#gha-016) | `CICD-SEC-3` |
| [`GHA-017`](../providers/github.md#gha-017) | `CICD-SEC-7` |
| [`GHA-018`](../providers/github.md#gha-018) | `CICD-SEC-3` |
| [`GHA-019`](../providers/github.md#gha-019) | `CICD-SEC-6` |
| [`GHA-020`](../providers/github.md#gha-020) | `CICD-SEC-3` |
| [`GHA-021`](../providers/github.md#gha-021) | `CICD-SEC-3` |
| [`GHA-022`](../providers/github.md#gha-022) | `CICD-SEC-3` |
| [`GHA-023`](../providers/github.md#gha-023) | `CICD-SEC-3` |
| [`GHA-024`](../providers/github.md#gha-024) | `CICD-SEC-9` |
| [`GHA-025`](../providers/github.md#gha-025) | `CICD-SEC-3` |
| [`GHA-026`](../providers/github.md#gha-026) | `CICD-SEC-7` |
| [`GHA-027`](../providers/github.md#gha-027) | `CICD-SEC-4` |
| [`GHA-028`](../providers/github.md#gha-028) | `CICD-SEC-4` |
| [`GHA-029`](../providers/github.md#gha-029) | `CICD-SEC-3` |
| [`GL-001`](../providers/gitlab.md#gl-001) | `CICD-SEC-3` |
| [`GL-002`](../providers/gitlab.md#gl-002) | `CICD-SEC-4` |
| [`GL-003`](../providers/gitlab.md#gl-003) | `CICD-SEC-6` |
| [`GL-004`](../providers/gitlab.md#gl-004) | `CICD-SEC-1` |
| [`GL-005`](../providers/gitlab.md#gl-005) | `CICD-SEC-3` |
| [`GL-006`](../providers/gitlab.md#gl-006) | `CICD-SEC-9` |
| [`GL-007`](../providers/gitlab.md#gl-007) | `CICD-SEC-9` |
| [`GL-008`](../providers/gitlab.md#gl-008) | `CICD-SEC-6` |
| [`GL-009`](../providers/gitlab.md#gl-009) | `CICD-SEC-3` |
| [`GL-010`](../providers/gitlab.md#gl-010) | `CICD-SEC-4` |
| [`GL-011`](../providers/gitlab.md#gl-011) | `CICD-SEC-4` |
| [`GL-012`](../providers/gitlab.md#gl-012) | `CICD-SEC-4` |
| [`GL-013`](../providers/gitlab.md#gl-013) | `CICD-SEC-6` |
| [`GL-014`](../providers/gitlab.md#gl-014) | `CICD-SEC-7` |
| [`GL-015`](../providers/gitlab.md#gl-015) | `CICD-SEC-7` |
| [`GL-016`](../providers/gitlab.md#gl-016) | `CICD-SEC-3` |
| [`GL-017`](../providers/gitlab.md#gl-017) | `CICD-SEC-7` |
| [`GL-018`](../providers/gitlab.md#gl-018) | `CICD-SEC-3` |
| [`GL-019`](../providers/gitlab.md#gl-019) | `CICD-SEC-3` |
| [`GL-020`](../providers/gitlab.md#gl-020) | `CICD-SEC-6` |
| [`GL-021`](../providers/gitlab.md#gl-021) | `CICD-SEC-3` |
| [`GL-022`](../providers/gitlab.md#gl-022) | `CICD-SEC-3` |
| [`GL-023`](../providers/gitlab.md#gl-023) | `CICD-SEC-3` |
| [`GL-024`](../providers/gitlab.md#gl-024) | `CICD-SEC-9` |
| [`GL-025`](../providers/gitlab.md#gl-025) | `CICD-SEC-4` |
| [`GL-026`](../providers/gitlab.md#gl-026) | `CICD-SEC-4` |
| [`GL-027`](../providers/gitlab.md#gl-027) | `CICD-SEC-3` |
| [`GL-028`](../providers/gitlab.md#gl-028) | `CICD-SEC-3` |
| [`GL-029`](../providers/gitlab.md#gl-029) | `CICD-SEC-1` |
| [`GL-030`](../providers/gitlab.md#gl-030) | `CICD-SEC-3` |
| [`IAM-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`IAM-001`](../providers/aws.md) | `CICD-SEC-2` |
| [`IAM-002`](../providers/aws.md) | `CICD-SEC-2` |
| [`IAM-003`](../providers/aws.md) | `CICD-SEC-2` |
| [`IAM-004`](../providers/aws.md) | `CICD-SEC-2` |
| [`IAM-005`](../providers/aws.md) | `CICD-SEC-2` |
| [`IAM-006`](../providers/aws.md) | `CICD-SEC-2` |
| [`IAM-007`](../providers/aws.md) | `CICD-SEC-6` |
| [`IAM-008`](../providers/aws.md) | `CICD-SEC-2` |
| [`JF-001`](../providers/jenkins.md#jf-001) | `CICD-SEC-3` |
| [`JF-002`](../providers/jenkins.md#jf-002) | `CICD-SEC-4` |
| [`JF-003`](../providers/jenkins.md#jf-003) | `CICD-SEC-5` |
| [`JF-004`](../providers/jenkins.md#jf-004) | `CICD-SEC-6` |
| [`JF-005`](../providers/jenkins.md#jf-005) | `CICD-SEC-1` |
| [`JF-006`](../providers/jenkins.md#jf-006) | `CICD-SEC-9` |
| [`JF-007`](../providers/jenkins.md#jf-007) | `CICD-SEC-9` |
| [`JF-008`](../providers/jenkins.md#jf-008) | `CICD-SEC-6` |
| [`JF-009`](../providers/jenkins.md#jf-009) | `CICD-SEC-3` |
| [`JF-010`](../providers/jenkins.md#jf-010) | `CICD-SEC-6` |
| [`JF-011`](../providers/jenkins.md#jf-011) | `CICD-SEC-10` |
| [`JF-012`](../providers/jenkins.md#jf-012) | `CICD-SEC-3` |
| [`JF-013`](../providers/jenkins.md#jf-013) | `CICD-SEC-4` |
| [`JF-014`](../providers/jenkins.md#jf-014) | `CICD-SEC-7` |
| [`JF-015`](../providers/jenkins.md#jf-015) | `CICD-SEC-7` |
| [`JF-016`](../providers/jenkins.md#jf-016) | `CICD-SEC-3` |
| [`JF-017`](../providers/jenkins.md#jf-017) | `CICD-SEC-7` |
| [`JF-018`](../providers/jenkins.md#jf-018) | `CICD-SEC-3` |
| [`JF-019`](../providers/jenkins.md#jf-019) | `CICD-SEC-4` |
| [`JF-020`](../providers/jenkins.md#jf-020) | `CICD-SEC-3` |
| [`JF-021`](../providers/jenkins.md#jf-021) | `CICD-SEC-3` |
| [`JF-022`](../providers/jenkins.md#jf-022) | `CICD-SEC-3` |
| [`JF-023`](../providers/jenkins.md#jf-023) | `CICD-SEC-3` |
| [`JF-024`](../providers/jenkins.md#jf-024) | `CICD-SEC-1` |
| [`JF-025`](../providers/jenkins.md#jf-025) | `CICD-SEC-7` |
| [`JF-026`](../providers/jenkins.md#jf-026) | `CICD-SEC-4` |
| [`JF-027`](../providers/jenkins.md#jf-027) | `CICD-SEC-9` |
| [`JF-028`](../providers/jenkins.md#jf-028) | `CICD-SEC-9` |
| [`JF-029`](../providers/jenkins.md#jf-029) | `CICD-SEC-4` |
| [`JF-030`](../providers/jenkins.md#jf-030) | `CICD-SEC-4` |
| [`JF-031`](../providers/jenkins.md#jf-031) | `CICD-SEC-3` |
| [`K8S-001`](../providers/kubernetes.md#k8s-001) | `CICD-SEC-3` |
| [`K8S-002`](../providers/kubernetes.md#k8s-002) | `CICD-SEC-7` |
| [`K8S-003`](../providers/kubernetes.md#k8s-003) | `CICD-SEC-7` |
| [`K8S-004`](../providers/kubernetes.md#k8s-004) | `CICD-SEC-7` |
| [`K8S-005`](../providers/kubernetes.md#k8s-005) | `CICD-SEC-7` |
| [`K8S-006`](../providers/kubernetes.md#k8s-006) | `CICD-SEC-7` |
| [`K8S-007`](../providers/kubernetes.md#k8s-007) | `CICD-SEC-7` |
| [`K8S-008`](../providers/kubernetes.md#k8s-008) | `CICD-SEC-7` |
| [`K8S-009`](../providers/kubernetes.md#k8s-009) | `CICD-SEC-7` |
| [`K8S-010`](../providers/kubernetes.md#k8s-010) | `CICD-SEC-7` |
| [`K8S-011`](../providers/kubernetes.md#k8s-011) | `CICD-SEC-2` |
| [`K8S-012`](../providers/kubernetes.md#k8s-012) | `CICD-SEC-2` · `CICD-SEC-6` |
| [`K8S-013`](../providers/kubernetes.md#k8s-013) | `CICD-SEC-7` |
| [`K8S-014`](../providers/kubernetes.md#k8s-014) | `CICD-SEC-7` |
| [`K8S-015`](../providers/kubernetes.md#k8s-015) | `CICD-SEC-7` |
| [`K8S-016`](../providers/kubernetes.md#k8s-016) | `CICD-SEC-7` |
| [`K8S-017`](../providers/kubernetes.md#k8s-017) | `CICD-SEC-6` |
| [`K8S-018`](../providers/kubernetes.md#k8s-018) | `CICD-SEC-6` |
| [`K8S-019`](../providers/kubernetes.md#k8s-019) | `CICD-SEC-2` |
| [`K8S-020`](../providers/kubernetes.md#k8s-020) | `CICD-SEC-2` · `CICD-SEC-5` |
| [`K8S-021`](../providers/kubernetes.md#k8s-021) | `CICD-SEC-2` · `CICD-SEC-5` |
| [`K8S-022`](../providers/kubernetes.md#k8s-022) | `CICD-SEC-7` |
| [`K8S-023`](../providers/kubernetes.md#k8s-023) | `CICD-SEC-7` |
| [`K8S-024`](../providers/kubernetes.md#k8s-024) | `CICD-SEC-10` |
| [`K8S-025`](../providers/kubernetes.md#k8s-025) | `CICD-SEC-2` · `CICD-SEC-5` |
| [`K8S-026`](../providers/kubernetes.md#k8s-026) | `CICD-SEC-7` |
| [`KMS-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`KMS-001`](../providers/aws.md) | `CICD-SEC-6` |
| [`KMS-002`](../providers/aws.md) | `CICD-SEC-2` |
| [`LMB-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`LMB-001`](../providers/aws.md) | `CICD-SEC-9` |
| [`LMB-002`](../providers/aws.md) | `CICD-SEC-8` |
| [`LMB-003`](../providers/aws.md) | `CICD-SEC-6` |
| [`LMB-004`](../providers/aws.md) | `CICD-SEC-8` |
| [`PBAC-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`PBAC-001`](../providers/aws.md) | `CICD-SEC-5` |
| [`PBAC-002`](../providers/aws.md) | `CICD-SEC-5` |
| [`PBAC-003`](../providers/aws.md) | `CICD-SEC-5` |
| [`PBAC-005`](../providers/aws.md) | `CICD-SEC-5` |
| [`S3-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`S3-001`](../providers/aws.md) | `CICD-SEC-9` |
| [`S3-002`](../providers/aws.md) | `CICD-SEC-9` |
| [`S3-003`](../providers/aws.md) | `CICD-SEC-9` |
| [`S3-004`](../providers/aws.md) | `CICD-SEC-10` |
| [`S3-005`](../providers/aws.md) | `CICD-SEC-9` |
| [`SIGN-001`](../providers/aws.md) | `CICD-SEC-9` |
| [`SIGN-002`](../providers/aws.md) | `CICD-SEC-9` |
| [`SM-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`SM-001`](../providers/aws.md) | `CICD-SEC-6` |
| [`SM-002`](../providers/aws.md) | `CICD-SEC-8` |
| [`SSM-000`](../providers/aws.md) | `CICD-SEC-10` |
| [`SSM-001`](../providers/aws.md) | `CICD-SEC-6` |
| [`SSM-002`](../providers/aws.md) | `CICD-SEC-9` |
| [`TF-001`](../providers/terraform.md) | `CICD-SEC-6` |
| [`TF-002`](../providers/terraform.md) | `CICD-SEC-6` |
| [`TF-003`](../providers/terraform.md) | `CICD-SEC-7` |
