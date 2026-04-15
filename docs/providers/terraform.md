# Terraform provider

Scans a parsed **`terraform show -json`** plan document — no live AWS
credentials required. The provider reads the resolved, typed resource
representation Terraform emits post-`plan`, so checks never parse raw HCL.

Every check ID mirrors its AWS-provider counterpart one-to-one. The
semantics are identical; only the data source differs.

## Producer workflow

```bash
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
pipeline_check --pipeline terraform --tf-plan plan.json
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the AWS provider.

## What it covers

| Service       | IDs               | Terraform resources consumed                                                         |
|---------------|-------------------|--------------------------------------------------------------------------------------|
| CodeBuild     | `CB-001…007`      | `aws_codebuild_project`, `aws_codebuild_source_credential`, `aws_codebuild_webhook`  |
| CodePipeline  | `CP-001…004`      | `aws_codepipeline`                                                                   |
| CodeDeploy    | `CD-001…003`      | `aws_codedeploy_deployment_group`                                                    |
| ECR           | `ECR-001…005`     | `aws_ecr_repository`, `aws_ecr_repository_policy`, `aws_ecr_lifecycle_policy`        |
| IAM           | `IAM-001…006`     | `aws_iam_role`, `aws_iam_role_policy`, `aws_iam_role_policy_attachment`, `aws_iam_policy` |
| PBAC          | `PBAC-001…002`    | `aws_codebuild_project`                                                              |
| S3            | `S3-001…005`      | `aws_codepipeline` + `aws_s3_bucket_{public_access_block,server_side_encryption_configuration,versioning,logging,policy}` |

Child modules are walked recursively; `mode="data"` entries are skipped.

## Per-check schema mapping

Every check reads Terraform's native attribute names (snake_case); single-
nested blocks appear as one-item lists. Only the fields each check
actually reads are listed below.

### CodeBuild (`aws_codebuild_project`)

| Check   | Attribute(s) read                                                                    |
|---------|--------------------------------------------------------------------------------------|
| CB-001  | `environment[0].environment_variable[*].{name,type}` — `type` defaults to PLAINTEXT  |
| CB-002  | `environment[0].privileged_mode`                                                     |
| CB-003  | `logs_config[0].cloudwatch_logs[0].status`, `logs_config[0].s3_logs[0].status`       |
| CB-004  | `build_timeout` (minutes)                                                            |
| CB-005  | `environment[0].image` (matched against `aws/codebuild/standard:<major>.<minor>`)    |
| CB-006  | `source[0].{type, auth[0].type}` + `aws_codebuild_source_credential.{server_type, auth_type}` — external VCS with OAUTH/PAT/BASIC_AUTH fails |
| CB-007  | `aws_codebuild_webhook.{project_name, filter_group[*]}` — no filter group fails      |

### CodePipeline (`aws_codepipeline`)

| Check   | Attribute(s) read                                                                              |
|---------|------------------------------------------------------------------------------------------------|
| CP-001  | `stage[*].action[*].category` — fails if any `Deploy` action precedes any `Approval`           |
| CP-002  | `artifact_store[*].encryption_key[*]` — non-empty means customer-managed KMS                   |
| CP-003  | `stage[*].action[*]` where `category="Source"` — fails on `configuration.PollForSourceChanges=true` |
| CP-004  | `stage[*].action[*]` where `category="Source"` — fails on `owner="ThirdParty"` + `provider="GitHub"` |

### CodeDeploy (`aws_codedeploy_deployment_group`)

| Check   | Attribute(s) read                                                                  |
|---------|------------------------------------------------------------------------------------|
| CD-001  | `auto_rollback_configuration[0].{enabled, events}` — requires `DEPLOYMENT_FAILURE` |
| CD-002  | `deployment_config_name` — fails when in `CodeDeployDefault.*AllAtOnce`            |
| CD-003  | `alarm_configuration[0].{enabled, alarms}`                                         |

### ECR

| Check   | Attribute(s) read                                                                  |
|---------|------------------------------------------------------------------------------------|
| ECR-001 | `aws_ecr_repository.image_scanning_configuration[0].scan_on_push`                  |
| ECR-002 | `aws_ecr_repository.image_tag_mutability`                                          |
| ECR-003 | `aws_ecr_repository_policy.policy` (JSON) joined on `repository` — fails on `Principal: "*"` |
| ECR-004 | Presence of an `aws_ecr_lifecycle_policy` joined on `repository`                   |
| ECR-005 | `aws_ecr_repository.encryption_configuration[0].{encryption_type, kms_key}` — requires KMS + CMK ARN |

### IAM (only roles trusted by CodeBuild/Pipeline/Deploy)

Scope filter: `aws_iam_role.assume_role_policy` includes
`codebuild.amazonaws.com`, `codepipeline.amazonaws.com`, or
`codedeploy.amazonaws.com` as a `Service` principal.

| Check   | Attribute(s) read                                                                                 |
|---------|---------------------------------------------------------------------------------------------------|
| IAM-001 | `managed_policy_arns` + `aws_iam_role_policy_attachment.policy_arn` — fails on `AdministratorAccess` |
| IAM-002 | `aws_iam_role_policy.policy` + `aws_iam_role.inline_policy[*].policy` — fails on `Action: "*"`    |
| IAM-003 | `aws_iam_role.permissions_boundary`                                                               |
| IAM-004 | Same policy sources as IAM-002 — fails on `iam:PassRole` / `iam:*` / `*` with `Resource: "*"`    |
| IAM-005 | `aws_iam_role.assume_role_policy` — external AWS principal without `sts:ExternalId` condition     |
| IAM-006 | Same policy sources as IAM-002 — fails on sensitive-service actions (s3/kms/secretsmanager/ssm/iam/sts/dynamodb/lambda/ec2) with `Resource: "*"` |

### PBAC (`aws_codebuild_project`)

| Check    | Attribute(s) read                                                                     |
|----------|---------------------------------------------------------------------------------------|
| PBAC-001 | `vpc_config[0].{vpc_id, subnets, security_group_ids}` — all three required           |
| PBAC-002 | `service_role` — fails when two or more projects share the same role ARN              |

### S3 (artifact buckets discovered from pipelines)

Discovery: the check walks every `aws_codepipeline.artifact_store[*].location`.
Per bucket, the helper resources below are joined by `bucket` name.

| Check   | Resource                                                   | Attribute(s) read                                                                 |
|---------|------------------------------------------------------------|-----------------------------------------------------------------------------------|
| S3-001  | `aws_s3_bucket_public_access_block`                        | `block_public_acls`, `ignore_public_acls`, `block_public_policy`, `restrict_public_buckets` |
| S3-002  | `aws_s3_bucket_server_side_encryption_configuration`       | `rule[0].apply_server_side_encryption_by_default[0].sse_algorithm`                |
| S3-003  | `aws_s3_bucket_versioning`                                 | `versioning_configuration[0].status == "Enabled"`                                 |
| S3-004  | `aws_s3_bucket_logging`                                    | `target_bucket`                                                                   |
| S3-005  | `aws_s3_bucket_policy`                                     | `policy` (JSON) — requires Deny on `s3:*` where `aws:SecureTransport=false`        |

If a helper resource is absent for a given bucket, the check fails —
matching the AWS-provider behaviour where the service returns the default
(usually "not configured").

## Limitations

- **Only the plan's resource set is visible.** Resources provisioned
  outside Terraform or via nested data sources are not scanned.
- **Compiled policy bodies only.** IAM checks read the `policy` strings
  present in the plan; they do not dereference `aws_iam_policy_document`
  data sources unless Terraform already resolved them.
- **No runtime state.** Checks like ECR-003 that in AWS-provider mode
  query the live repository policy rely here on whether an
  `aws_ecr_repository_policy` resource exists in the plan.
