# Terraform provider

Two input paths, same rule pack:

- **Plan JSON** (canonical): fully resolved attributes from
  `terraform show -json`. Every value is typed, no ambiguity.
- **HCL source** (best-effort): direct `*.tf` parsing via
  `python-hcl2`. Variable/local substitution is partial;
  unresolvable references stay opaque and findings on those
  resources get confidence-demoted.

Every AWS-mirrored check ID (CB-*, CP-*, CD-*, ECR-*, IAM-*, PBAC-*,
S3-*, CT-*, CWL-*, SM-*, CA-*, CCM-*, LMB-*, KMS-*, SSM-*, EB-*,
SIGN-*, CW-*) maps one-to-one to its AWS-provider counterpart. The
semantics are identical, only the data source differs. TF-* rules are
Terraform-only and have no AWS-runtime analogue.

## Plan JSON workflow (canonical)

```bash
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
pipeline_check --pipeline terraform --tf-plan plan.json
```

## HCL source workflow (no `terraform` binary required)

```bash
pip install 'pipeline-check[hcl]'
pipeline_check --pipeline terraform --tf-source ./infra/
```

When `main.tf` is present and no `--tf-plan` is given, `--tf-source .`
is auto-detected. Variables with a `default` and `locals` with literal
values resolve; `var.X` / `local.Y` references without defaults stay
as opaque `${...}` strings. Terraform functions (`jsonencode`,
`lookup`, `coalesce`) are not evaluated. Local child modules
(`source = "./"`) are walked recursively; remote registry modules are
skipped.

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the AWS provider.

Child modules are walked recursively; `mode = "data"` entries are
exposed separately from managed resources so rules that only care
about to-be-created state keep their current semantics.

## Per-check schema mapping

Every check reads Terraform's native attribute names (snake_case);
single-nested blocks appear as one-item lists. The summary table
below names the rule body's primary input; for the full per-attribute
path list, see the rule's source under
`pipeline_check/core/checks/terraform/rules/`.

### CodeBuild (`aws_codebuild_project`)

| Check   | Primary attribute(s) read |
|---------|---------------------------|
| CB-001  | `environment[0].environment_variable[*].{name,type,value}` |
| CB-002  | `environment[0].privileged_mode` |
| CB-003  | `logs_config[0].cloudwatch_logs[0].status`, `logs_config[0].s3_logs[0].status` |
| CB-004  | `build_timeout` |
| CB-005  | `environment[0].image` (matched against `aws/codebuild/standard:<major>.<minor>`) |
| CB-006  | `source[0].{type, auth[0].type}` + `aws_codebuild_source_credential.{server_type, auth_type}` |
| CB-007  | `aws_codebuild_webhook.{project_name, filter_group[*]}` |
| CB-008  | `source[0].buildspec` (inline detection) |
| CB-009  | `environment[0].image` (digest-pin classifier) |
| CB-010  | `aws_codebuild_webhook.filter_group[*].filter[*]` |
| CB-011  | `source[0].buildspec` (IOC matcher) |

### CodePipeline (`aws_codepipeline`)

| Check   | Primary attribute(s) read |
|---------|---------------------------|
| CP-001  | `stage[*].action[*].category` |
| CP-002  | `artifact_store[*].encryption_key[*]` |
| CP-003  | `stage[*].action[*]` where `category = "Source"` and `configuration.PollForSourceChanges` |
| CP-004  | `stage[*].action[*]` where `owner = "ThirdParty"` and `provider = "GitHub"` |
| CP-005  | Stages whose `name` matches `prod` / `production` / `live` |
| CP-007  | `pipeline_type = "V2"` + `trigger.git_configuration.pull_request[*].branches.includes` |

### CodeDeploy (`aws_codedeploy_deployment_group`)

| Check   | Primary attribute(s) read |
|---------|---------------------------|
| CD-001  | `auto_rollback_configuration[0].{enabled,events}` |
| CD-002  | `deployment_config_name` |
| CD-003  | `alarm_configuration[0].{enabled,alarms}` |

### ECR

| Check   | Resource | Attribute(s) read |
|---------|----------|-------------------|
| ECR-001 | `aws_ecr_repository` | `image_scanning_configuration[0].scan_on_push` |
| ECR-002 | `aws_ecr_repository` | `image_tag_mutability` |
| ECR-003 | `aws_ecr_repository_policy` | `policy` (JSON, joined on `repository`) |
| ECR-004 | `aws_ecr_lifecycle_policy` | presence (joined on `repository`) |
| ECR-005 | `aws_ecr_repository` | `encryption_configuration[0].{encryption_type,kms_key}` |
| ECR-006 | `aws_ecr_pull_through_cache_rule` | `{upstream_registry_url,credential_arn}` |

### IAM (scoped to CI/CD service roles)

Scope filter: `aws_iam_role.assume_role_policy` includes
`codebuild.amazonaws.com`, `codepipeline.amazonaws.com`, or
`codedeploy.amazonaws.com` as a `Service` principal.

`IAM-009` / `IAM-010` are the cross-cloud OIDC-federation analogs
(Azure / GCP). They read their own resource types and are not gated by
the AWS service-principal scope filter above.

| Check   | Primary input |
|---------|---------------|
| IAM-001 | `managed_policy_arns` + `aws_iam_role_policy_attachment.policy_arn` |
| IAM-002 | inline + attached policy JSON (Action `*`) |
| IAM-003 | `aws_iam_role.permissions_boundary` |
| IAM-004 | inline + attached policy JSON (`iam:PassRole` on `Resource = "*"`) |
| IAM-005 | `aws_iam_role.assume_role_policy` (external principal w/o `sts:ExternalId`) |
| IAM-006 | inline + attached policy JSON (sensitive actions on `Resource = "*"`) |
| IAM-008 | `aws_iam_role.assume_role_policy` (OIDC `:aud` / `:sub` pin) |
| IAM-009 | `azurerm_federated_identity_credential.{issuer,subject}` |
| IAM-010 | `google_iam_workload_identity_pool_provider` (`oidc.issuer_uri` + `attribute_condition`) |

### S3 (artifact buckets discovered from pipelines)

Discovery: walks every `aws_codepipeline.artifact_store[*].location`.
Per bucket, the helper resources below are joined by `bucket` name.

| Check   | Helper resource | Attribute(s) read |
|---------|-----------------|-------------------|
| S3-001  | `aws_s3_bucket_public_access_block` | all four `block_*` / `ignore_*` / `restrict_*` flags |
| S3-002  | `aws_s3_bucket_server_side_encryption_configuration` | `rule[0].apply_server_side_encryption_by_default[0].sse_algorithm` |
| S3-003  | `aws_s3_bucket_versioning` | `versioning_configuration[0].status` |
| S3-004  | `aws_s3_bucket_logging` | `target_bucket` |
| S3-005  | `aws_s3_bucket_policy` | `policy` (JSON, `Deny` on `aws:SecureTransport=false`) |

### Terraform-native (TF-*)

| Check  | Primary input |
|--------|---------------|
| TF-001 | `aws_iam_access_key` (any) |
| TF-002 | string leaves on `aws_db_instance`, `aws_rds_cluster`, `aws_redshift_cluster`, `aws_elasticache_replication_group`, `aws_docdb_cluster`, `aws_neptune_cluster`, `aws_opensearch_domain`, `aws_memorydb_cluster` |
| TF-003 | `aws_codebuild_project.vpc_config[0].vpc_id` + every `aws_subnet` in that VPC (`map_public_ip_on_launch`) |

## Working with data sources

The context exposes a second iterator, `ctx.data_sources(type=None)`,
for resources with `mode = "data"` (e.g. `aws_iam_policy_document`,
`aws_caller_identity`). Managed-resource iteration via
`ctx.resources()` is unchanged. In most plans, Terraform resolves
`aws_iam_policy_document` data sources inline, the rendered JSON
arrives on `aws_iam_policy.policy` or `aws_iam_role_policy.policy`
directly and the IAM checks see it without any extra work. The data
iterator only matters when the data source depends on a
to-be-created resource and Terraform defers it to apply.

## Limitations

- **Only the plan's resource set is visible.** Resources provisioned
  outside Terraform (console, other stacks) are not scanned.
- **No runtime state.** Checks like ECR-003 that in AWS-provider mode
  query the live repository policy rely here on whether an
  `aws_ecr_repository_policy` resource exists in the plan.

## What it covers

73 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [CA-001](#ca-001) | CodeArtifact domain not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CA-002](#ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CA-003](#ca-003) | CodeArtifact domain policy allows cross-account wildcard | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [CA-004](#ca-004) | CodeArtifact repo policy grants codeartifact:* with Resource '*' | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-001](#cb-001) | Secrets in plaintext environment variables | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [CB-002](#cb-002) | Privileged mode enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-003](#cb-003) | Build logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CB-004](#cb-004) | No build timeout configured | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [CB-005](#cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CB-006](#cb-006) | CodeBuild source auth uses long-lived token | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-007](#cb-007) | CodeBuild webhook has no filter_group | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CB-008](#cb-008) | CodeBuild buildspec is inline (not sourced from a protected repo) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-009](#cb-009) | CodeBuild image not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CB-010](#cb-010) | CodeBuild webhook allows fork-PR builds without actor filtering | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-011](#cb-011) | CodeBuild buildspec contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [CCM-001](#ccm-001) | CodeCommit repository has no approval rule template attached | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CCM-002](#ccm-002) | CodeCommit repository not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CCM-003](#ccm-003) | CodeCommit trigger targets SNS/Lambda in a different account | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CD-001](#cd-001) | Automatic rollback on failure not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CD-002](#cd-002) | AllAtOnce deployment config, no canary or rolling strategy | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CD-003](#cd-003) | No CloudWatch alarm monitoring on deployment group | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CP-001](#cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CP-002](#cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CP-003](#cp-003) | Source stage using polling instead of event-driven trigger | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [CP-004](#cp-004) | Legacy ThirdParty/GitHub source action (OAuth token) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CP-005](#cp-005) | Production Deploy stage has no preceding ManualApproval | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CP-007](#cp-007) | CodePipeline v2 PR trigger accepts all branches | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CT-001](#ct-001) | No active CloudTrail trail in region | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CT-002](#ct-002) | CloudTrail log-file validation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CT-003](#ct-003) | CloudTrail trail is not multi-region | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CW-001](#cw-001) | No CloudWatch alarm on CodeBuild FailedBuilds metric | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [CWL-001](#cwl-001) | CodeBuild log group has no retention policy | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [CWL-002](#cwl-002) | CodeBuild log group not KMS-encrypted | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [EB-001](#eb-001) | No EventBridge rule for CodePipeline failure notifications | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [EB-002](#eb-002) | EventBridge rule has a wildcard target ARN | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ECR-001](#ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ECR-002](#ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ECR-003](#ecr-003) | Repository policy allows public access | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ECR-004](#ecr-004) | No lifecycle policy configured | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [ECR-005](#ecr-005) | Repository encrypted with AES256 rather than KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ECR-006](#ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-001](#iam-001) | CI/CD role has AdministratorAccess policy attached | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [IAM-002](#iam-002) | CI/CD role has wildcard Action in attached policy | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-003](#iam-003) | CI/CD role has no permission boundary | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [IAM-004](#iam-004) | CI/CD role can PassRole to any role | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-005](#iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-006](#iam-006) | Sensitive actions granted with wildcard Resource | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [IAM-008](#iam-008) | OIDC-federated role trust policy missing audience or subject pin | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-009](#iam-009) | Azure federated identity credential trusts a broad GitHub subject | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-010](#iam-010) | GCP workload identity provider has no repository attribute condition | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [KMS-001](#kms-001) | Customer-managed symmetric KMS key has rotation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [KMS-002](#kms-002) | KMS key policy grants kms:* to an IAM principal | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [LMB-001](#lmb-001) | Lambda function has no code-signing config | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [LMB-002](#lmb-002) | Lambda Function URL configured with AuthType = NONE | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [LMB-003](#lmb-003) | Lambda environment variables contain plaintext secrets | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [LMB-004](#lmb-004) | Lambda resource policy grants wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [PBAC-001](#pbac-001) | CodeBuild project has no VPC configuration | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PBAC-002](#pbac-002) | CodeBuild service role shared across multiple projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PBAC-003](#pbac-003) | CodeBuild security group allows 0.0.0.0/0 all-port egress | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PBAC-005](#pbac-005) | Pipeline action roles all equal the pipeline-level role | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [S3-001](#s3-001) | Artifact bucket public access block not fully enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [S3-002](#s3-002) | Artifact bucket server-side encryption not configured | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [S3-003](#s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [S3-004](#s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [S3-005](#s3-005) | Artifact bucket missing aws:SecureTransport deny | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SIGN-001](#sign-001) | No active AWS Signer profile exists for the Lambda platform | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SM-001](#sm-001) | Secrets Manager secret has no rotation configured | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SM-002](#sm-002) | Secrets Manager resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [SSM-001](#ssm-001) | SSM parameter with secret-like name stored as String, not SecureString | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SSM-002](#ssm-002) | SecureString uses alias/aws/ssm rather than a customer CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [TF-001](#tf-001) | Plan declares aws_iam_access_key (long-lived credential) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TF-002](#tf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [TF-003](#tf-003) | CodeBuild VPC config references a public subnet | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## CA-001: CodeArtifact domain not encrypted with customer KMS CMK { #ca-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads ``aws_codeartifact_domain.encryption_key``. An empty value (or the default AWS-managed key) means anyone with ``codeartifact:Read*`` can read packages — the encryption key isn't a separate authorization boundary.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``encryption_key`` on every ``aws_codeartifact_domain`` to a customer-managed KMS CMK ARN. The default AWS-owned key can't be rotated or scoped by IAM policy.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CA-002: CodeArtifact repository has a public external connection { #ca-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads ``aws_codeartifact_repository.external_connections``. Any value beginning with ``public:`` (e.g. ``public:npmjs``) fetches packages directly from the public ecosystem with no intermediate scrub.

<div class="pg-rule__rec" markdown>

**Recommended action**

Route every ``aws_codeartifact_repository.external_connections`` through a private mirror that caches and vets public packages, or scope it with upstream allow-lists. Direct ``public:npmjs``/``public:pypi`` is dependency-confusion fuel.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CA-003: CodeArtifact domain policy allows cross-account wildcard { #ca-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Parses ``aws_codeartifact_domain_permissions_policy.policy_document``. Fires on any ``Allow`` statement that names a wildcard principal — wildcard at the domain level grants the bearer access to every repo in the domain.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``Principal: "*"`` (or ``Principal.AWS = "*"``) from every ``Allow`` statement in ``aws_codeartifact_domain_permissions_policy``. Name the specific accounts and add an ``aws:PrincipalOrgID`` condition.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CA-004: CodeArtifact repo policy grants codeartifact:* with Resource '*' { #ca-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Parses ``aws_codeartifact_repository_permissions_policy.policy_document``. Fires when an ``Allow`` statement pairs ``codeartifact:*`` (or ``*``) with ``Resource = "*"``. That combination lets the principal publish, delete, and rewrite every package version in the repo.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enumerate specific actions (``codeartifact:GetPackageVersion``, ``codeartifact:DescribePackageVersion``) and resources (specific package ARNs) instead of ``codeartifact:*`` with ``Resource = "*"``.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CB-001: Secrets in plaintext environment variables { #cb-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Walks every ``aws_codebuild_project.environment[0].environment_variable[*]``. Flags any entry whose ``type`` is ``PLAINTEXT`` (or absent, which Terraform defaults to PLAINTEXT) when (a) the ``name`` matches a secret-like pattern (``PASSWORD``, ``TOKEN``, ``API_KEY``, …) or (b) the ``value`` matches one of pipeline-check's known credential shapes (cloud access keys, VCS / registry / CI / cloud-service tokens, Slack ``xox*`` tokens, JWTs — the same shared detector catalog GHA-008 uses). Plaintext values land in the AWS console, CloudTrail, and build logs.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move secrets to AWS Secrets Manager or SSM Parameter Store and reference them using ``type = "SECRETS_MANAGER"`` or ``type = "PARAMETER_STORE"`` on the corresponding ``environment_variable`` block.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CB-002: Privileged mode enabled { #cb-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Reads ``aws_codebuild_project.environment[0].privileged_mode``. Privileged mode hands the build container root-level access to the Docker daemon on the host. A compromised build can escape the container, modify other in-flight builds on the same host, or steal credentials mounted on the instance.

<div class="pg-rule__rec" markdown>

**Recommended action**

Disable ``environment[0].privileged_mode`` unless the project genuinely needs Docker-in-Docker. Where DinD is unavoidable, consider Kaniko or BuildKit's rootless mode and keep the buildspec under branch protection.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CB-003: Build logging not enabled { #cb-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Reads both ``logs_config[0].cloudwatch_logs[0].status`` and ``logs_config[0].s3_logs[0].status``. Without either, the build's stdout/stderr is captured only in the in-flight console view, audit and post-incident review have no record of what the build actually did.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable at least one of ``logs_config[0].cloudwatch_logs[0].status = "ENABLED"`` or ``logs_config[0].s3_logs[0].status = "ENABLED"``. CloudWatch is the easier default; pair S3 with an object-lock bucket if you need tamper-evident retention.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CB-004: No build timeout configured { #cb-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Reads ``aws_codebuild_project.build_timeout`` (in minutes). Projects left at the AWS maximum of 480 minutes let a runaway or hijacked build consume compute and delay detection of a compromised pipeline stage.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``build_timeout`` to a value matched to your real build duration (15–60 minutes is typical). Pair with a CloudWatch alarm on ``AWS/CodeBuild`` ``BuildDuration`` so builds that approach the cap surface as runtime alerts, not stuck jobs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CB-005: Outdated managed build image { #cb-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Matches ``environment[0].image`` against ``aws/codebuild/standard:<major>.<minor>``. Older managed images carry unpatched OS packages, runtimes, and build tools, every artifact they produce inherits those gaps.

<div class="pg-rule__rec" markdown>

**Recommended action**

Update ``environment[0].image`` to the latest ``aws/codebuild/standard:<major>.0`` release. For custom or third-party images, pin by ``@sha256:<digest>`` instead of a mutable tag (see CB-009).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CB-006: CodeBuild source auth uses long-lived token { #cb-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Reads ``source[0].{type,auth[0].type}`` plus any ``aws_codebuild_source_credential.{server_type,auth_type}`` side resource. Fires when an external VCS source (``GITHUB``, ``GITHUB_ENTERPRISE``, ``BITBUCKET``) is authenticated with a long-lived OAuth/PAT/BASIC_AUTH credential.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``OAUTH`` / ``PERSONAL_ACCESS_TOKEN`` / ``BASIC_AUTH`` with an AWS CodeConnections (CodeStar) connection and reference it from ``source.location``. Tokens stored via ``aws_codebuild_source_credential`` or inline ``source.auth`` don't rotate and survive the engineer who created them.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CB-007: CodeBuild webhook has no filter_group { #cb-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Joins ``aws_codebuild_webhook`` records to their parent ``aws_codebuild_project`` via ``project_name`` and reads ``filter_group[*]``. A webhook with no filter group accepts every push event from every principal, including forks for public repositories.

<div class="pg-rule__rec" markdown>

**Recommended action**

Define ``filter_group`` blocks on the ``aws_codebuild_webhook`` resource that restrict triggers to specific branches, actors, and event types. At minimum include an ``ACTOR_ACCOUNT_ID`` filter to keep fork PRs from triggering builds.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CB-008: CodeBuild buildspec is inline (not sourced from a protected repo) { #cb-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Inspects ``aws_codebuild_project.source[0].buildspec``. Flags multi-line literal values or values that begin with YAML preamble (``version:``, ``phases:``) — those indicate an inline spec that any principal with ``codebuild:UpdateProject`` can rewrite without going through code review.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move buildspec content into a ``buildspec.yml`` (or similar) inside the source repository, under branch protection. Reference it from ``source.buildspec`` only by relative path.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CB-009: CodeBuild image not pinned by digest { #cb-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Classifies ``environment[0].image`` using the same shared image classifier the GitLab / Jenkins / Azure DevOps providers use. Mutable tags let an upstream image swap execute on the next build with no plan change.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin ``environment[0].image`` by ``@sha256:<digest>`` rather than a mutable tag. AWS-managed ``aws/codebuild/standard:N`` images are exempted (AWS owns the rotation contract).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CB-010: CodeBuild webhook allows fork-PR builds without actor filtering { #cb-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-863</span>
</div>

Reads ``aws_codebuild_webhook.filter_group[*].filter[*]``. For each group that covers a ``PULL_REQUEST_*`` event, fires when no sibling ``ACTOR_ACCOUNT_ID`` filter constrains the PR author.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an ``ACTOR_ACCOUNT_ID`` filter to every ``filter_group`` whose ``EVENT`` filter covers a ``PULL_REQUEST_*`` event. Without it, a fork-PR build runs with the project's service role.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CB-011: CodeBuild buildspec contains indicators of malicious activity { #cb-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-506</span>
</div>

Runs the shared buildspec-IOC matcher against any inline ``source[0].buildspec``. The matcher looks for reverse-shell payloads, miner CLIs, secret-exfil patterns, and credential-grabbing one-liners. Repo-sourced buildspecs are skipped — the text isn't visible in the plan.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat any hit on this rule as a potential pipeline compromise. Identify the commit that introduced the buildspec, rotate every credential reachable by the project's service role, and move the buildspec to a repo-sourced file under branch protection (see CB-008).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CCM-001: CodeCommit repository has no approval rule template attached { #ccm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

Looks for at least one ``aws_codecommit_approval_rule_template_association`` joined to the repository by ``repository_name``. Without an approval rule, the merge gate every reviewer assumes exists doesn't.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create an ``aws_codecommit_approval_rule_template`` requiring at least one reviewer from a named team, then associate it with the repository via ``aws_codecommit_approval_rule_template_association``.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CCM-002: CodeCommit repository not encrypted with customer KMS CMK { #ccm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads ``aws_codecommit_repository.kms_key_id``. Empty values fall back to AWS-owned encryption, which can't be audited or scoped to a specific role via key policy.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``kms_key_id`` on every ``aws_codecommit_repository`` to a customer-managed CMK ARN. Source code carries IP, credentials, and customer data — the encryption boundary matters.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CCM-003: CodeCommit trigger targets SNS/Lambda in a different account { #ccm-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-942</span>
</div>

Compares ``aws_codecommit_trigger.destination_arn`` against the current account ID (from ``aws_caller_identity`` data source). A trigger whose destination lives in another account leaks repository activity outside the trust boundary.

<div class="pg-rule__rec" markdown>

**Recommended action**

Point ``aws_codecommit_trigger.destination_arn`` at an SNS topic or Lambda function in the same account. If cross-account is intentional, document the receiving account in your threat model and baseline this finding.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CD-001: Automatic rollback on failure not enabled { #cd-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-754</span>
</div>

Reads ``aws_codedeploy_deployment_group.auto_rollback_configuration[0]``. The block needs ``enabled = true`` AND ``"DEPLOYMENT_FAILURE"`` present in ``events`` for the deployment group to self-heal.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable ``auto_rollback_configuration`` with at least the ``DEPLOYMENT_FAILURE`` event so a failed release returns the environment to its prior state without manual intervention.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CD-002: AllAtOnce deployment config, no canary or rolling strategy { #cd-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-754</span>
</div>

Reads ``aws_codedeploy_deployment_group.deployment_config_name``. Fires when the value is ``CodeDeployDefault.AllAtOnce``, ``LambdaAllAtOnce``, or ``ECSAllAtOnce`` — these route every request to the new revision simultaneously, leaving no canary validation window.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch ``deployment_config_name`` to a canary or linear config (e.g. ``CodeDeployDefault.LambdaCanary10Percent5Minutes``). A staged rollout gives alarm-based rollback a window to catch regressions before they hit 100% of traffic.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CD-003: No CloudWatch alarm monitoring on deployment group { #cd-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Reads ``aws_codedeploy_deployment_group.alarm_configuration[0].{enabled,alarms}``. Without an alarm list, error spikes or latency regressions from a release won't auto-halt the deployment or trigger rollback.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add CloudWatch alarms to ``alarm_configuration.alarms`` and set ``enabled = true``. Pair this with CD-001 — alarm-triggered rollback only fires when at least one alarm exists to monitor.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CP-001: No approval action before deploy stages { #cp-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

Walks ``aws_codepipeline.stage[*].action[*].category``. Fires when any ``Deploy`` action is reachable from the source without an intervening ``Approval`` action upstream of it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``Manual`` approval action to a stage that precedes every ``Deploy``-category action. Pipelines that auto-promote to production trust every prior stage's findings absolutely.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CP-002: Artifact store not encrypted with customer-managed KMS key { #cp-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads every ``aws_codepipeline.artifact_store[*].encryption_key`` block. An empty list means the store falls back to AWS-owned-key S3 SSE; with a CMK you control key policy and rotation independently.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``artifact_store[*].encryption_key`` to a customer-managed KMS CMK on every artifact store. Default S3 SSE is encrypted by an AWS-owned key you can't rotate or scope by IAM.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CP-003: Source stage using polling instead of event-driven trigger { #cp-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-1188</span>
</div>

Reads ``stage[*].action[*]`` where ``category = "Source"``. Fires when ``configuration.PollForSourceChanges`` is the literal string ``"true"`` — polling forces a 60s minimum trigger lag and bypasses the audit trail an EventBridge rule would leave.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``configuration.PollForSourceChanges = "false"`` on every ``Source`` action and create an EventBridge rule (or ``aws_codestarconnections_connection``) to drive change detection on commit.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CP-004: Legacy ThirdParty/GitHub source action (OAuth token) { #cp-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Fires on any ``stage[*].action[*]`` with ``category = "Source"``, ``owner = "ThirdParty"``, ``provider = "GitHub"``. The v1 GitHub action authenticates with a long-lived OAuth token literally stored in the pipeline configuration, anyone with ``codepipeline:GetPipeline`` reads it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Migrate the source action to ``owner = "AWS", provider = "CodeStarSourceConnection"`` and point ``configuration.ConnectionArn`` at an ``aws_codestarconnections_connection``. The connection brokers short-lived OIDC credentials in place of the embedded OAuth token.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CP-005: Production Deploy stage has no preceding ManualApproval { #cp-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

A stricter version of CP-001 scoped to production-named stages. Walks ``stage[*].name`` for ``prod`` / ``production`` / ``live`` substrings and requires a preceding ``Approval`` action — even pipelines that pass CP-001 globally often skip the gate on the production stage.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``Manual`` approval action in the stage that precedes any stage whose name contains ``prod``, ``production``, or ``live`` and contains a Deploy action. Approval surfaces the release decision as an auditable event.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CP-007: CodePipeline v2 PR trigger accepts all branches { #cp-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-863</span>
</div>

Inspects v2 pipelines (``pipeline_type = "V2"``) whose ``trigger.git_configuration`` declares a ``pull_request`` block without ``branches.includes``. The trigger then matches every PR, fork-source PRs included.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``trigger.git_configuration.push[*].branches.includes`` or ``trigger.git_configuration.pull_request[*].branches.includes`` to the specific branches the pipeline expects. An empty include list runs on every branch event, including fork-PR rebases.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CT-001: No active CloudTrail trail in region { #ct-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Counts ``aws_cloudtrail`` resources in the plan. Without a trail (declared here or out-of-band), management-plane activity has no durable audit record — every incident reply starts from scratch.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare at least one ``aws_cloudtrail`` resource — typically a single ``is_multi_region_trail = true`` trail sending events to a write-protected S3 bucket. If trails are managed out-of-band (e.g. Control Tower), this rule's INFO baseline is the right place to suppress it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CT-002: CloudTrail log-file validation disabled { #ct-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-353</span>
</div>

Reads ``aws_cloudtrail.enable_log_file_validation``. Without it, an attacker with ``s3:PutObject`` on the trail's bucket can rewrite event records and there's no cryptographic record of the original.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``enable_log_file_validation = true`` on every ``aws_cloudtrail`` resource. CloudTrail will then write hash digests S3 cannot tamper with, post-incident validation can detect log forgery.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CT-003: CloudTrail trail is not multi-region { #ct-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Reads ``aws_cloudtrail.is_multi_region_trail`` for every declared trail. Multi-region is the only configuration that guarantees you'll see ``CreateAccessKey`` in ``ap-south-1`` from your ``us-east-1`` trail.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``is_multi_region_trail = true`` so a single trail captures activity from every region. A region-scoped trail misses anything an attacker does in another region (a classic pivot).

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CW-001: No CloudWatch alarm on CodeBuild FailedBuilds metric { #cw-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Gated check: fires only when the plan declares ``aws_codebuild_project``. Passes when at least one ``aws_cloudwatch_metric_alarm`` is configured for ``namespace = "AWS/CodeBuild"`` + ``metric_name = "FailedBuilds"``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare an ``aws_cloudwatch_metric_alarm`` with ``namespace = "AWS/CodeBuild"`` and ``metric_name = "FailedBuilds"`` and route it to an actionable destination (PagerDuty, Slack via Chatbot, SNS topic with a human responder).

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CWL-001: CodeBuild log group has no retention policy { #cwl-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-1188</span>
</div>

Filters ``aws_cloudwatch_log_group`` by ``name`` prefix ``/aws/codebuild/`` and reads ``retention_in_days``. Unbounded retention isn't free; it also makes incident response harder when there are years of irrelevant logs to grep.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``retention_in_days`` on every ``aws_cloudwatch_log_group`` whose name starts with ``/aws/codebuild/``. 30 / 90 / 365 days are typical; match the figure to your compliance regime.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CWL-002: CodeBuild log group not KMS-encrypted { #cwl-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads ``aws_cloudwatch_log_group.kms_key_id`` on log groups whose name starts with ``/aws/codebuild/``. Without a CMK, logs are encrypted with an AWS-owned key, which can't be audited or scoped by IAM.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``kms_key_id`` on every ``aws_cloudwatch_log_group`` whose name starts with ``/aws/codebuild/`` to a customer-managed CMK ARN. Build logs commonly carry secret fragments and environment dumps.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## EB-001: No EventBridge rule for CodePipeline failure notifications { #eb-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Looks for at least one ``aws_cloudwatch_event_rule`` whose ``event_pattern`` JSON matches ``aws.codepipeline`` ``Pipeline Execution State Change`` events filtered to ``FAILED``. Without one, the only failure signal is engineers noticing the pipeline didn't update.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare an ``aws_cloudwatch_event_rule`` whose ``event_pattern`` matches ``aws.codepipeline`` events with ``detail.state = "FAILED"``, and target it at the notification destination of your choice (SNS, Slack via Chatbot, PagerDuty).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## EB-002: EventBridge rule has a wildcard target ARN { #eb-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-441</span>
</div>

Reads ``aws_cloudwatch_event_target.arn``. A literal ``*`` in the ARN is the offending shape, even when EventBridge allows it at the API level, it makes the target opaque to any reviewer trying to trace event flow.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin ``aws_cloudwatch_event_target.arn`` to a specific function or queue ARN. Wildcards in target ARNs (e.g. ``arn:aws:lambda:*:*:function:*``) defeat the per-target audit trail and let any resource matching the pattern receive the event.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ECR-001: Image scanning on push not enabled { #ecr-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Reads ``aws_ecr_repository.image_scanning_configuration[0].scan_on_push``. Without it, a freshly-pushed image goes straight into deployable storage with no known-CVE pass.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``image_scanning_configuration { scan_on_push = true }`` on every ``aws_ecr_repository``. For deeper coverage, also enable Inspector v2 enhanced scanning at the registry level.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ECR-002: Image tags are mutable { #ecr-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Reads ``aws_ecr_repository.image_tag_mutability``. Default is ``MUTABLE`` — anyone with ``ecr:PutImage`` on the repo can overwrite any existing tag, including release tags consumed by production deployments.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``image_tag_mutability = "IMMUTABLE"`` on every ``aws_ecr_repository``. With immutable tags, a tag points at exactly one digest forever; an attacker can't swap ``:latest`` mid-deploy.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ECR-003: Repository policy allows public access { #ecr-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Parses ``aws_ecr_repository_policy.policy`` JSON joined to the repo by ``repository``. Flags any ``Allow`` statement that names a wildcard principal — a wildcard there lets every AWS account in the world pull the image.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop any ``Statement`` with ``Effect = "Allow"`` plus ``Principal = "*"`` (or ``Principal.AWS = "*"`` / ``Principal.Service = "*"``). Use specific account IDs and lock cross-account access to a known set.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## ECR-004: No lifecycle policy configured { #ecr-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Looks for an ``aws_ecr_lifecycle_policy`` joined by ``repository`` for each ``aws_ecr_repository``. Without a lifecycle policy, images and untagged digests accumulate indefinitely — old vulnerable images stay deployable and storage costs creep.

<div class="pg-rule__rec" markdown>

**Recommended action**

Attach an ``aws_ecr_lifecycle_policy`` that expires untagged and old tagged images. Both bounded image age and bounded image count are reasonable starting points; pick what matches your release cadence.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ECR-005: Repository encrypted with AES256 rather than KMS CMK { #ecr-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads ``aws_ecr_repository.encryption_configuration[0].{encryption_type,kms_key}``. The AES256 default uses an AWS-owned key — you can't audit who used it or revoke access with a key policy.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``encryption_configuration { encryption_type = "KMS" kms_key = aws_kms_key.ecr.arn }`` referencing a customer-managed CMK with a key policy that scopes ``kms:Decrypt`` to the principals that legitimately pull.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ECR-006: ECR pull-through cache rule uses an untrusted upstream { #ecr-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads ``aws_ecr_pull_through_cache_rule.{upstream_registry_url,credential_arn}``. Fires when the upstream is not on the trusted allow-list AND no credential ARN is configured — the cache then proxies any image from an attacker-controlled domain into your registry.

<div class="pg-rule__rec" markdown>

**Recommended action**

Either scope ``upstream_registry_url`` to a trusted registry (``public.ecr.aws``, ``registry.k8s.io``, ``ghcr.io``, ``gcr.io``) or set ``credential_arn`` so the upstream registry authenticates the pull.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## IAM-001: CI/CD role has AdministratorAccess policy attached { #iam-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Considers a role CI/CD-scoped when its ``assume_role_policy`` trusts ``codebuild.amazonaws.com``, ``codepipeline.amazonaws.com``, or ``codedeploy.amazonaws.com``. Reads ``managed_policy_arns`` plus every ``aws_iam_role_policy_attachment.policy_arn`` joined to the role, fires when ``arn:aws:iam::aws:policy/AdministratorAccess`` appears.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``AdministratorAccess`` with least-privilege policies that grant only the specific actions and resources the build actually needs. Pair with IAM-003 (permissions boundary) so a future policy edit can't quietly re-broaden the role.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-002: CI/CD role has wildcard Action in attached policy { #iam-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Walks every policy document attached to a CI/CD role: inline ``aws_iam_role_policy``, inline blocks on the role itself, customer-managed ``aws_iam_policy`` joined through ``aws_iam_role_policy_attachment``. Fires when any ``Allow`` statement names ``"*"`` in ``Action``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enumerate the specific IAM actions the role needs and drop ``Action = "*"`` (or ``Action = ["*"]``) entirely. Tools like Access Analyzer or CloudTrail-based policy generation can suggest the minimum set.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## IAM-003: CI/CD role has no permission boundary { #iam-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Reads ``aws_iam_role.permissions_boundary`` on every CI/CD-scoped role. Without a boundary, every additive policy attached to the role takes immediate effect — there's no second layer constraining the maximum reach.

<div class="pg-rule__rec" markdown>

**Recommended action**

Attach a permissions boundary policy via ``permissions_boundary = aws_iam_policy.cicd_boundary.arn``. Boundaries cap the effective permissions of the role even if an admin later attaches a broader policy.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-004: CI/CD role can PassRole to any role { #iam-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Inspects every policy reachable from a CI/CD role. Fires on any ``Allow`` statement granting ``iam:PassRole`` (or ``iam:*`` / ``*``) with ``Resource = "*"``. PassRole on a wildcard resource is one of the canonical privilege-escalation primitives in AWS.

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope ``iam:PassRole`` to the specific role ARNs the pipeline must hand off to (CodeDeploy task role, ECS task role, …). Add an ``iam:PassedToService`` condition so the role can only be passed to the service that actually consumes it.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-005: CI/CD role trust policy missing sts:ExternalId { #iam-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-441</span>
</div>

Parses ``aws_iam_role.assume_role_policy``. Walks every ``Allow`` statement whose ``Principal.AWS`` is an external account, and fires when no ``Condition`` on the statement carries ``sts:ExternalId``. Without it the role is vulnerable to the confused-deputy pattern.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``Condition`` block with ``StringEquals.sts:ExternalId`` to every trust-policy statement that allows an external AWS account to assume the role. Generate a high-entropy ExternalId once and store it in the relying party's configuration.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## IAM-006: Sensitive actions granted with wildcard Resource { #iam-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Inspects every policy reachable from a CI/CD role. Fires on any ``Allow`` statement pairing a sensitive service action (``s3:*``, ``kms:*``, ``secretsmanager:*``, ``ssm:*``, ``iam:*``, ``sts:*``, ``dynamodb:*``, ``lambda:*``, ``ec2:*``) with ``Resource = "*"``. A compromised build with these reaches into prod data, secrets, and IAM in one step.

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope ``Resource`` to specific ARNs (bucket ARNs, key ARNs, secret ARNs, role ARNs). Reserve ``Resource = "*"`` for actions that genuinely require it (e.g. ``ec2:Describe*``, ``cloudwatch:DescribeAlarms``).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-008: OIDC-federated role trust policy missing audience or subject pin { #iam-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-287</span>
</div>

Inspects every ``aws_iam_role.assume_role_policy`` that carries an OIDC trust statement (provider URL like ``token.actions.githubusercontent.com``). Fires when ``Condition`` omits the audience or subject claim, or when a GitHub ``repo:`` subject wildcards the repo or ref segment (``repo:org/*``, ``repo:org/repo:*``) or trusts the ``pull_request`` context. Without a specific repo + ref pin, an untrusted workflow (including a fork PR) can assume the role.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add ``Condition.StringEquals`` (or ``StringLike``) entries pinning both ``<host>:aud`` and ``<host>:sub`` to specific values. For GitHub Actions: pin ``aud`` to ``sts.amazonaws.com`` and ``sub`` to ``repo:<org>/<repo>:ref:refs/heads/main`` (or the env / branch combination the role expects).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-009: Azure federated identity credential trusts a broad GitHub subject { #iam-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-287</span> <span class="pg-tag pg-tag--cwe">CWE-1390</span>
</div>

Fires on an ``azurerm_federated_identity_credential`` whose ``issuer`` is the GitHub Actions OIDC issuer and whose ``subject`` wildcards the org/repo segment, wildcards the ref segment, or uses the ``pull_request`` context. Azure's Workload Identity Federation is the Azure analogue of the AWS OIDC trust IAM-008 audits; no other rule reads ``azurerm_federated_identity_credential``. A subject pinned to a specific repo and ref/environment passes.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin ``azurerm_federated_identity_credential.subject`` to one repository AND a specific ref or environment, e.g. ``repo:myorg/myrepo:ref:refs/heads/main`` or ``repo:myorg/myrepo:environment:production``. An org wildcard (``repo:myorg/*``), a ref wildcard (``repo:myorg/myrepo:*``), or the ``pull_request`` context lets an untrusted workflow run (including a fork pull request) exchange its GitHub token for your Azure identity. Use one federated credential per repo+environment rather than a wildcarded subject.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-010: GCP workload identity provider has no repository attribute condition { #iam-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-287</span> <span class="pg-tag pg-tag--cwe">CWE-1390</span>
</div>

Fires on a ``google_iam_workload_identity_pool_provider`` with an ``oidc`` block that either has no ``attribute_condition`` at all (any token from the issuer federates), or - for the GitHub / GitLab CI issuers - has a condition that never references the repository (``repository`` / ``repo:`` / ``sub``), so it does not constrain which repo can assume the identity. GHA-062 audits the same surface from a GitHub workflow's sibling files; this reads the Terraform resource directly.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``attribute_condition`` on every ``google_iam_workload_identity_pool_provider`` with an ``oidc`` block, and make it constrain the source repository, e.g. ``assertion.repository_owner == 'myorg'`` or ``assertion.repository == 'myorg/myrepo'``. Without a condition that pins the repo, any identity the issuer mints (any GitHub repo on the planet, for the GitHub issuer) can exchange its token for a Google access token scoped to whatever the pool grants. Restrict ``allowed_audiences`` as well.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## KMS-001: Customer-managed symmetric KMS key has rotation disabled { #kms-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-322</span>
</div>

Reads ``aws_kms_key.enable_key_rotation`` on symmetric keys (``customer_master_key_spec = "SYMMETRIC_DEFAULT"`` or absent). Asymmetric keys are skipped — KMS doesn't rotate them, key replacement is the only path.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``enable_key_rotation = true`` on every symmetric ``aws_kms_key``. KMS rotates the underlying key material once per year transparently, no downstream change is needed.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## KMS-002: KMS key policy grants kms:* to an IAM principal { #kms-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Parses ``aws_kms_key.policy`` (or ``aws_kms_key_policy.policy``). Fires on any ``Allow`` statement that pairs ``kms:*`` with a non-root IAM principal — that's the canonical key-compromise primitive.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enumerate the specific KMS actions each principal needs (``kms:Encrypt``, ``kms:Decrypt``, ``kms:GenerateDataKey``, ``kms:DescribeKey``). Reserve ``kms:*`` for the root principal that owns the key.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## LMB-001: Lambda function has no code-signing config { #lmb-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Reads ``aws_lambda_function.code_signing_config_arn``. Without it, Lambda accepts any zip the deployer can upload — there's no cryptographic check that the artifact came from the expected pipeline.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``code_signing_config_arn`` on every ``aws_lambda_function`` to an ``aws_lambda_code_signing_config`` whose allowed publishers list signing profiles your release pipeline uses.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## LMB-002: Lambda Function URL configured with AuthType = NONE { #lmb-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

Reads ``aws_lambda_function_url.authorization_type``. The ``NONE`` setting exposes the function over a public HTTPS endpoint with no authentication — if invoke is the goal, AWS_IAM with a scoped resource policy is almost always the right answer.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``authorization_type = "AWS_IAM"`` on every ``aws_lambda_function_url`` and grant invoke permission via explicit ``aws_lambda_permission`` resources rather than leaving the URL public.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## LMB-003: Lambda environment variables contain plaintext secrets { #lmb-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Walks ``aws_lambda_function.environment[0].variables`` for (a) secret-like names (``PASSWORD``, ``TOKEN``, ``API_KEY``) and (b) credential-shaped values (``AKIA…``, ``ghp_…``, ``xox*``, JWTs). Env vars are visible to anyone with ``lambda:GetFunctionConfiguration``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move secrets to Secrets Manager or SSM Parameter Store and read them at function init time. For static values that must live in the env, encrypt them at rest with a customer CMK via ``kms_key_arn``.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## LMB-004: Lambda resource policy grants wildcard principal { #lmb-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Inspects every ``aws_lambda_permission`` resource. Fires when ``principal`` is ``"*"`` or any other wildcard form. A wildcard invoker exposes the function — and whatever role it executes with — to the whole internet.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop any ``aws_lambda_permission`` with ``principal = "*"`` (or ``principal = "arn:aws:iam::*:root"``). Name the specific service principal or account that needs invoke, and scope further with ``source_account`` / ``source_arn`` conditions.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PBAC-001: CodeBuild project has no VPC configuration { #pbac-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-1327</span>
</div>

Reads ``aws_codebuild_project.vpc_config[0].{vpc_id,subnets,security_group_ids}``. All three must be set. Without VPC config, build nodes run in AWS-managed infrastructure with unrestricted outbound internet — every exfiltration path is open.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``vpc_config { vpc_id = …, subnets = […], security_group_ids = […] }`` on every ``aws_codebuild_project``. Use private subnets with egress scoped to the package mirrors and AWS endpoints the build actually needs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PBAC-002: CodeBuild service role shared across multiple projects { #pbac-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Counts ``aws_codebuild_project.service_role`` collisions. When two or more projects share the same role ARN, a build compromise in any one of them inherits the others' permissions wholesale.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create one ``aws_iam_role`` per ``aws_codebuild_project`` and reference it via ``service_role``. Per-project roles cap the blast radius of a hijacked build to the resources that one project legitimately needs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PBAC-003: CodeBuild security group allows 0.0.0.0/0 all-port egress { #pbac-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-1327</span>
</div>

Walks ``aws_security_group.egress[*]`` for every SG attached to a CodeBuild project's ``vpc_config``. Fires on any rule that allows ``0.0.0.0/0`` on the full port range — that's a completely open exfiltration channel.

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope egress to the specific destinations the build needs (package mirrors, AWS endpoints via VPC interface endpoints). Drop the catch-all ``egress { cidr_blocks = ["0.0.0.0/0"], from_port = 0, to_port = 0, protocol = "-1" }``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PBAC-005: Pipeline action roles all equal the pipeline-level role { #pbac-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Compares each ``stage[*].action[*].role_arn`` against the pipeline's top-level ``role_arn``. When all action-level values are empty or identical to the pipeline role, every stage runs with the same blast-radius — a compromise in any one action reaches the others' resources.

<div class="pg-rule__rec" markdown>

**Recommended action**

Assign a least-privilege ``role_arn`` to every ``stage[*].action[*]`` that needs cross-account or cross-service permissions, instead of falling back to the ``aws_codepipeline.role_arn``.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## S3-001: Artifact bucket public access block not fully enabled { #s3-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Discovers pipeline artifact buckets from ``aws_codepipeline.artifact_store[*].location``. For each, joins the corresponding ``aws_s3_bucket_public_access_block`` by ``bucket``. Any of the four PAB flags left ``false`` (or missing entirely) lets an ACL or bucket policy make build artifacts publicly readable.

<div class="pg-rule__rec" markdown>

**Recommended action**

Attach an ``aws_s3_bucket_public_access_block`` with all four flags ``true`` to every artifact bucket: ``block_public_acls = true``, ``ignore_public_acls = true``, ``block_public_policy = true``, ``restrict_public_buckets = true``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## S3-002: Artifact bucket server-side encryption not configured { #s3-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Discovers pipeline artifact buckets from ``aws_codepipeline.artifact_store[*].location`` and joins ``aws_s3_bucket_server_side_encryption_configuration`` by ``bucket``. Reads ``rule[0].apply_server_side_encryption_by_default[0].sse_algorithm``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Attach an ``aws_s3_bucket_server_side_encryption_configuration`` with ``rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }`` referencing a customer-managed KMS CMK.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## S3-003: Artifact bucket versioning not enabled { #s3-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-353</span>
</div>

Joins ``aws_s3_bucket_versioning`` by ``bucket`` for every pipeline artifact bucket. Reads ``versioning_configuration[0].status``, passes only when it is ``Enabled``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Attach an ``aws_s3_bucket_versioning`` with ``versioning_configuration { status = "Enabled" }`` to every artifact bucket. Versioning lets you recover from accidental or malicious overwrites without restoring from external backups.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## S3-004: Artifact bucket access logging not enabled { #s3-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Joins ``aws_s3_bucket_logging`` by ``bucket`` for every pipeline artifact bucket. Passes when ``target_bucket`` is set on the joined resource.

<div class="pg-rule__rec" markdown>

**Recommended action**

Attach an ``aws_s3_bucket_logging`` resource pointing ``target_bucket`` at a central, write-protected logging bucket. Access logs are what forensics use to reconstruct who pulled which artifact during an incident.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## S3-005: Artifact bucket missing aws:SecureTransport deny { #s3-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Joins ``aws_s3_bucket_policy`` by ``bucket`` for every pipeline artifact bucket. Parses ``policy`` JSON and looks for any ``Deny`` statement whose ``Condition`` matches ``aws:SecureTransport = false``. Without it, plaintext HTTP reads and writes still succeed.

<div class="pg-rule__rec" markdown>

**Recommended action**

Attach an ``aws_s3_bucket_policy`` carrying a ``Deny`` statement on ``Action: "s3:*"`` when ``Bool aws:SecureTransport = false``. Validate the policy with Access Analyzer before applying.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SIGN-001: No active AWS Signer profile exists for the Lambda platform { #sign-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Gated check: fires only when a ``aws_lambda_function`` references ``code_signing_config_arn``. Passes when at least one ``aws_signer_signing_profile`` with ``platform_id`` starting with ``AWSLambda-`` exists in the plan.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare an ``aws_signer_signing_profile`` with ``platform_id = "AWSLambda-SHA384-ECDSA"`` and reference it from an ``aws_lambda_code_signing_config``. Without one, the Lambda code-signing config can't be wired (see LMB-001).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SM-001: Secrets Manager secret has no rotation configured { #sm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-262</span>
</div>

Joins ``aws_secretsmanager_secret_rotation`` to ``aws_secretsmanager_secret`` by ``secret_id``. Fires when a secret has no matching rotation resource — a static secret that lives forever in any backup or snapshot taken since the leak.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare an ``aws_secretsmanager_secret_rotation`` that targets the secret via its ``secret_id``, with a Lambda rotation function and ``rotation_rules.automatically_after_days``. 30 / 60 / 90-day cadences are the usual stops.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## SM-002: Secrets Manager resource policy allows wildcard principal { #sm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Parses ``aws_secretsmanager_secret_policy.policy`` JSON and fires on any ``Allow`` statement that names a wildcard principal. The secret content is readable by every AWS account in the world until the policy is fixed.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``Principal: "*"`` (or ``Principal.AWS = "*"``) from every ``Allow`` statement in the resource policy. If cross-account access is intentional, name the specific accounts and add an ``aws:PrincipalOrgID`` condition.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SSM-001: SSM parameter with secret-like name stored as String, not SecureString { #ssm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-312</span>
</div>

Checks ``aws_ssm_parameter.name`` against the standard secret-name regex (``PASSWORD``, ``TOKEN``, ``API_KEY``, …). If the name matches and ``type`` is ``String`` (the default), the value is stored in plaintext, visible to anyone with ``ssm:GetParameter``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``type = "SecureString"`` on every ``aws_ssm_parameter`` whose name or value looks secret-like. SecureString parameters are encrypted with KMS and audited separately from plain ``GetParameter`` access.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SSM-002: SecureString uses alias/aws/ssm rather than a customer CMK { #ssm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads ``aws_ssm_parameter.{type,key_id}``. Fires on a ``SecureString`` whose ``key_id`` is empty or set to ``alias/aws/ssm`` — the encryption boundary collapses back to ``ssm:GetParameter`` permissions alone.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``key_id`` on every ``SecureString`` ``aws_ssm_parameter`` to a customer-managed KMS CMK ARN. Default ``alias/aws/ssm`` is an AWS-owned key that can't be scoped or rotated by your key policy.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TF-001: Plan declares aws_iam_access_key (long-lived credential) { #tf-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Fires on every ``aws_iam_access_key`` in the plan. Terraform writes the resulting ``secret`` to state, even on remote backends, the secret is now in every state-file backup, every CI run, and anywhere ``terraform output`` ran.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace static keys with role-based access: an ``aws_iam_role`` plus an OIDC ``aws_iam_openid_connect_provider`` for CI, or ``aws_iam_role`` for service-to-service auth. Static keys live forever in state, in backups, in every machine that ever ran ``terraform plan``.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## TF-002: Stateful data-store resource carries a plaintext secret { #tf-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-312</span>
</div>

Walks every value of the stateful data-store resources (``aws_db_instance``, ``aws_rds_cluster``, ``aws_redshift_cluster``, ``aws_elasticache_replication_group``, ``aws_docdb_cluster``, ``aws_neptune_cluster``, ``aws_opensearch_domain``, ``aws_memorydb_cluster``). Fires when a string leaf matches a credential shape (AKIA/ASIA, ``ghp_``, JWT, …) OR when a secret-named attribute (``*password``, ``*token``, …) carries a non-placeholder literal.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the secret into Secrets Manager (or SSM Parameter Store SecureString) and reference it via ``data.aws_secretsmanager_secret_version.…`` at apply time. Never literal-string a credential into a stateful resource — the value lives in state forever.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TF-003: CodeBuild VPC config references a public subnet { #tf-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-1327</span>
</div>

When ``aws_codebuild_project.vpc_config[0].vpc_id`` resolves to a concrete string, walks every ``aws_subnet`` in the same VPC and fires if any has ``map_public_ip_on_launch = true``. Silent when ``vpc_id`` is unresolved (``known after apply``).

<div class="pg-rule__rec" markdown>

**Recommended action**

Place CodeBuild projects in private subnets (``map_public_ip_on_launch = false``) with egress routed through a NAT gateway or VPC interface endpoints. Public subnets put the build host on a public IP for the duration of the build.

</div>

</div>

---

## Adding a new Terraform check

1. Drop a single module at
   `pipeline_check/core/checks/terraform/rules/<id>_<slug>.py`
   exporting a `RULE` (metadata) and a
   `check(ctx: TerraformContext) -> list[Finding]` callable. The
   orchestrator (`TerraformRuleChecks`) auto-discovers it and this
   doc's table picks it up on the next regen.
2. If the rule needs side resources (webhooks, attachments, policy
   documents joined on `bucket` / `role`), add a private helper to
   `pipeline_check/core/checks/terraform/rules/_<service>_context.py`
   following the `_iam_context.py` / `_s3_context.py` pattern so the
   pre-fetch lands once per scan.
3. Add the check ID to
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
4. Add unit tests in `tests/terraform/test_<service>.py` using
   `make_terraform_ctx` or one of the existing plan fixtures.
5. (Recommended) Add an AWS-runtime parity rule under
   `pipeline_check/core/checks/aws/rules/` so shift-left scans stay
   at parity with runtime.
6. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py terraform
   ```
