# CIS AWS Foundations Benchmark

- **Version:** 5.0
- **URL:** <https://www.cisecurity.org/benchmark/amazon_web_services>
- **Source of truth:** `pipeline_check/core/standards/data/cis_aws_foundations.py`

CIS AWS Foundations Benchmark, CI/CD-relevant subset. IAM hardening,
S3 protection, KMS hygiene, and the CloudTrail / CloudWatch logging
controls the AWS provider scans against a live account.

## At a glance

- **Controls in this standard:** 14
- **Controls evidenced by at least one check:** 12 / 14
- **Distinct checks evidencing this standard:** 62
- **Of those, autofixable with `--fix`:** 0

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`1.14`](#ctrl-1-14) | Ensure access keys are rotated every 90 days or less | 4 | 4H |
| [`1.16`](#ctrl-1-16) | Ensure IAM policies that allow full '*:*' administrative privileges are not attached | 18 | 5C · 9H · 4M |
| [`1.17`](#ctrl-1-17) | Ensure a support role has been created to manage incidents with AWS Support | 0 | — |
| [`2.1.1`](#ctrl-2-1-1) | Ensure all S3 buckets employ encryption-at-rest | 1 | 1H |
| [`2.1.2`](#ctrl-2-1-2) | Ensure S3 Bucket Policy is set to deny HTTP requests | 2 | 2M |
| [`2.1.4`](#ctrl-2-1-4) | Ensure that S3 Buckets are configured with 'Block public access' | 1 | 1C |
| [`3.1`](#ctrl-3-1) | Ensure CloudTrail is enabled in all regions | 18 | 1H · 1M · 16I |
| [`3.2`](#ctrl-3-2) | Ensure CloudTrail log file validation is enabled | 1 | 1M |
| [`3.4`](#ctrl-3-4) | Ensure CloudTrail trails are integrated with CloudWatch Logs | 3 | 2M · 1L |
| [`3.6`](#ctrl-3-6) | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket | 2 | 1L · 1I |
| [`3.7`](#ctrl-3-7) | Ensure CloudTrail logs are encrypted at rest using KMS CMKs | 8 | 2H · 6M |
| [`3.8`](#ctrl-3-8) | Ensure rotation for customer-created symmetric CMKs is enabled | 2 | 2M |
| [`4.3`](#ctrl-4-3) | Ensure a log metric filter and alarm exist for usage of the root account | 0 | — |
| [`4.16`](#ctrl-4-16) | Ensure AWS Security Hub is enabled | 4 | 1H · 2M · 1L |

## Filter at runtime

Restrict a scan to checks that evidence this standard with `--standard cis_aws_foundations`:

```bash
# All providers, only checks tied to this standard
pipeline_check --standard cis_aws_foundations

# Compose with --pipeline to scope by provider
pipeline_check --pipeline github --standard cis_aws_foundations

# Compose with another standard to widen the lens
pipeline_check --pipeline aws --standard cis_aws_foundations --standard owasp_cicd_top_10
```

## Controls in scope

### 1.14: Ensure access keys are rotated every 90 days or less { #ctrl-1-14 }

**Evidenced by 4 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CB-006`](../providers/aws.md#cb-006) | CodeBuild source auth uses long-lived token | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-004`](../providers/aws.md#cp-004) | Legacy ThirdParty/GitHub source action (OAuth token) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-007`](../providers/aws.md#iam-007) | IAM user has access key older than 90 days | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SM-001`](../providers/aws.md#sm-001) | Secrets Manager secret has no rotation configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |

### 1.16: Ensure IAM policies that allow full '*:*' administrative privileges are not attached { #ctrl-1-16 }

**Evidenced by 18 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-003`](../providers/aws.md#ca-003) | CodeArtifact domain policy allows cross-account wildcard | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CA-004`](../providers/aws.md#ca-004) | CodeArtifact repo policy grants ``codeartifact:*`` with ``Resource '*'`` | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CCM-003`](../providers/aws.md#ccm-003) | CodeCommit trigger targets SNS/Lambda in a different account | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`EB-002`](../providers/aws.md#eb-002) | EventBridge rule has a wildcard target ARN | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-003`](../providers/aws.md#ecr-003) | Repository policy allows public access | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`IAM-001`](../providers/aws.md#iam-001) | CI/CD role has AdministratorAccess policy attached | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`IAM-002`](../providers/aws.md#iam-002) | CI/CD role has wildcard Action in attached policy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-003`](../providers/aws.md#iam-003) | CI/CD role has no permission boundary | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-004`](../providers/aws.md#iam-004) | CI/CD role can PassRole to any role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-005`](../providers/aws.md#iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-006`](../providers/aws.md#iam-006) | Sensitive actions granted with wildcard Resource | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-008`](../providers/aws.md#iam-008) | OIDC-federated role trust policy missing audience or subject pin | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`KMS-002`](../providers/aws.md#kms-002) | KMS key policy grants wildcard KMS actions | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-002`](../providers/aws.md#lmb-002) | Lambda function URL has AuthType=NONE | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-004`](../providers/aws.md#lmb-004) | Lambda resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-002`](../providers/aws.md#pbac-002) | CodeBuild service role shared across multiple projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-005`](../providers/aws.md#pbac-005) | CodePipeline stage action roles mirror the pipeline role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SM-002`](../providers/aws.md#sm-002) | Secrets Manager resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |

### 1.17: Ensure a support role has been created to manage incidents with AWS Support { #ctrl-1-17 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### 2.1.1: Ensure all S3 buckets employ encryption-at-rest { #ctrl-2-1-1 }

**Evidenced by 1 check** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`S3-002`](../providers/aws.md#s3-002) | Artifact bucket server-side encryption not configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |

### 2.1.2: Ensure S3 Bucket Policy is set to deny HTTP requests { #ctrl-2-1-2 }

**Evidenced by 2 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`S3-003`](../providers/aws.md#s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`S3-005`](../providers/aws.md#s3-005) | Artifact bucket missing aws:SecureTransport deny | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### 2.1.4: Ensure that S3 Buckets are configured with 'Block public access' { #ctrl-2-1-4 }

**Evidenced by 1 check** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`S3-001`](../providers/aws.md#s3-001) | Artifact bucket public access block not fully enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |

### 3.1: Ensure CloudTrail is enabled in all regions { #ctrl-3-1 }

**Evidenced by 18 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-000`](../providers/aws.md#ca-000) | CodeArtifact API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CB-000`](../providers/aws.md#cb-000) | CodeBuild API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CCM-000`](../providers/aws.md#ccm-000) | CodeCommit API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CD-000`](../providers/aws.md#cd-000) | CodeDeploy API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CP-000`](../providers/aws.md#cp-000) | CodePipeline API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CT-000`](../providers/aws.md#ct-000) | CloudTrail API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CT-001`](../providers/aws.md#ct-001) | No active CloudTrail trail in region | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CT-003`](../providers/aws.md#ct-003) | CloudTrail trail is not multi-region | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CWL-000`](../providers/aws.md#cwl-000) | CloudWatch Logs API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`EB-000`](../providers/aws.md#eb-000) | EventBridge API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`ECR-000`](../providers/aws.md#ecr-000) | ECR API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`IAM-000`](../providers/aws.md#iam-000) | IAM API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`KMS-000`](../providers/aws.md#kms-000) | KMS API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`LMB-000`](../providers/aws.md#lmb-000) | Lambda API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-000`](../providers/aws.md#pbac-000) | PBAC enumeration failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`S3-000`](../providers/aws.md#s3-000) | S3 API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`SM-000`](../providers/aws.md#sm-000) | Secrets Manager API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`SSM-000`](../providers/aws.md#ssm-000) | SSM Parameter Store API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |

### 3.2: Ensure CloudTrail log file validation is enabled { #ctrl-3-2 }

**Evidenced by 1 check** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CT-002`](../providers/aws.md#ct-002) | CloudTrail log-file validation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### 3.4: Ensure CloudTrail trails are integrated with CloudWatch Logs { #ctrl-3-4 }

**Evidenced by 3 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CB-003`](../providers/aws.md#cb-003) | Build logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CD-003`](../providers/aws.md#cd-003) | No CloudWatch alarm monitoring on deployment group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CWL-001`](../providers/aws.md#cwl-001) | CodeBuild log group has no retention policy | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |

### 3.6: Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket { #ctrl-3-6 }

**Evidenced by 2 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`S3-000`](../providers/aws.md#s3-000) | S3 API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`S3-004`](../providers/aws.md#s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |

### 3.7: Ensure CloudTrail logs are encrypted at rest using KMS CMKs { #ctrl-3-7 }

**Evidenced by 8 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-001`](../providers/aws.md#ca-001) | CodeArtifact domain not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CCM-002`](../providers/aws.md#ccm-002) | CodeCommit repository not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CP-002`](../providers/aws.md#cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CWL-002`](../providers/aws.md#cwl-002) | CodeBuild log group not KMS-encrypted | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-005`](../providers/aws.md#ecr-005) | Repository encrypted with AES256 rather than KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`LMB-003`](../providers/aws.md#lmb-003) | Lambda function env vars may contain plaintext secrets | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SSM-001`](../providers/aws.md#ssm-001) | SSM Parameter with secret-like name is not a SecureString | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SSM-002`](../providers/aws.md#ssm-002) | SSM SecureString uses the default AWS-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### 3.8: Ensure rotation for customer-created symmetric CMKs is enabled { #ctrl-3-8 }

**Evidenced by 2 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`KMS-001`](../providers/aws.md#kms-001) | KMS customer-managed key has rotation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SSM-002`](../providers/aws.md#ssm-002) | SSM SecureString uses the default AWS-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### 4.3: Ensure a log metric filter and alarm exist for usage of the root account { #ctrl-4-3 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### 4.16: Ensure AWS Security Hub is enabled { #ctrl-4-16 }

**Evidenced by 4 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CW-001`](../providers/aws.md#cw-001) | No CloudWatch alarm on CodeBuild FailedBuilds metric | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`EB-001`](../providers/aws.md#eb-001) | No EventBridge rule for CodePipeline failure notifications | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-001`](../providers/aws.md#ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-007`](../providers/aws.md#ecr-007) | Inspector v2 enhanced scanning disabled for ECR | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

---

_This page is generated. Edit `pipeline_check/core/standards/data/cis_aws_foundations.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py cis_aws_foundations`._
