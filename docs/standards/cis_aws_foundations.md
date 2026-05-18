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
- **Distinct checks evidencing this standard:** 44
- **Of those, autofixable with `--fix`:** 0

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`1.14`](#ctrl-1-14) | Ensure access keys are rotated every 90 days or less | 2 | 2H |
| [`1.16`](#ctrl-1-16) | Ensure IAM policies that allow full '*:*' administrative privileges are not attached | 18 | 5C · 9H · 4M |
| [`1.17`](#ctrl-1-17) | Ensure a support role has been created to manage incidents with AWS Support | 0 | — |
| [`2.1.1`](#ctrl-2-1-1) | Ensure all S3 buckets employ encryption-at-rest | 1 | 1H |
| [`2.1.2`](#ctrl-2-1-2) | Ensure S3 Bucket Policy is set to deny HTTP requests | 2 | 2M |
| [`2.1.4`](#ctrl-2-1-4) | Ensure that S3 Buckets are configured with 'Block public access' | 1 | 1C |
| [`3.1`](#ctrl-3-1) | Ensure CloudTrail is enabled in all regions | 2 | 1H · 1M |
| [`3.2`](#ctrl-3-2) | Ensure CloudTrail log file validation is enabled | 1 | 1M |
| [`3.4`](#ctrl-3-4) | Ensure CloudTrail trails are integrated with CloudWatch Logs | 3 | 2M · 1L |
| [`3.6`](#ctrl-3-6) | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket | 1 | 1L |
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

**Evidenced by 2 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`IAM-007`](#detail-iam-007) | IAM user has access key older than 90 days | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SM-001`](#detail-sm-001) | Secrets Manager secret has no rotation configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |

### 1.16: Ensure IAM policies that allow full '*:*' administrative privileges are not attached { #ctrl-1-16 }

**Evidenced by 18 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-003`](#detail-ca-003) | CodeArtifact domain policy allows cross-account wildcard | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CA-004`](#detail-ca-004) | CodeArtifact repo policy grants codeartifact:* with Resource '*' | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CCM-003`](#detail-ccm-003) | CodeCommit trigger targets SNS/Lambda in a different account | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`EB-002`](#detail-eb-002) | EventBridge rule has a wildcard target ARN | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-003`](#detail-ecr-003) | Repository policy allows public access | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`IAM-001`](#detail-iam-001) | CI/CD role has AdministratorAccess policy attached | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`IAM-002`](#detail-iam-002) | CI/CD role has wildcard Action in attached policy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-003`](#detail-iam-003) | CI/CD role has no permission boundary | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-004`](#detail-iam-004) | CI/CD role can PassRole to any role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-005`](#detail-iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-006`](#detail-iam-006) | Sensitive actions granted with wildcard Resource | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-008`](#detail-iam-008) | OIDC-federated role trust policy missing audience or subject pin | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`KMS-002`](#detail-kms-002) | KMS key policy grants wildcard KMS actions | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-002`](#detail-lmb-002) | Lambda function URL has AuthType=NONE | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-004`](#detail-lmb-004) | Lambda resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-002`](#detail-pbac-002) | CodeBuild service role shared across multiple projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-005`](#detail-pbac-005) | CodePipeline stage action roles mirror the pipeline role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SM-002`](#detail-sm-002) | Secrets Manager resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |

### 1.17: Ensure a support role has been created to manage incidents with AWS Support { #ctrl-1-17 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### 2.1.1: Ensure all S3 buckets employ encryption-at-rest { #ctrl-2-1-1 }

**Evidenced by 1 check** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`S3-002`](#detail-s3-002) | Artifact bucket server-side encryption not configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |

### 2.1.2: Ensure S3 Bucket Policy is set to deny HTTP requests { #ctrl-2-1-2 }

**Evidenced by 2 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`S3-003`](#detail-s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`S3-005`](#detail-s3-005) | Artifact bucket missing aws:SecureTransport deny | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### 2.1.4: Ensure that S3 Buckets are configured with 'Block public access' { #ctrl-2-1-4 }

**Evidenced by 1 check** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`S3-001`](#detail-s3-001) | Artifact bucket public access block not fully enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |

### 3.1: Ensure CloudTrail is enabled in all regions { #ctrl-3-1 }

**Evidenced by 2 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CT-001`](#detail-ct-001) | No active CloudTrail trail in region | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CT-003`](#detail-ct-003) | CloudTrail trail is not multi-region | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### 3.2: Ensure CloudTrail log file validation is enabled { #ctrl-3-2 }

**Evidenced by 1 check** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CT-002`](#detail-ct-002) | CloudTrail log-file validation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### 3.4: Ensure CloudTrail trails are integrated with CloudWatch Logs { #ctrl-3-4 }

**Evidenced by 3 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CB-003`](#detail-cb-003) | Build logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CD-003`](#detail-cd-003) | No CloudWatch alarm monitoring on deployment group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CWL-001`](#detail-cwl-001) | CodeBuild log group has no retention policy | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |

### 3.6: Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket { #ctrl-3-6 }

**Evidenced by 1 check** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`S3-004`](#detail-s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |

### 3.7: Ensure CloudTrail logs are encrypted at rest using KMS CMKs { #ctrl-3-7 }

**Evidenced by 8 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-001`](#detail-ca-001) | CodeArtifact domain not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CCM-002`](#detail-ccm-002) | CodeCommit repository not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CP-002`](#detail-cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CWL-002`](#detail-cwl-002) | CodeBuild log group not KMS-encrypted | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-005`](#detail-ecr-005) | Repository encrypted with AES256 rather than KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`LMB-003`](#detail-lmb-003) | Lambda function env vars may contain plaintext secrets | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SSM-001`](#detail-ssm-001) | SSM Parameter with secret-like name is not a SecureString | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SSM-002`](#detail-ssm-002) | SSM SecureString uses the default AWS-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### 3.8: Ensure rotation for customer-created symmetric CMKs is enabled { #ctrl-3-8 }

**Evidenced by 2 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`KMS-001`](#detail-kms-001) | KMS customer-managed key has rotation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SSM-002`](#detail-ssm-002) | SSM SecureString uses the default AWS-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### 4.3: Ensure a log metric filter and alarm exist for usage of the root account { #ctrl-4-3 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### 4.16: Ensure AWS Security Hub is enabled { #ctrl-4-16 }

**Evidenced by 4 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CW-001`](#detail-cw-001) | No CloudWatch alarm on CodeBuild FailedBuilds metric | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`EB-001`](#detail-eb-001) | No EventBridge rule for CodePipeline failure notifications | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-001`](#detail-ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-007`](#detail-ecr-007) | Inspector v2 enhanced scanning disabled for ECR | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

## Check details

Every check that evidences this standard, rendered once with its detection mechanism, recommendation, and any known false-positive modes or real-world incident references. The per-control tables above link to the matching block here.

#### `CA-001`: CodeArtifact domain not encrypted with customer KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ca-001 }

**Evidences:** [`3.7`](#ctrl-3-7) Ensure CloudTrail logs are encrypted at rest using KMS CMKs.

**How this is detected.** AWS-owned encryption (the default ``alias/aws/codeartifact`` key) keeps the key policy under AWS's control, not yours. That's fine for confidentiality but means cross-account auditability of every Decrypt event lives with AWS, and you can't revoke or scope key access without recreating the domain. A customer-managed CMK puts both controls back in your hands.

**Recommendation.** Recreate the CodeArtifact domain with an encryption-key argument pointing at a customer-managed CMK. Domain encryption is set at creation and cannot be changed after.

**Source:** [`CA-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CA-003`: CodeArtifact domain policy allows cross-account wildcard <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ca-003 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** A wildcard-principal Allow on a CodeArtifact domain lets any AWS account reach the domain's permissions surface. The exact damage depends on the action set, but at minimum it lets external accounts read package names and versions, which is enough for typosquat-against-private-package attacks. ``aws:PrincipalOrgID`` is the org-level rescue without enumerating accounts.

**Recommendation.** Remove Allow statements with ``Principal: '*'`` from every CodeArtifact domain permissions policy, or restrict them with an ``aws:PrincipalOrgID`` condition so only accounts in your org can consume packages from the domain.

**Source:** [`CA-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CA-004`: CodeArtifact repo policy grants codeartifact:* with Resource '*' <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ca-004 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** ``codeartifact:*`` on ``Resource: '*'`` collapses the entire repository's authority into one grant: the holder can read, write, delete, dispose, and re-publish every package. Even for a service principal that nominally only consumes packages, the grant lets a compromise of that consumer rewrite every dependency the team relies on.

**Recommendation.** Scope Allow statements to specific ``codeartifact:`` actions (e.g. ``codeartifact:ReadFromRepository``) and to specific package-group ARNs. Wildcard action + wildcard resource is the classic over-broad grant that lets a consumer also publish.

**Source:** [`CA-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-003`: Build logging not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-003 }

**Evidences:** [`3.4`](#ctrl-3-4) Ensure CloudTrail trails are integrated with CloudWatch Logs.

**How this is detected.** A CodeBuild project with neither CloudWatch Logs nor S3 logging enabled leaves no durable record of what the build did. The CodeBuild console shows the last execution's logs for a short retention window, but anything older, and any automated review of historical activity during incident response, is gone.

**Recommendation.** Enable CloudWatch Logs or S3 logging in the CodeBuild project configuration to maintain a durable audit trail of all build activity.

**Source:** [`CB-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CCM-002`: CodeCommit repository not encrypted with customer KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ccm-002 }

**Evidences:** [`3.7`](#ctrl-3-7) Ensure CloudTrail logs are encrypted at rest using KMS CMKs.

**How this is detected.** Same shape as CA-001 / ECR-005 / S3 default encryption: the AWS-owned default key keeps the key policy under AWS, removing your ability to scope or audit Decrypt operations. Source code in the repo deserves the same key-policy + CloudTrail story you'd apply to artifacts in S3.

**Recommendation.** Recreate the repository with a ``kmsKeyId`` argument pointing at a customer-managed KMS key. CodeCommit encryption is set at creation and cannot be changed afterwards.

**Source:** [`CCM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CCM-003`: CodeCommit trigger targets SNS/Lambda in a different account <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ccm-003 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** A repo trigger pointing at an SNS topic or Lambda in a different account fires under the receiving account's permissions on every push. Sometimes this is the intended shape (a centralized notifications account), but a cross-account fan-out from a compromised repo can drive actions in the receiving account that the source-account owner can't directly observe.

**Recommendation.** Move trigger targets into the same account as the repository or explicitly document the cross-account relationship. Cross-account triggers extend the blast radius of a repository compromise to whatever the target ARN can do.

**Source:** [`CCM-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CD-003`: No CloudWatch alarm monitoring on deployment group <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cd-003 }

**Evidences:** [`3.4`](#ctrl-3-4) Ensure CloudTrail trails are integrated with CloudWatch Logs.

**How this is detected.** Alarm-based rollback is what lets a canary configuration actually stop a bad deploy mid-flight. Without alarms wired into ``alarmConfiguration``, CodeDeploy's only signal that the deploy went wrong is the deployment-state machine itself, which doesn't notice an application-level regression. CD-002's canary work and this rule's alarm-based halt are paired.

**Recommendation.** Add CloudWatch alarms (e.g. error rate, 5xx count, latency p99) to the deployment group's alarmConfiguration. Enable automatic rollback on DEPLOYMENT_STOP_ON_ALARM to halt bad deployments.

**Source:** [`CD-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-002`: Artifact store not encrypted with customer-managed KMS key <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cp-002 }

**Evidences:** [`3.7`](#ctrl-3-7) Ensure CloudTrail logs are encrypted at rest using KMS CMKs.

**How this is detected.** The pipeline's S3 artifact store holds intermediate build outputs handed between stages. Default SSE-S3 (AES256) encrypts at rest but uses an AWS-owned key whose policy you can't scope. A customer-managed CMK gives the same key-policy + CloudTrail Decrypt-event audit story you'd apply to Lambda code, Secrets Manager, or any other build output.

**Recommendation.** Configure a customer-managed AWS KMS key as the encryptionKey for each artifact store. This enables key rotation, fine-grained access policies, and CloudTrail auditing of decrypt operations.

**Source:** [`CP-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CT-001`: No active CloudTrail trail in region <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ct-001 }

**Evidences:** [`3.1`](#ctrl-3-1) Ensure CloudTrail is enabled in all regions.

**How this is detected.** CloudTrail is the only AWS-native source of record for management-plane API calls. A region with no active trail blinds incident responders: a pipeline compromise is invisible once the in-memory CloudWatch buffer rolls over.

**Recommendation.** Create a CloudTrail trail that logs management events in this region and start logging. Without a trail, CodeBuild/CodePipeline/IAM API activity, including credential changes during a compromise, has no durable audit record.

**Source:** [`CT-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CT-002`: CloudTrail log-file validation disabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ct-002 }

**Evidences:** [`3.2`](#ctrl-3-2) Ensure CloudTrail log file validation is enabled.

**How this is detected.** CloudTrail logs are S3 objects. Without log-file validation, an attacker with ``s3:PutObject`` on the trail bucket can edit log files to remove evidence of their activity, and there's no digest to compare against. With validation on, every hour of logs is summarized in a signed digest file under ``CloudTrail-Digest/``.

**Recommendation.** Set ``LogFileValidationEnabled=true`` on every CloudTrail trail. Log validation produces a signed digest file alongside each log object so tampering by an attacker who also has S3 write access can be detected after the fact.

**Source:** [`CT-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CT-003`: CloudTrail trail is not multi-region <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ct-003 }

**Evidences:** [`3.1`](#ctrl-3-1) Ensure CloudTrail is enabled in all regions.

**How this is detected.** An attacker who knows your CloudTrail trail is regional deliberately operates from a different region. Multi-region trails capture management events from every region into a single trail, closing the gap without you having to enumerate which regions you actually use.

**Recommendation.** Convert the trail to a multi-region trail. A single-region trail misses activity in every other region, an attacker aware of the scope can drive reconnaissance or persistence from an unlogged region.

**Source:** [`CT-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CW-001`: No CloudWatch alarm on CodeBuild FailedBuilds metric <span class="pg-sev pg-sev--low">LOW</span> { #detail-cw-001 }

**Evidences:** [`4.16`](#ctrl-4-16) Ensure AWS Security Hub is enabled.

**How this is detected.** Failure-rate signals are how on-call learns about an unfamiliar build crashing in a loop, an attacker probing the build environment, or a CI quota being exhausted. CloudWatch captures the ``FailedBuilds`` metric automatically, the alarm is the missing fan-out.

**Recommendation.** Create a CloudWatch alarm on the ``AWS/CodeBuild`` namespace ``FailedBuilds`` metric (aggregated or per-project). Without one, repeated build failures during a compromise, or a runaway fork-PR build, won't reach on-call.

**Source:** [`CW-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CWL-001`: CodeBuild log group has no retention policy <span class="pg-sev pg-sev--low">LOW</span> { #detail-cwl-001 }

**Evidences:** [`3.4`](#ctrl-3-4) Ensure CloudTrail trails are integrated with CloudWatch Logs.

**How this is detected.** CloudWatch Logs created by CodeBuild default to ``Never Expire`` retention. Build logs frequently echo secrets accidentally (a `set -x` script, an `env` dump in an error trace), so unbounded retention extends the exposure window for every secret a build has ever leaked. A short-but-finite retention also caps cost.

**Recommendation.** Set a retention policy on every ``/aws/codebuild/*`` log group. The default is 'Never Expire', which both racks up storage cost and keeps logs indefinitely past any compliance window.

**Source:** [`CWL-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CWL-002`: CodeBuild log group not KMS-encrypted <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cwl-002 }

**Evidences:** [`3.7`](#ctrl-3-7) Ensure CloudTrail logs are encrypted at rest using KMS CMKs.

**How this is detected.** CloudWatch Logs default encryption is service-managed, fine for confidentiality, but no audit trail or scoping. Build logs are a frequent secret-leak vector (CWL-001's rationale extended), so the same key-policy + Decrypt-event story you'd apply to S3 / Lambda / Secrets Manager is warranted here too.

**Recommendation.** Associate a customer-managed KMS key with every ``/aws/codebuild/*`` log group via ``associate-kms-key``. Logs often contain secret material accidentally echoed by builds; encrypting them with a CMK means the key policy controls who can read the logs, not just S3/CloudWatch IAM.

**Source:** [`CWL-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `EB-001`: No EventBridge rule for CodePipeline failure notifications <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-eb-001 }

**Evidences:** [`4.16`](#ctrl-4-16) Ensure AWS Security Hub is enabled.

**How this is detected.** Pipeline failure events are emitted to EventBridge automatically; the missing piece is a rule that pipes them to somewhere a human reads (SNS, Slack, PagerDuty). Without it, failures only surface via the CodePipeline console, which no one watches.

**Recommendation.** Create an EventBridge rule matching ``detail-type: 'CodePipeline Pipeline Execution State Change'`` and ``state: FAILED``, and point it at an SNS topic or chat webhook. Without it, pipeline failures during an incident (a compromise triggering rollback, for example) go unnoticed.

**Source:** [`EB-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `EB-002`: EventBridge rule has a wildcard target ARN <span class="pg-sev pg-sev--high">HIGH</span> { #detail-eb-002 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** Wildcard target ARNs (e.g. ``arn:aws:lambda:us-east-1:123456789012:function:*``) match every resource that fits the prefix. This is rarely intentional, usually a copy-paste from a more permissive resource ARN, and means the rule fans out to a much larger set of consumers than the author meant.

**Recommendation.** Replace wildcard target ARNs with specific resource ARNs. EventBridge targets with ``*`` route events to any resource that matches the prefix, frequently triggering unintended Lambda invocations or SNS sends.

**Source:** [`EB-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-001`: Image scanning on push not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-001 }

**Evidences:** [`4.16`](#ctrl-4-16) Ensure AWS Security Hub is enabled.

**How this is detected.** scan-on-push runs a CVE check against the image's OS package layers at the moment it lands in ECR. Without it, an image with a known CVE deploys silently. The ECR basic scanner is free; ECR-007 covers the Inspector v2 enhanced scanner that adds language-ecosystem CVEs (npm, pip, gem).

**Recommendation.** Enable imageScanningConfiguration.scanOnPush on the repository. Consider also enabling Amazon Inspector continuous scanning for ongoing CVE detection against images already in the registry.

**Source:** [`ECR-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-003`: Repository policy allows public access <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ecr-003 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** A wildcard-principal repo policy means anyone on the internet can pull images. Sometimes intentional (a publicly-distributed base image), but should be a deliberate exposure, typically via the ECR Public registry rather than a private repo with a public policy. The default for build-output images should never be public.

**Recommendation.** Remove wildcard principals from the repository policy. Grant access only to specific AWS account IDs or IAM principals that require it.

**Source:** [`ECR-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-005`: Repository encrypted with AES256 rather than KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ecr-005 }

**Evidences:** [`3.7`](#ctrl-3-7) Ensure CloudTrail logs are encrypted at rest using KMS CMKs.

**How this is detected.** Same shape as CP-002 / CWL-002 / CCM-002: AES256 (the AWS-managed default) gives confidentiality at rest but no key-policy or CloudTrail Decrypt-event story. Container images are arguably sensitive intellectual property, the same key-policy + audit shape as build outputs in S3 is warranted.

**Recommendation.** Set encryptionType=KMS with a customer-managed key ARN.

**Source:** [`ECR-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-007`: Inspector v2 enhanced scanning disabled for ECR <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ecr-007 }

**Evidences:** [`4.16`](#ctrl-4-16) Ensure AWS Security Hub is enabled.

**How this is detected.** ECR-001's basic on-push scan covers OS-level packages, apt / yum / apk lineage. Most production CVE risk is in language ecosystems (npm, pip, gem, mvn) which the basic scanner ignores. Inspector v2 enhanced scanning closes that gap and runs continuously, so a CVE published two weeks after a build still surfaces against the deployed image.

**Recommendation.** Enable Amazon Inspector v2 for the ``ECR`` scan type on this account. Basic ECR scanning on-push only covers OS packages; Inspector v2 enhanced scanning adds language-ecosystem CVEs and runs continuously as new vulnerabilities are published.

**Source:** [`ECR-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-001`: CI/CD role has AdministratorAccess policy attached <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-iam-001 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** A CI/CD service role with ``AdministratorAccess`` attached turns any pipeline compromise into account compromise. The classic anti-pattern: the role started narrow, the pipeline grew, someone attached AdministratorAccess to unblock a deploy, and it never came off.

**Recommendation.** Replace AdministratorAccess with least-privilege policies.

**Proof of exploit.**

# Vulnerable: CodeBuild service role with AdministratorAccess.
# (Terraform shown for clarity; the actual finding comes from
# live ListAttachedRolePolicies on the role.)
resource "aws_iam_role" "codebuild" {
  name               = "codebuild-deploy"
  assume_role_policy = data.aws_iam_policy_document.cb_trust.json
}
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.codebuild.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Attack: any compromise of the build (poisoned dependency,
# leaked buildspec edit, malicious PR merged to the branch
# CodeBuild trusts) runs as a principal with full account
# permissions. From a build shell:
#
#   aws iam create-user --user-name persistence
#   aws iam attach-user-policy --user-name persistence \
#     --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
#   aws iam create-access-key --user-name persistence
#
# Game over: out-of-band admin, no IP gate, survives every
# subsequent rotation of the CodeBuild role itself.

# Safe: scope the role to the resources the pipeline actually
# touches. ``AdministratorAccess`` is never the right answer
# for an automation principal.
resource "aws_iam_role_policy" "codebuild_least_priv" {
  role   = aws_iam_role.codebuild.id
  policy = data.aws_iam_policy_document.deploy_specific.json
}

**Source:** [`IAM-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-002`: CI/CD role has wildcard Action in attached policy <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-002 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** ``Action: '*'`` (or service-prefix wildcards like ``s3:*``) on an attached policy is functionally equivalent to AdministratorAccess for that resource. The wildcard absorbs every new IAM action AWS adds, so the role's authority grows without any local change.

**Recommendation.** Replace wildcard actions with specific IAM actions.

**Source:** [`IAM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-003`: CI/CD role has no permission boundary <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-iam-003 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** A permissions boundary is the maximum-permission ceiling for a role. Without one, every future PR that attaches another inline / managed policy raises the role's effective authority indefinitely. With a boundary in place, the policy churn happens beneath a fixed cap that your security team owns separately.

**Recommendation.** Attach a permissions boundary defining max permissions.

**Source:** [`IAM-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-004`: CI/CD role can PassRole to any role <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-004 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** ``iam:PassRole`` with ``Resource: '*'`` lets the principal hand any role to any service. Combined with a service that runs your code (Lambda, ECS, CodeBuild, EC2 Instance Profiles), this is role-hop privilege escalation: launch an ephemeral resource configured with a higher-privileged role, run code under that identity, exfil. Scoping by ARN + ``iam:PassedToService`` removes the escalation path.

**Recommendation.** Restrict iam:PassRole to specific role ARNs and add an iam:PassedToService condition.

**Proof of exploit.**

# Vulnerable: pipeline role grants PassRole with Resource: '*'.
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:PassRole", "lambda:CreateFunction",
                "lambda:InvokeFunction"],
    "Resource": "*"
  }]
}

# Attack: from a build shell, create a Lambda configured with
# the highest-privileged role you can name and invoke it:
#
#   aws lambda create-function --function-name pwn \
#     --role arn:aws:iam::123456789012:role/prod-admin \
#     --runtime python3.12 --handler i.h \
#     --zip-file fileb://payload.zip
#   aws lambda invoke --function-name pwn /tmp/out
#
# The Lambda now runs as ``prod-admin`` even though the
# pipeline principal never had that role's permissions
# directly. Classic role-hop privilege escalation.

# Safe: pin to one role ARN AND require the pass be scoped
# to the service that legitimately consumes it.
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/lambda-deploy-target",
  "Condition": {
    "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}
  }
}

**Source:** [`IAM-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-005`: CI/CD role trust policy missing sts:ExternalId <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-005 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** A trust policy that lets an external AWS account assume the role without an ``sts:ExternalId`` condition is vulnerable to the confused-deputy pattern: a third-party SaaS configured with your role ARN can also be used by another customer of that SaaS to assume your role (if they know the ARN). ``sts:ExternalId`` ties the role to a specific tenancy.

**Recommendation.** Add a Condition requiring sts:ExternalId for external principals.

**Source:** [`IAM-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-006`: Sensitive actions granted with wildcard Resource <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-iam-006 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** IAM-002 catches ``Action: "*"``. IAM-006 catches the more common "scoped action, unscoped resource" pattern on sensitive services (S3/KMS/SecretsManager/SSM/IAM/STS/DynamoDB/Lambda/EC2).

**Recommendation.** Scope the Resource element to specific ARNs (buckets, keys, secrets, roles).

**Source:** [`IAM-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-007`: IAM user has access key older than 90 days <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-007 }

**Evidences:** [`1.14`](#ctrl-1-14) Ensure access keys are rotated every 90 days or less.

**How this is detected.** Every user in the account is evaluated. CI/CD tooling that still uses IAM users (older Jenkins agents, GitHub Actions pre-OIDC, third-party schedulers) shows up here. The 90-day window matches the common compliance baseline; rotate sooner if the key is used from on-prem or an untrusted runner.

**Recommendation.** Rotate or delete IAM access keys older than 90 days. Long-lived static credentials are the #1 way compromised CI credentials get reused across environments, prefer short-lived STS tokens via OIDC federation or an assumed role.

**Source:** [`IAM-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-008`: OIDC-federated role trust policy missing audience or subject pin <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-008 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** IAM-005 already covers cross-account AWS principals. This rule targets the OIDC federation path specifically because the blast radius of a missed audience/subject pin is the entire identity provider's tenant base (e.g. all GitHub users, not just your org).

**Recommendation.** Every Allow statement that trusts a federated OIDC provider (``token.actions.githubusercontent.com``, GitLab, CircleCI, Terraform Cloud, etc.) must pin both the audience (``...:aud = sts.amazonaws.com``) and a subject prefix (``...:sub`` matching ``repo:myorg/*``). Without these, any workflow from any tenant can assume the role.

**Source:** [`IAM-008`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `KMS-001`: KMS customer-managed key has rotation disabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-kms-001 }

**Evidences:** [`3.8`](#ctrl-3-8) Ensure rotation for customer-created symmetric CMKs is enabled.

**How this is detected.** Annual rotation regenerates the underlying key material for the same CMK ARN. Existing ciphertexts can still be decrypted (KMS keeps old material around), but new encrypts use the new material, so a cryptographic exposure (side-channel, an accidental export, an old compromised offline backup) only protects ciphertexts from before the rotation.

**Recommendation.** Enable annual rotation on every customer-managed KMS key used for CI/CD artifact, log, and secret encryption. Unrotated CMKs keep the same key material indefinitely, so a single cryptographic exposure (side-channel, accidental export) is permanent.

**Source:** [`KMS-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `KMS-002`: KMS key policy grants wildcard KMS actions <span class="pg-sev pg-sev--high">HIGH</span> { #detail-kms-002 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** ``kms:*`` on a key policy is administrative authority over the cipher boundary: ``CancelKeyDeletion``, ``ScheduleKeyDeletion``, ``ReEncrypt``, ``UpdateKeyDescription``, and the data-plane decrypt actions all collapse into one grant. A CI/CD principal almost never needs more than the data-plane subset (``Decrypt`` / ``GenerateDataKey`` / ``Encrypt``).

**Recommendation.** Replace ``kms:*`` grants with specific actions needed by the caller (e.g. ``kms:Decrypt``, ``kms:GenerateDataKey``). Key-policy wildcard grants let any holder of the principal re-key, schedule deletion, or export material at will.

**Source:** [`KMS-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `LMB-002`: Lambda function URL has AuthType=NONE <span class="pg-sev pg-sev--high">HIGH</span> { #detail-lmb-002 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** A Lambda function URL with ``AuthType=NONE`` is a public HTTPS endpoint. Anyone who knows the URL can invoke. This is sometimes deliberate (a webhook receiver) but the deliberate version typically signs / validates inside the function, the rule fires regardless because the IAM-side control isn't there.

**Recommendation.** Set the function URL ``auth_type`` to ``AWS_IAM`` and grant ``lambda:InvokeFunctionUrl`` through IAM. ``NONE`` exposes the function to the public internet without authentication.

**Source:** [`LMB-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `LMB-003`: Lambda function env vars may contain plaintext secrets <span class="pg-sev pg-sev--high">HIGH</span> { #detail-lmb-003 }

**Evidences:** [`3.7`](#ctrl-3-7) Ensure CloudTrail logs are encrypted at rest using KMS CMKs.

**How this is detected.** Lambda env vars are world-readable to any principal with ``lambda:GetFunctionConfiguration``, much wider than the principal that can invoke the function. They also persist in CloudFormation drift, change-sets, and CloudTrail events. A secret in a Lambda env var is essentially exposed to anyone with read access to the account.

**Recommendation.** Move secrets out of Lambda environment variables and into Secrets Manager or SSM Parameter Store. Environment variables are visible to anyone with ``lambda:GetFunctionConfiguration`` and persist in CloudTrail events, which keeps the secret in audit logs.

**Source:** [`LMB-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `LMB-004`: Lambda resource policy allows wildcard principal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-lmb-004 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** A wildcard-principal Allow on a Lambda function resource policy lets anyone invoke. The legitimate case is a service principal (API Gateway, S3 events) where AWS fills in the SourceArn/SourceAccount at invoke time, without those conditions, any account using that service can invoke.

**Recommendation.** Remove Allow statements with ``Principal: '*'`` from every Lambda function resource policy, or scope them with a ``SourceArn`` / ``SourceAccount`` condition. Service principals (e.g. ``apigateway.amazonaws.com``) are the common legitimate case, ensure they carry a condition.

**Source:** [`LMB-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `PBAC-002`: CodeBuild service role shared across multiple projects <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-pbac-002 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** One CodeBuild service role across many projects means a compromise of any project's build environment grants access to whatever resources every other project's build needs. Per-project roles cap the radius, a backdoor in the ``foo-tests`` build can't reach the ``deploy-prod`` build's secrets if they each have their own role.

**Recommendation.** Create a dedicated IAM service role for each CodeBuild project, scoped to only the permissions that specific project requires. This limits the blast radius if one project's build is compromised.

**Source:** [`PBAC-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `PBAC-005`: CodePipeline stage action roles mirror the pipeline role <span class="pg-sev pg-sev--high">HIGH</span> { #detail-pbac-005 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** When stage actions don't set their own ``roleArn``, they fall back to the pipeline-level role, which is the union of every stage's needs. A compromise of any one stage (typically the build, which runs untrusted code) gains the deploy stage's authority, including production deploy credentials. Per-action roles cap the radius.

**Recommendation.** Give each stage action (Source, Build, Deploy) its own narrowly-scoped IAM role via ``roleArn`` on the action declaration. Sharing the pipeline-level role means a compromise of one action (e.g. a build) gains the permissions the deploy stage also needs.

**Source:** [`PBAC-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-001`: Artifact bucket public access block not fully enabled <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-s3-001 }

**Evidences:** [`2.1.4`](#ctrl-2-1-4) Ensure that S3 Buckets are configured with 'Block public access'.

**How this is detected.** S3 Block Public Access is the bucket-level circuit breaker that supersedes any future ACL or bucket-policy edit. Without all four settings enabled, a misconfigured CloudFormation change or a stray ``aws s3api`` call can re-expose the bucket to the public, even if the bucket had previously been private.

**Recommendation.** Enable all four S3 Block Public Access settings on the artifact bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.

**Source:** [`S3-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-002`: Artifact bucket server-side encryption not configured <span class="pg-sev pg-sev--high">HIGH</span> { #detail-s3-002 }

**Evidences:** [`2.1.1`](#ctrl-2-1-1) Ensure all S3 buckets employ encryption-at-rest.

**How this is detected.** Default bucket encryption applies SSE-S3 (AES256) to every PutObject. As of January 2023, AWS enables this on all new buckets automatically, but existing buckets created before then can still be unencrypted unless explicitly configured. Without it, individual objects can be uploaded without encryption (the client gets to choose).

**Recommendation.** Enable default bucket encryption using at minimum AES256 (SSE-S3). For stronger key control, use SSE-KMS with a customer-managed key.

**Source:** [`S3-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-003`: Artifact bucket versioning not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-s3-003 }

**Evidences:** [`2.1.2`](#ctrl-2-1-2) Ensure S3 Bucket Policy is set to deny HTTP requests.

**How this is detected.** Versioning makes overwrites and deletes recoverable: the previous content of an object survives until lifecycle expires it. Without versioning, an artifact overwrite (a bad pipeline run, a malicious replacement, a typo'd ``aws s3 cp``) is unrecoverable, the original bytes are gone.

**Recommendation.** Enable S3 versioning on the artifact bucket so that previous artifact versions are retained and rollback is possible. Combine with a lifecycle rule to expire old versions after a retention period.

**Source:** [`S3-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-004`: Artifact bucket access logging not enabled <span class="pg-sev pg-sev--low">LOW</span> { #detail-s3-004 }

**Evidences:** [`3.6`](#ctrl-3-6) Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket.

**How this is detected.** S3 server access logging records every API operation against the bucket, who, when, what object, what method. CloudTrail data events overlap but cost more; access logs are the cheap baseline. Without them, an exfiltration via ``GetObject`` doesn't leave a trail you can investigate.

**Recommendation.** Enable S3 server access logging for the artifact bucket and direct logs to a separate, centralized logging bucket with restricted write access.

**Source:** [`S3-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-005`: Artifact bucket missing aws:SecureTransport deny <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-s3-005 }

**Evidences:** [`2.1.2`](#ctrl-2-1-2) Ensure S3 Bucket Policy is set to deny HTTP requests.

**How this is detected.** S3 endpoints accept HTTP and HTTPS by default. Without an explicit Deny on ``aws:SecureTransport=false``, a plaintext request, typically from a misconfigured client or a SDK with a stale endpoint, is honored if signed. The bucket policy Deny is the only enforcement; no account-level switch covers it.

**Recommendation.** Add a Deny statement for s3:* with Bool aws:SecureTransport=false.

**Source:** [`S3-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SM-001`: Secrets Manager secret has no rotation configured <span class="pg-sev pg-sev--high">HIGH</span> { #detail-sm-001 }

**Evidences:** [`1.14`](#ctrl-1-14) Ensure access keys are rotated every 90 days or less.

**How this is detected.** Only secrets actually referenced by CodeBuild are checked, secrets used purely by application workloads are out of scope for a CI/CD scanner.

**Recommendation.** Enable automatic rotation on every Secrets Manager secret referenced by a CodeBuild project or CodePipeline. Unrotated secrets persist indefinitely, so a single leak (e.g. a build log that echoed the value) compromises the secret for its full lifetime.

**Source:** [`SM-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SM-002`: Secrets Manager resource policy allows wildcard principal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-sm-002 }

**Evidences:** [`1.16`](#ctrl-1-16) Ensure IAM policies that allow full '*:*' administrative privileges are not attached.

**How this is detected.** A wildcard-principal Allow on a Secrets Manager resource policy means any principal in any AWS account can call ``GetSecretValue`` (subject to conditions, if any). Always combine with at least ``aws:SourceAccount`` or ``aws:PrincipalOrgID``, the lift-and-shift cross-account secret-access pattern needs scoping.

**Recommendation.** Remove Allow statements whose Principal is ``*`` from every Secrets Manager resource policy, or scope them with a ``Condition`` restricting the source account/org (``aws:PrincipalOrgID``). A wildcard-principal policy allows any AWS account to call ``GetSecretValue`` on the secret.

**Source:** [`SM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SSM-001`: SSM Parameter with secret-like name is not a SecureString <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ssm-001 }

**Evidences:** [`3.7`](#ctrl-3-7) Ensure CloudTrail logs are encrypted at rest using KMS CMKs.

**How this is detected.** An SSM ``String`` parameter is plaintext at rest and at API; ``ssm:GetParameter`` without any KMS Decrypt authority returns the value. ``SecureString`` adds KMS-encryption + the ``WithDecryption=true`` flag (which forces an explicit KMS authorization step). Secret-named parameters (``TOKEN``, ``PASSWORD``, ``KEY``) are almost always intended to be SecureString and rarely should not be.

**Recommendation.** Recreate the parameter with ``Type=SecureString`` and migrate consumers to the new name if needed. Plain ``String`` parameters are visible via ``ssm:GetParameter`` without any KMS authorization.

**Proof of exploit.**

# Vulnerable: secret-named parameter stored as plain ``String``.
$ aws ssm put-parameter \
    --name /prod/api/GITHUB_TOKEN \
    --value ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
    --type String

# Attack: any principal with the minimal ``ssm:GetParameter``
# permission reads the cleartext, no KMS authorization needed:
#
#   aws ssm get-parameter --name /prod/api/GITHUB_TOKEN
#   # Returns the plaintext, even for principals with
#   # ``kms:Decrypt`` explicitly denied account-wide.
#
# CloudTrail records the GetParameter call but not the value;
# defenders see the access only by name + principal, not what
# was read.

# Safe: SecureString forces a separate KMS authorization step.
$ aws ssm put-parameter \
    --name /prod/api/GITHUB_TOKEN \
    --value ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
    --type SecureString \
    --key-id alias/prod-secrets

# Now readers need BOTH ``ssm:GetParameter`` AND ``kms:Decrypt``
# on the named CMK, and the call only returns plaintext when
# ``WithDecryption=true`` is set (an explicit, auditable opt-in).

**Source:** [`SSM-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SSM-002`: SSM SecureString uses the default AWS-managed key <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ssm-002 }

**Evidences:** [`3.7`](#ctrl-3-7) Ensure CloudTrail logs are encrypted at rest using KMS CMKs, [`3.8`](#ctrl-3-8) Ensure rotation for customer-created symmetric CMKs is enabled.

**How this is detected.** ``alias/aws/ssm`` is the AWS-managed default for SecureString. Its key policy is fixed and account-wide. A customer-managed key gives you the same per-parameter key-policy + CloudTrail audit story you'd apply to Secrets Manager (which always uses a CMK).

**Recommendation.** Recreate SecureString parameters with ``KeyId`` pointing at a customer-managed KMS key. The default ``alias/aws/ssm`` key is shared across the account and its key policy cannot be audited or scoped per parameter.

**Source:** [`SSM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

---

_This page is generated. Edit `pipeline_check/core/standards/data/cis_aws_foundations.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py cis_aws_foundations`._
