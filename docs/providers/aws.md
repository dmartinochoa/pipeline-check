# AWS provider

The AWS provider uses a `boto3.Session` scoped to a single region. It
supports named AWS CLI profiles via `--profile` and honors the
`AWS_ENDPOINT_URL` environment variable (for LocalStack).

Every AWS rule is one module under
`pipeline_check/core/checks/aws/rules/<id>_<slug>.py`, auto-discovered by
`AWSRuleChecks` and given a shared `ResourceCatalog` so enumerations run
once per scan.

## Services covered

| Service | Check IDs |
|---|---|
| CodeBuild | CB-001..011 |
| CodePipeline | CP-001..007 |
| CodeDeploy | CD-001, CD-002, CD-003 |
| ECR | ECR-001..007 |
| IAM | IAM-001..008 |
| PBAC (CodeBuild roles/VPC, pipeline role scoping) | PBAC-001..005 |
| S3 | S3-001, S3-002, S3-003, S3-004, S3-005 |
| CloudTrail | CT-001, CT-002, CT-003 |
| CloudWatch Logs | CWL-001, CWL-002 |
| CloudWatch Alarms | CW-001 |
| Secrets Manager | SM-001, SM-002 |
| CodeArtifact | CA-001, CA-002, CA-003, CA-004 |
| CodeCommit | CCM-001, CCM-002, CCM-003 |
| Lambda | LMB-001, LMB-002, LMB-003, LMB-004 |
| KMS | KMS-001, KMS-002 |
| SSM Parameter Store | SSM-001, SSM-002 |
| EventBridge | EB-001, EB-002 |
| AWS Signer | SIGN-001, SIGN-002 |

## CLI usage

```bash
# Default: scan us-east-1 with the ambient boto3 credential chain
pipeline_check --pipeline aws

# Pick a region
pipeline_check --pipeline aws --region eu-west-1

# Use a named AWS CLI profile (~/.aws/credentials)
pipeline_check --pipeline aws --profile prod-readonly

# Scope the scan to a single resource (e.g. one CodePipeline)
pipeline_check --pipeline aws --target my-release-pipeline

# Point boto3 at a local endpoint (LocalStack, etc.)
AWS_ENDPOINT_URL=http://localhost:4566 pipeline_check --pipeline aws
```

Credentials are resolved through the standard
[boto3 credential chain](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html). Environment variables, `~/.aws/credentials`, IMDS on EC2, container
credentials on ECS/Fargate, EKS Pod Identity, or SSO. To scan a different
account, assume the role first with `aws sts assume-role` (or
`aws sso login` / `aws-vault`) and export the resulting credentials, then
invoke `pipeline_check`. The provider does not currently accept an
`--assume-role-arn` flag.

## Required IAM permissions

The scanner is **read-only**: every API call is a `List*`, `Describe*`,
`Get*`, or `BatchGet*`. It never mutates state. Per-resource API calls
are scoped to the active `--region`; IAM, S3, and STS are global and are
reached through the same regional session.

### Quickest path: managed policies

If you don't care about least-privilege, attach one of:

- `arn:aws:iam::aws:policy/SecurityAudit`: covers everything below
  except a few `Get*Policy` calls; produces the same findings minus
  `S3-005` (bucket policies), `LMB-004` (Lambda resource policy),
  `KMS-002` (key policy), `CA-003`/`CA-004` (CodeArtifact policies),
  `ECR-003` (repo policy), `SM-002` (secret resource policy).
- `arn:aws:iam::aws:policy/ReadOnlyAccess`: covers every action the
  scanner uses, plus a great deal more. Convenient but broad.

For least-privilege, use the policy below.

### Permission map by service

Each row lists the check IDs that depend on the actions in that service.
If you skip a service entirely, you can drop its row from the policy and
the scanner will emit a `<PREFIX>-000` degraded finding (INFO) for that
service rather than failing.

| Service | Check IDs that need it | Required actions |
|---|---|---|
| CodeBuild | CB-001..011, PBAC-001 | `codebuild:ListProjects`, `codebuild:BatchGetProjects`, `codebuild:ListSourceCredentials` |
| CodePipeline | CP-001..007, PBAC-005 (also feeds S3 artifact-bucket discovery) | `codepipeline:ListPipelines`, `codepipeline:GetPipeline` |
| CodeDeploy | CD-001..003 | `codedeploy:ListApplications`, `codedeploy:ListDeploymentGroups`, `codedeploy:BatchGetDeploymentGroups` |
| ECR | ECR-001..007 | `ecr:DescribeRepositories`, `ecr:GetRepositoryPolicy`, `ecr:GetLifecyclePolicy`, `ecr:DescribePullThroughCacheRules` |
| Inspector v2 | ECR-007 | `inspector2:BatchGetAccountStatus` |
| IAM | IAM-001..008, PBAC-002, CICD-role enumeration | `iam:ListRoles`, `iam:ListUsers`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion` |
| CloudTrail | CT-001..003 | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` |
| CloudWatch Logs | CWL-001, CWL-002 | `logs:DescribeLogGroups` |
| CloudWatch Alarms | CW-001 | `cloudwatch:DescribeAlarms` |
| Secrets Manager | SM-001, SM-002 | `secretsmanager:ListSecrets`, `secretsmanager:GetResourcePolicy` |
| CodeArtifact | CA-001..004 | `codeartifact:ListDomains`, `codeartifact:ListRepositories`, `codeartifact:DescribeRepository`, `codeartifact:GetDomainPermissionsPolicy`, `codeartifact:GetRepositoryPermissionsPolicy` |
| CodeCommit | CCM-001..003 | `codecommit:ListRepositories`, `codecommit:GetRepository`, `codecommit:GetRepositoryTriggers`, `codecommit:ListAssociatedApprovalRuleTemplatesForRepository` |
| Lambda | LMB-001..004 | `lambda:ListFunctions`, `lambda:GetFunctionCodeSigningConfig`, `lambda:GetFunctionUrlConfig`, `lambda:GetPolicy` |
| KMS | KMS-001, KMS-002 | `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:GetKeyPolicy` |
| SSM Parameter Store | SSM-001, SSM-002 | `ssm:DescribeParameters` |
| EventBridge | EB-001, EB-002 | `events:ListRules`, `events:ListTargetsByRule` |
| Signer | SIGN-001, SIGN-002 | `signer:ListSigningProfiles` |
| S3 | S3-001..005 (artifact buckets discovered via CodePipeline) | `s3:GetPublicAccessBlock`, `s3:GetBucketEncryption`, `s3:GetBucketVersioning`, `s3:GetBucketLogging`, `s3:GetBucketPolicy` |
| EC2 | PBAC-003 (CodeBuild VPC security groups) | `ec2:DescribeSecurityGroups` |
| STS | CCM-003 (current account ID for cross-account trigger detection) | `sts:GetCallerIdentity` |

### Copy-paste IAM policy

Save the following as `pipeline-check-readonly.json` and attach it to the
role or user the scanner runs as. Every action is read-only and every
resource is `*` because boto3 list/describe APIs do not accept
resource-level conditions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PipelineCheckReadOnlyScan",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudwatch:DescribeAlarms",
        "codeartifact:DescribeRepository",
        "codeartifact:GetDomainPermissionsPolicy",
        "codeartifact:GetRepositoryPermissionsPolicy",
        "codeartifact:ListDomains",
        "codeartifact:ListRepositories",
        "codebuild:BatchGetProjects",
        "codebuild:ListProjects",
        "codebuild:ListSourceCredentials",
        "codecommit:GetRepository",
        "codecommit:GetRepositoryTriggers",
        "codecommit:ListAssociatedApprovalRuleTemplatesForRepository",
        "codecommit:ListRepositories",
        "codedeploy:BatchGetDeploymentGroups",
        "codedeploy:ListApplications",
        "codedeploy:ListDeploymentGroups",
        "codepipeline:GetPipeline",
        "codepipeline:ListPipelines",
        "ec2:DescribeSecurityGroups",
        "ecr:DescribePullThroughCacheRules",
        "ecr:DescribeRepositories",
        "ecr:GetLifecyclePolicy",
        "ecr:GetRepositoryPolicy",
        "events:ListRules",
        "events:ListTargetsByRule",
        "iam:GetAccessKeyLastUsed",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRolePolicy",
        "iam:ListAccessKeys",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:ListRoles",
        "iam:ListUsers",
        "inspector2:BatchGetAccountStatus",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListKeys",
        "lambda:GetFunctionCodeSigningConfig",
        "lambda:GetFunctionUrlConfig",
        "lambda:GetPolicy",
        "lambda:ListFunctions",
        "logs:DescribeLogGroups",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3:GetBucketVersioning",
        "s3:GetPublicAccessBlock",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:ListSecrets",
        "signer:ListSigningProfiles",
        "ssm:DescribeParameters",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

The policy is **2.5 KB**, well inside the 6,144-byte limit for a
customer-managed policy and the 10,240-byte limit for an inline role
policy.

### Trust policy for an IAM role

If you run the scanner from CI (e.g. GitHub Actions with OIDC), pair
the policy above with a trust policy that lets your CI system assume
the role. Below is an example for GitHub Actions OIDC; adapt for your
provider.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

### Behavior when permissions are missing

The scanner does not fail closed when the principal lacks an action.
Instead, the per-service enumeration records the error and the
orchestrator emits one `<PREFIX>-000` finding (INFO severity) per
degraded service, for example `CT-000`, `LMB-000`, `KMS-000`. Every
rule that depends on that service is suppressed for the run. Operators
can therefore see exactly which permission gaps are masking findings.

Two exceptions are tolerated silently because their endpoints are
optional:

- `ecr:DescribePullThroughCacheRules`: not all regions/accounts have
  PTC; only ECR-006 is suppressed if it fails.
- `inspector2:BatchGetAccountStatus`: only ECR-007 is suppressed if
  Inspector v2 is not enabled in the region.

## What it covers

71 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [CA-001](#ca-001) | CodeArtifact domain has no KMS encryptionKey configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CA-002](#ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CA-003](#ca-003) | CodeArtifact domain policy allows cross-account wildcard | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [CA-004](#ca-004) | CodeArtifact repo policy grants ``codeartifact:*`` with ``Resource '*'`` | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-001](#cb-001) | Secrets in plaintext environment variables | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [CB-002](#cb-002) | Privileged mode enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-003](#cb-003) | Build logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CB-004](#cb-004) | No build timeout configured | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [CB-005](#cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CB-006](#cb-006) | CodeBuild source auth uses long-lived token | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-007](#cb-007) | CodeBuild webhook has no filter group | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
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
| [ECR-007](#ecr-007) | Inspector v2 enhanced scanning disabled for ECR | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [IAM-001](#iam-001) | CI/CD role has AdministratorAccess policy attached | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [IAM-002](#iam-002) | CI/CD role has wildcard Action in attached policy | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-003](#iam-003) | CI/CD role has no permission boundary | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [IAM-004](#iam-004) | CI/CD role can PassRole to any role | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-005](#iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-006](#iam-006) | Sensitive actions granted with wildcard Resource | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [IAM-007](#iam-007) | IAM user has access key older than 90 days | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-008](#iam-008) | OIDC-federated role trust policy missing audience or subject pin | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [KMS-001](#kms-001) | KMS customer-managed key has rotation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [KMS-002](#kms-002) | KMS key policy grants wildcard KMS actions | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [LMB-001](#lmb-001) | Lambda function has no code-signing config | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [LMB-002](#lmb-002) | Lambda function URL has AuthType=NONE | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [LMB-003](#lmb-003) | Lambda function env vars may contain plaintext secrets | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [LMB-004](#lmb-004) | Lambda resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [PBAC-001](#pbac-001) | CodeBuild project has no VPC configuration | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PBAC-002](#pbac-002) | CodeBuild service role shared across multiple projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PBAC-003](#pbac-003) | CodeBuild security group allows 0.0.0.0/0 all-port egress | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PBAC-005](#pbac-005) | CodePipeline stage action roles mirror the pipeline role | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [S3-001](#s3-001) | Artifact bucket public access block not fully enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [S3-002](#s3-002) | Artifact bucket server-side encryption not configured | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [S3-003](#s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [S3-004](#s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [S3-005](#s3-005) | Artifact bucket missing aws:SecureTransport deny | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SIGN-001](#sign-001) | No AWS Signer profile defined for Lambda deploys | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SIGN-002](#sign-002) | AWS Signer profile is revoked or inactive | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SM-001](#sm-001) | Secrets Manager secret has no rotation configured | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SM-002](#sm-002) | Secrets Manager resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [SSM-001](#ssm-001) | SSM Parameter with secret-like name is not a SecureString | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SSM-002](#ssm-002) | SSM SecureString uses the default AWS-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## CA-001: CodeArtifact domain has no KMS encryptionKey configured { #ca-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

When no ``encryptionKey`` is configured on the domain, AWS uses its own managed key, keeping the key policy under AWS's control. That removes your ability to scope or audit Decrypt operations, and you can't revoke key access without recreating the domain. A customer-managed CMK puts those controls back in your hands. Note: the CodeArtifact API returns the resolved KMS key ARN in this field; the check flags only the absent-key case because the ARN alone does not reliably identify whether the key is AWS-managed or customer-managed without a separate ``kms:DescribeKey`` call.

<div class="pg-rule__rec" markdown>

**Recommended action**

Recreate the CodeArtifact domain with an encryption-key argument pointing at a customer-managed CMK. Domain encryption is set at creation and cannot be changed after.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CA-002: CodeArtifact repository has a public external connection { #ca-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

An external connection to ``public:npmjs`` / ``public:pypi`` / ``public:nuget`` / ``public:maven-central`` fetches packages from the public registry on first resolution. A typo-squat (``request`` vs ``requests``) or a compromised upstream lands in the cache the first time anyone names it; every subsequent build pulls the cached substitute. The pull-through cache with an allow-list is the same risk shape solved by an explicit allowlist.

<div class="pg-rule__rec" markdown>

**Recommended action**

Route public package consumption through a pull-through cache repository governed by an allow-list of package names, and point build-time repos at that cache rather than directly at ``public:npmjs``/``public:pypi``. Unscoped public upstreams expose builds to dependency-confusion and typosquatting attacks.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CA-003: CodeArtifact domain policy allows cross-account wildcard { #ca-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

A wildcard-principal Allow on a CodeArtifact domain lets any AWS account reach the domain's permissions surface. The exact damage depends on the action set, but at minimum it lets external accounts read package names and versions, which is enough for typosquat-against-private-package attacks. ``aws:PrincipalOrgID`` is the org-level rescue without enumerating accounts.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove Allow statements with ``Principal: '*'`` from every CodeArtifact domain permissions policy, or restrict them with an ``aws:PrincipalOrgID`` condition so only accounts in your org can consume packages from the domain.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CA-004: CodeArtifact repo policy grants ``codeartifact:*`` with ``Resource '*'`` { #ca-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

``codeartifact:*`` on ``Resource: '*'`` collapses the entire repository's authority into one grant: the holder can read, write, delete, dispose, and re-publish every package. Even for a service principal that nominally only consumes packages, the grant lets a compromise of that consumer rewrite every dependency the team relies on.

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope Allow statements to specific ``codeartifact:`` actions (e.g. ``codeartifact:ReadFromRepository``) and to specific package-group ARNs. Wildcard action + wildcard resource is the classic over-broad grant that lets a consumer also publish.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CB-001: Secrets in plaintext environment variables { #cb-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Flags a plaintext env var when either (a) its **name** matches a secret-like pattern (PASSWORD, TOKEN, API_KEY, ...) or (b) its **value** matches a known credential shape (AKIA/ASIA access keys, GitHub tokens, Slack xox* tokens, JWTs). Plaintext values are visible in the AWS console, CloudTrail, and build logs to anyone with read access.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move secrets to AWS Secrets Manager or SSM Parameter Store and reference them using type SECRETS_MANAGER or PARAMETER_STORE in the CodeBuild environment variable configuration.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CB-002: Privileged mode enabled { #cb-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Privileged mode grants the build container root access to the host's Docker daemon. A compromised build can escape the container or tamper with the host. Only flip this on for real Docker-in-Docker workloads and keep the buildspec under branch-protected review.

<div class="pg-rule__rec" markdown>

**Recommended action**

Disable privileged mode unless the project explicitly requires Docker-in-Docker builds. If required, ensure the buildspec is tightly controlled, peer-reviewed, and sourced from a trusted repository with branch protection.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CB-003: Build logging not enabled { #cb-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

A CodeBuild project with neither CloudWatch Logs nor S3 logging enabled leaves no durable record of what the build did. The CodeBuild console shows the last execution's logs for a short retention window, but anything older, and any automated review of historical activity during incident response, is gone.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable CloudWatch Logs or S3 logging in the CodeBuild project configuration to maintain a durable audit trail of all build activity.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CB-004: No build timeout configured { #cb-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

A CodeBuild project at AWS's 480-minute maximum is rarely deliberate. Without a tighter ceiling, a runaway test loop, a fork-PR cryptomining payload, or a build that hangs on stdin keeps the build host (and its IAM role) live for the full eight hours, racking up cost and extending the compromise window.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set a build timeout appropriate for your expected build duration (typically 15–60 minutes) to limit the blast radius of a runaway or abused build.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CB-005: Outdated managed build image { #cb-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Only AWS-managed ``aws/codebuild/standard:N.0`` images are version-checked. Custom or third-party images pass here, CB-009 handles the separate concern of tag vs digest pinning for custom images.

**Known false-positive modes**

- One version behind the current ``aws/codebuild/standard`` is a hygiene warning, not a production issue, and defaults to MEDIUM confidence. The rule emits HIGH only when the project is two or more versions behind. Custom or third-party images are not version-checked here; CB-009 handles tag-vs-digest pinning for those.

<div class="pg-rule__rec" markdown>

**Recommended action**

Update the CodeBuild environment image to aws/codebuild/standard:7.0 or later to ensure the build environment receives the latest security patches.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CB-006: CodeBuild source auth uses long-lived token { #cb-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

OAUTH / PERSONAL_ACCESS_TOKEN / BASIC_AUTH source credentials are stored long-lived on the account and used by every CodeBuild project that points at the SCM provider. Rotating the upstream PAT requires manual re-credentialing here too. CodeConnections (CodeStar) is the AWS-managed alternative with token refresh and revocation.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch to an AWS CodeConnections (CodeStar) connection and reference it from the source configuration. Delete any stored source credentials of type OAUTH, PERSONAL_ACCESS_TOKEN, or BASIC_AUTH via delete_source_credentials.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CB-007: CodeBuild webhook has no filter group { #cb-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A CodeBuild webhook with no filter groups fires on every push and every PR from any actor, including fork PRs from outside the org. Anyone able to open a PR triggers the build with whatever IAM authority the project's role carries. Filter groups (branch + actor + event type) are the gate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Define filter groups restricting triggers to specific branches, actors, and event types.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CB-008: CodeBuild buildspec is inline (not sourced from a protected repo) { #cb-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

An inline buildspec (source.buildspec set to YAML text, or a S3 URL) bypasses the protections that cover your source code. A user with ``codebuild:UpdateProject`` can rewrite the build commands without touching the repository, no PR review, no branch protection, no audit of what changed. Store buildspec.yml in the repo instead.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the inline buildspec and store buildspec.yml in the source repository under branch protection. Anyone with codebuild:UpdateProject can silently rewrite an inline buildspec; repository-sourced buildspecs inherit the repo's review and protection controls.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CB-009: CodeBuild image not pinned by digest { #cb-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

CodeBuild pulls the environment image on every build. A tag pointer can be moved by whoever controls the registry; a digest cannot. AWS-managed ``aws/codebuild/...`` images are exempt. Those are covered by CB-005 and are not part of the tag-mutation threat model.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin custom CodeBuild images by ``@sha256:<digest>``. Tag-based references (``:latest``, ``:1.2.3``) can be silently overwritten to point at a malicious layer that is pulled on the next build.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CB-010: CodeBuild webhook allows fork-PR builds without actor filtering { #cb-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

GitHub/Bitbucket webhook filter groups that fire on pull-request events will build forks by default. Because CodeBuild runs with the project's own IAM role (not the PR author's), a fork PR can execute arbitrary code with CI privileges and exfiltrate secrets. Restrict to known contributors with an ``ACTOR_ACCOUNT_ID`` pattern group.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an ``ACTOR_ACCOUNT_ID`` filter pattern to every webhook filter group that accepts ``PULL_REQUEST_CREATED`` / ``PULL_REQUEST_UPDATED`` / ``PULL_REQUEST_REOPENED``, or remove those PR event types. Without actor filtering, any fork can trigger a build that runs with the project's service role.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CB-011: CodeBuild buildspec contains indicators of malicious activity { #cb-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-506</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Scans the ``source.buildspec`` text on every CodeBuild project for concrete attack indicators: reverse shells, base64-decoded execution, miner binaries/pools, Discord/Telegram webhooks, credential-dump pipes, audit-erasure commands. CB-011 is CRITICAL by design, a true positive is evidence of compromise, not a hygiene improvement. Repo-sourced buildspecs (not inlined) return ``NOT APPLICABLE`` because the text isn't visible to the scanner; CB-008 already flags the inline form as a governance gap.

**Known false-positive modes**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat as a potential compromise. Identify which principal or pipeline ran the CodeBuild project recently, rotate its service role's credentials, audit CloudTrail for outbound activity to the matched hosts, and, if an inline buildspec is in use (CB-008), enforce repo-sourced buildspecs under branch protection so the next malicious edit requires a PR.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CCM-001: CodeCommit repository has no approval rule template attached { #ccm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Approval-rule templates are CodeCommit's analog of GitHub's branch-protection require-review. Without one associated, the repository accepts merges from any push-permitted principal, including the PR author themselves, without any second-pair-of-eyes gate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a CodeCommit approval-rule template requiring at least one approval from a designated pool of reviewers and associate it with every repository. Without one, any PR author with push rights can self-approve and merge.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CCM-002: CodeCommit repository not encrypted with customer KMS CMK { #ccm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Same shape as CA-001 / ECR-005 / S3 default encryption: the AWS-owned default key keeps the key policy under AWS, removing your ability to scope or audit Decrypt operations. Source code in the repo deserves the same key-policy + CloudTrail story you'd apply to artifacts in S3.

<div class="pg-rule__rec" markdown>

**Recommended action**

Recreate the repository with a ``kmsKeyId`` argument pointing at a customer-managed KMS key. CodeCommit encryption is set at creation and cannot be changed afterwards.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CCM-003: CodeCommit trigger targets SNS/Lambda in a different account { #ccm-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-441</span>
</div>

A repo trigger pointing at an SNS topic or Lambda in a different account fires under the receiving account's permissions on every push. Sometimes this is the intended shape (a centralized notifications account), but a cross-account fan-out from a compromised repo can drive actions in the receiving account that the source-account owner can't directly observe.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move trigger targets into the same account as the repository or explicitly document the cross-account relationship. Cross-account triggers extend the blast radius of a repository compromise to whatever the target ARN can do.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CD-001: Automatic rollback on failure not enabled { #cd-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-754</span>
</div>

Without ``autoRollbackConfiguration``, a CodeDeploy deployment that fails leaves the failed revision live until an operator notices. The default is opt-in, not opt-out, deployments fail-open, not fail-back.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable autoRollbackConfiguration with at least the DEPLOYMENT_FAILURE event so CodeDeploy automatically reverts to the last successful revision when a deployment fails.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CD-002: AllAtOnce deployment config, no canary or rolling strategy { #cd-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-754</span>
</div>

AllAtOnce shifts 100% of traffic to the new revision in one step. There's no gradient to halt on if a CloudWatch alarm trips mid-rollout, the bad revision is already serving every request. Canary / linear configs introduce the shift-then-watch shape that lets monitors catch a regression before it's universal.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch to a canary or linear deployment configuration (e.g. CodeDeployDefault.LambdaCanary10Percent5Minutes or a custom rolling config) so that defects are caught before they affect all instances or traffic.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CD-003: No CloudWatch alarm monitoring on deployment group { #cd-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Alarm-based rollback is what lets a canary configuration actually stop a bad deploy mid-flight. Without alarms wired into ``alarmConfiguration``, CodeDeploy's only signal that the deploy went wrong is the deployment-state machine itself, which doesn't notice an application-level regression. CD-002's canary work and this rule's alarm-based halt are paired.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add CloudWatch alarms (e.g. error rate, 5xx count, latency p99) to the deployment group's alarmConfiguration. Enable automatic rollback on DEPLOYMENT_STOP_ON_ALARM to halt bad deployments.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CP-001: No approval action before deploy stages { #cp-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A pipeline that goes Source -> Build -> Deploy with no Approval action means every commit on the source branch ships, with no human ack between code-merged and code-running-in-prod. The Manual approval action is the intentional pause point, combine with CP-005 for production-tagged stages specifically.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a Manual approval action to a stage that precedes every Deploy stage that targets a production or sensitive environment.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CP-002: Artifact store not encrypted with customer-managed KMS key { #cp-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

The pipeline's S3 artifact store holds intermediate build outputs handed between stages. Default SSE-S3 (AES256) encrypts at rest but uses an AWS-owned key whose policy you can't scope. A customer-managed CMK gives the same key-policy + CloudTrail Decrypt-event audit story you'd apply to Lambda code, Secrets Manager, or any other build output.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure a customer-managed AWS KMS key as the encryptionKey for each artifact store. This enables key rotation, fine-grained access policies, and CloudTrail auditing of decrypt operations.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CP-003: Source stage using polling instead of event-driven trigger { #cp-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

``PollForSourceChanges=true`` polls the source repo every minute or two. Beyond the API-quota and latency cost, polling produces a less-useful CloudTrail story than event-driven triggers. You see the poll calls, not the specific commit that started the pipeline. EventBridge / CodeCommit triggers tie each pipeline start to the originating event.

**Known false-positive modes**

- ``PollForSourceChanges=true`` is the CFN default for CodeCommit sources, so legacy templates can carry the flag without an active design decision behind it. The rule is advisory (consider EventBridge / CodeStarSourceConnection) rather than a real risk; defaults to LOW confidence so CI gates default-filter it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set PollForSourceChanges=false and configure an Amazon EventBridge rule or CodeCommit trigger to start the pipeline on change. This reduces latency, API usage, and improves auditability.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CP-004: Legacy ThirdParty/GitHub source action (OAuth token) { #cp-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

The legacy ThirdParty/GitHub source-action provider stores a long-lived OAuth token in the pipeline's action configuration. The token has whatever scope the granting GitHub user has, never rotates, and isn't directly revocable from the AWS side. CodeConnections (formerly CodeStar Connections) replaces this with an AWS-managed connection that the GitHub user can revoke.

<div class="pg-rule__rec" markdown>

**Recommended action**

Migrate to owner=AWS, provider=CodeStarSourceConnection and reference a CodeConnections connection ARN.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CP-005: Production Deploy stage has no preceding ManualApproval { #cp-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

The complement to CP-001: this rule fires only on stages whose name contains ``prod`` / ``production`` / ``live``. Even teams that intentionally skip approvals for dev / staging deploys usually want a human in the loop for a production-tagged target.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``Manual`` approval action immediately before any stage whose name contains ``prod`` / ``production`` / ``live``. CP-001 covers the generic case; this rule specifically looks at production-tagged stages where the blast radius of an unreviewed deploy is largest.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CP-007: CodePipeline v2 PR trigger accepts all branches { #cp-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

V2 pipelines added native PR triggers; without a ``branches.includes`` filter, any PR, including fork PRs from outside the org, fires the pipeline. The build stage runs with whatever IAM authority the pipeline's role carries, which is the full attack surface a fork-PR compromise can reach.

<div class="pg-rule__rec" markdown>

**Recommended action**

On V2 pipelines, add an ``includes`` filter under the trigger's ``branches`` block (and optionally ``pullRequest.events``) so only PRs targeting specific branches run. Without a filter, any fork-PR can execute the pipeline's build and deploy stages.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CT-001: No active CloudTrail trail in region { #ct-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

CloudTrail is the only AWS-native source of record for management-plane API calls. A region with no active trail blinds incident responders: a pipeline compromise is invisible once the in-memory CloudWatch buffer rolls over.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a CloudTrail trail that logs management events in this region and start logging. Without a trail, CodeBuild/CodePipeline/IAM API activity, including credential changes during a compromise, has no durable audit record.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CT-002: CloudTrail log-file validation disabled { #ct-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-354</span>
</div>

CloudTrail logs are S3 objects. Without log-file validation, an attacker with ``s3:PutObject`` on the trail bucket can edit log files to remove evidence of their activity, and there's no digest to compare against. With validation on, every hour of logs is summarized in a signed digest file under ``CloudTrail-Digest/``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``LogFileValidationEnabled=true`` on every CloudTrail trail. Log validation produces a signed digest file alongside each log object so tampering by an attacker who also has S3 write access can be detected after the fact.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CT-003: CloudTrail trail is not multi-region { #ct-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

An attacker who knows your CloudTrail trail is regional deliberately operates from a different region. Multi-region trails capture management events from every region into a single trail, closing the gap without you having to enumerate which regions you actually use.

<div class="pg-rule__rec" markdown>

**Recommended action**

Convert the trail to a multi-region trail. A single-region trail misses activity in every other region, an attacker aware of the scope can drive reconnaissance or persistence from an unlogged region.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CW-001: No CloudWatch alarm on CodeBuild FailedBuilds metric { #cw-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Failure-rate signals are how on-call learns about an unfamiliar build crashing in a loop, an attacker probing the build environment, or a CI quota being exhausted. CloudWatch captures the ``FailedBuilds`` metric automatically, the alarm is the missing fan-out.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a CloudWatch alarm on the ``AWS/CodeBuild`` namespace ``FailedBuilds`` metric (aggregated or per-project). Without one, repeated build failures during a compromise, or a runaway fork-PR build, won't reach on-call.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CWL-001: CodeBuild log group has no retention policy { #cwl-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

CloudWatch Logs created by CodeBuild default to ``Never Expire`` retention. Build logs frequently echo secrets accidentally (a `set -x` script, an `env` dump in an error trace), so unbounded retention extends the exposure window for every secret a build has ever leaked. A short-but-finite retention also caps cost.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set a retention policy on every ``/aws/codebuild/*`` log group. The default is 'Never Expire', which both racks up storage cost and keeps logs indefinitely past any compliance window.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CWL-002: CodeBuild log group not KMS-encrypted { #cwl-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

CloudWatch Logs default encryption is service-managed, fine for confidentiality, but no audit trail or scoping. Build logs are a frequent secret-leak vector (CWL-001's rationale extended), so the same key-policy + Decrypt-event story you'd apply to S3 / Lambda / Secrets Manager is warranted here too.

<div class="pg-rule__rec" markdown>

**Recommended action**

Associate a customer-managed KMS key with every ``/aws/codebuild/*`` log group via ``associate-kms-key``. Logs often contain secret material accidentally echoed by builds; encrypting them with a CMK means the key policy controls who can read the logs, not just S3/CloudWatch IAM.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## EB-001: No EventBridge rule for CodePipeline failure notifications { #eb-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Pipeline failure events are emitted to EventBridge automatically; the missing piece is a rule that pipes them to somewhere a human reads (SNS, Slack, PagerDuty). Without it, failures only surface via the CodePipeline console, which no one watches.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create an EventBridge rule matching ``detail-type: 'CodePipeline Pipeline Execution State Change'`` and ``state: FAILED``, and point it at an SNS topic or chat webhook. Without it, pipeline failures during an incident (a compromise triggering rollback, for example) go unnoticed.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## EB-002: EventBridge rule has a wildcard target ARN { #eb-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-441</span>
</div>

Wildcard target ARNs (e.g. ``arn:aws:lambda:us-east-1:123456789012:function:*``) match every resource that fits the prefix. This is rarely intentional, usually a copy-paste from a more permissive resource ARN, and means the rule fans out to a much larger set of consumers than the author meant.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace wildcard target ARNs with specific resource ARNs. EventBridge targets with ``*`` route events to any resource that matches the prefix, frequently triggering unintended Lambda invocations or SNS sends.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ECR-001: Image scanning on push not enabled { #ecr-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

scan-on-push runs a CVE check against the image's OS package layers at the moment it lands in ECR. Without it, an image with a known CVE deploys silently. The ECR basic scanner is free; ECR-007 covers the Inspector v2 enhanced scanner that adds language-ecosystem CVEs (npm, pip, gem).

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable imageScanningConfiguration.scanOnPush on the repository. Consider also enabling Amazon Inspector continuous scanning for ongoing CVE detection against images already in the registry.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ECR-002: Image tags are mutable { #ecr-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Mutable tags mean ``:latest``, ``:v1.0``, and ``:stable`` can be re-pushed silently, the same tag points to different image content over time. Pinning by digest (``sha256:...``) in deployment manifests is the only durable reference; IMMUTABLE on the repo enforces the property registry-side so a forgotten digest reference doesn't drift.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set imageTagMutability=IMMUTABLE on the repository. Reference images by digest (sha256:...) in deployment manifests for strongest immutability guarantees.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ECR-003: Repository policy allows public access { #ecr-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

A wildcard-principal repo policy means anyone on the internet can pull images. Sometimes intentional (a publicly-distributed base image), but should be a deliberate exposure, typically via the ECR Public registry rather than a private repo with a public policy. The default for build-output images should never be public.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove wildcard principals from the repository policy. Grant access only to specific AWS account IDs or IAM principals that require it.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## ECR-004: No lifecycle policy configured { #ecr-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without a lifecycle policy, untagged images and old tagged images accumulate indefinitely. Stale images keep CVE attack surface available, anyone who can pull from the repo can pull the old, unpatched version even after a newer build has shipped. Lifecycle expiry is the housekeeper that closes that window.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a lifecycle policy that expires untagged images after a short period (e.g. 7 days) and limits the number of tagged images retained, reducing exposure to images with known CVEs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ECR-005: Repository encrypted with AES256 rather than KMS CMK { #ecr-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Same shape as CP-002 / CWL-002 / CCM-002: AES256 (the AWS-managed default) gives confidentiality at rest but no key-policy or CloudTrail Decrypt-event story. Container images are arguably sensitive intellectual property, the same key-policy + audit shape as build outputs in S3 is warranted.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set encryptionType=KMS with a customer-managed key ARN.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ECR-006: ECR pull-through cache rule uses an untrusted upstream { #ecr-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

AWS supports pull-through cache for ECR Public, Quay, K8s, GitHub Container Registry, GitLab, and Docker Hub. A rule pointing at ``registry-1.docker.io`` without an authenticated credential silently caches whatever the public namespace resolves to.

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope pull-through cache rules to AWS-trusted registries (ECR Public, Quay.io with authentication, or a vetted private registry). Avoid wildcard or unauthenticated upstreams, a malicious image there gets cached into your account registry on first pull.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ECR-007: Inspector v2 enhanced scanning disabled for ECR { #ecr-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

ECR-001's basic on-push scan covers OS-level packages, apt / yum / apk lineage. Most production CVE risk is in language ecosystems (npm, pip, gem, mvn) which the basic scanner ignores. Inspector v2 enhanced scanning closes that gap and runs continuously, so a CVE published two weeks after a build still surfaces against the deployed image.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable Amazon Inspector v2 for the ``ECR`` scan type on this account. Basic ECR scanning on-push only covers OS packages; Inspector v2 enhanced scanning adds language-ecosystem CVEs and runs continuously as new vulnerabilities are published.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## IAM-001: CI/CD role has AdministratorAccess policy attached { #iam-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

A CI/CD service role with ``AdministratorAccess`` attached turns any pipeline compromise into account compromise. The classic anti-pattern: the role started narrow, the pipeline grew, someone attached AdministratorAccess to unblock a deploy, and it never came off.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace AdministratorAccess with least-privilege policies.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-002: CI/CD role has wildcard Action in attached policy { #iam-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

``Action: '*'`` on an attached policy is functionally equivalent to AdministratorAccess: the role can call every API in every service. The wildcard absorbs every new IAM action AWS adds, so the role's authority grows without any local change. Service-prefix wildcards like ``s3:*`` are caught by IAM-006, not this rule.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace wildcard actions with specific IAM actions.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## IAM-003: CI/CD role has no permission boundary { #iam-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

A permissions boundary is the maximum-permission ceiling for a role. Without one, every future PR that attaches another inline / managed policy raises the role's effective authority indefinitely. With a boundary in place, the policy churn happens beneath a fixed cap that your security team owns separately.

<div class="pg-rule__rec" markdown>

**Recommended action**

Attach a permissions boundary defining max permissions.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-004: CI/CD role can PassRole to any role { #iam-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

``iam:PassRole`` with ``Resource: '*'`` lets the principal hand any role to any service. Combined with a service that runs your code (Lambda, ECS, CodeBuild, EC2 Instance Profiles), this is role-hop privilege escalation: launch an ephemeral resource configured with a higher-privileged role, run code under that identity, exfil. Scoping by ARN + ``iam:PassedToService`` removes the escalation path.

<div class="pg-rule__rec" markdown>

**Recommended action**

Restrict iam:PassRole to specific role ARNs and add an iam:PassedToService condition.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-005: CI/CD role trust policy missing sts:ExternalId { #iam-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-441</span>
</div>

A trust policy that lets an external AWS account assume the role without an ``sts:ExternalId`` condition is vulnerable to the confused-deputy pattern: a third-party SaaS configured with your role ARN can also be used by another customer of that SaaS to assume your role (if they know the ARN). ``sts:ExternalId`` ties the role to a specific tenancy.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a Condition requiring sts:ExternalId for external principals.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## IAM-006: Sensitive actions granted with wildcard Resource { #iam-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

IAM-002 catches ``Action: "*"``. IAM-006 catches the more common "scoped action, unscoped resource" pattern on sensitive services (S3/KMS/SecretsManager/SSM/IAM/STS/DynamoDB/Lambda/EC2).

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope the Resource element to specific ARNs (buckets, keys, secrets, roles).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-007: IAM user has access key older than 90 days { #iam-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Every user in the account is evaluated. CI/CD tooling that still uses IAM users (older Jenkins agents, GitHub Actions pre-OIDC, third-party schedulers) shows up here. The 90-day window matches the common compliance baseline; rotate sooner if the key is used from on-prem or an untrusted runner.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate or delete IAM access keys older than 90 days. Long-lived static credentials are the #1 way compromised CI credentials get reused across environments, prefer short-lived STS tokens via OIDC federation or an assumed role.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-008: OIDC-federated role trust policy missing audience or subject pin { #iam-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

IAM-005 already covers cross-account AWS principals. This rule targets the OIDC federation path specifically because the blast radius of a missed audience/subject pin is the entire identity provider's tenant base (e.g. all GitHub users, not just your org).

<div class="pg-rule__rec" markdown>

**Recommended action**

Every Allow statement that trusts a federated OIDC provider (``token.actions.githubusercontent.com``, GitLab, CircleCI, Terraform Cloud, etc.) must pin both the audience (``...:aud = sts.amazonaws.com``) and a subject prefix (``...:sub`` matching ``repo:myorg/*``). Without these, any workflow from any tenant can assume the role.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## KMS-001: KMS customer-managed key has rotation disabled { #kms-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-321</span>
</div>

Annual rotation regenerates the underlying key material for the same CMK ARN. Existing ciphertexts can still be decrypted (KMS keeps old material around), but new encrypts use the new material, so a cryptographic exposure (side-channel, an accidental export, an old compromised offline backup) only protects ciphertexts from before the rotation.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable annual rotation on every customer-managed KMS key used for CI/CD artifact, log, and secret encryption. Unrotated CMKs keep the same key material indefinitely, so a single cryptographic exposure (side-channel, accidental export) is permanent.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## KMS-002: KMS key policy grants wildcard KMS actions { #kms-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

``kms:*`` on a key policy is administrative authority over the cipher boundary: ``CancelKeyDeletion``, ``ScheduleKeyDeletion``, ``ReEncrypt``, ``UpdateKeyDescription``, and the data-plane decrypt actions all collapse into one grant. A CI/CD principal almost never needs more than the data-plane subset (``Decrypt`` / ``GenerateDataKey`` / ``Encrypt``).

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``kms:*`` grants with specific actions needed by the caller (e.g. ``kms:Decrypt``, ``kms:GenerateDataKey``). Key-policy wildcard grants let any holder of the principal re-key, schedule deletion, or export material at will.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## LMB-001: Lambda function has no code-signing config { #lmb-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-347</span>
</div>

Lambda code-signing config + a Signer profile (SIGN-001) validates that an uploaded zip was signed by a known profile before it's allowed to run. Without one, anyone who reaches ``lambda:UpdateFunctionCode``, a CI/CD role compromise, a misattached IAM policy, can replace the function's code with no chain-of-custody check.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create an AWS Signer profile, reference it from an ``aws_lambda_code_signing_config`` with ``untrusted_artifact_on_deployment = Enforce`` and attach that config to the function. Without one, the Lambda runtime will execute any code that a principal with lambda:UpdateFunctionCode uploads.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## LMB-002: Lambda function URL has AuthType=NONE { #lmb-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-306</span>
</div>

A Lambda function URL with ``AuthType=NONE`` is a public HTTPS endpoint. Anyone who knows the URL can invoke. This is sometimes deliberate (a webhook receiver) but the deliberate version typically signs / validates inside the function, the rule fires regardless because the IAM-side control isn't there.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set the function URL ``auth_type`` to ``AWS_IAM`` and grant ``lambda:InvokeFunctionUrl`` through IAM. ``NONE`` exposes the function to the public internet without authentication.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## LMB-003: Lambda function env vars may contain plaintext secrets { #lmb-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Lambda env vars are world-readable to any principal with ``lambda:GetFunctionConfiguration``, much wider than the principal that can invoke the function. They also persist in CloudFormation drift, change-sets, and CloudTrail events. A secret in a Lambda env var is essentially exposed to anyone with read access to the account.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move secrets out of Lambda environment variables and into Secrets Manager or SSM Parameter Store. Environment variables are visible to anyone with ``lambda:GetFunctionConfiguration`` and persist in CloudTrail events, which keeps the secret in audit logs.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## LMB-004: Lambda resource policy allows wildcard principal { #lmb-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

A wildcard-principal Allow on a Lambda function resource policy lets anyone invoke. The legitimate case is a service principal (API Gateway, S3 events) where AWS fills in the SourceArn/SourceAccount at invoke time, without those conditions, any account using that service can invoke.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove Allow statements with ``Principal: '*'`` from every Lambda function resource policy, or scope them with a ``SourceArn`` / ``SourceAccount`` condition. Service principals (e.g. ``apigateway.amazonaws.com``) are the common legitimate case, ensure they carry a condition.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PBAC-001: CodeBuild project has no VPC configuration { #pbac-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A CodeBuild project with no VPC configuration runs in AWS-managed network space, egress to the public internet is unrestricted, every package registry / CDN / arbitrary endpoint is reachable. Inside a VPC, security-group + VPC-endpoint policies become the egress gate, which is the only practical way to limit a compromised build's exfiltration paths.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure the CodeBuild project to run inside a VPC with appropriate subnets and security groups. Use a NAT gateway or VPC endpoints to control outbound internet access and restrict build nodes to only the network resources they require.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PBAC-002: CodeBuild service role shared across multiple projects { #pbac-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

One CodeBuild service role across many projects means a compromise of any project's build environment grants access to whatever resources every other project's build needs. Per-project roles cap the radius, a backdoor in the ``foo-tests`` build can't reach the ``deploy-prod`` build's secrets if they each have their own role.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create a dedicated IAM service role for each CodeBuild project, scoped to only the permissions that specific project requires. This limits the blast radius if one project's build is compromised.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PBAC-003: CodeBuild security group allows 0.0.0.0/0 all-port egress { #pbac-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

A security-group egress rule of ``0.0.0.0/0`` on all ports/protocols means a compromised build can connect to any endpoint on the internet, typosquat-package registry, C2 server, attacker-owned dump endpoint. Even when the build is inside a VPC (PBAC-001), this egress rule negates the network-side gating.

<div class="pg-rule__rec" markdown>

**Recommended action**

Restrict CodeBuild security-group egress to the specific endpoints builds need (package registries, artifact repositories, STS). A wildcard egress rule lets a compromised build exfiltrate to anywhere on the internet.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PBAC-005: CodePipeline stage action roles mirror the pipeline role { #pbac-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

When stage actions don't set their own ``roleArn``, they fall back to the pipeline-level role, which is the union of every stage's needs. A compromise of any one stage (typically the build, which runs untrusted code) gains the deploy stage's authority, including production deploy credentials. Per-action roles cap the radius.

<div class="pg-rule__rec" markdown>

**Recommended action**

Give each stage action (Source, Build, Deploy) its own narrowly-scoped IAM role via ``roleArn`` on the action declaration. Sharing the pipeline-level role means a compromise of one action (e.g. a build) gains the permissions the deploy stage also needs.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## S3-001: Artifact bucket public access block not fully enabled { #s3-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

S3 Block Public Access is the bucket-level circuit breaker that supersedes any future ACL or bucket-policy edit. Without all four settings enabled, a misconfigured CloudFormation change or a stray ``aws s3api`` call can re-expose the bucket to the public, even if the bucket had previously been private.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable all four S3 Block Public Access settings on the artifact bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## S3-002: Artifact bucket server-side encryption not configured { #s3-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Default bucket encryption applies SSE-S3 (AES256) to every PutObject. As of January 2023, AWS enables this on all new buckets automatically, but existing buckets created before then can still be unencrypted unless explicitly configured. Without it, individual objects can be uploaded without encryption (the client gets to choose).

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable default bucket encryption using at minimum AES256 (SSE-S3). For stronger key control, use SSE-KMS with a customer-managed key.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## S3-003: Artifact bucket versioning not enabled { #s3-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Versioning makes overwrites and deletes recoverable: the previous content of an object survives until lifecycle expires it. Without versioning, an artifact overwrite (a bad pipeline run, a malicious replacement, a typo'd ``aws s3 cp``) is unrecoverable, the original bytes are gone.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable S3 versioning on the artifact bucket so that previous artifact versions are retained and rollback is possible. Combine with a lifecycle rule to expire old versions after a retention period.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## S3-004: Artifact bucket access logging not enabled { #s3-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

S3 server access logging records every API operation against the bucket, who, when, what object, what method. CloudTrail data events overlap but cost more; access logs are the cheap baseline. Without them, an exfiltration via ``GetObject`` doesn't leave a trail you can investigate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable S3 server access logging for the artifact bucket and direct logs to a separate, centralized logging bucket with restricted write access.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## S3-005: Artifact bucket missing aws:SecureTransport deny { #s3-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

S3 endpoints accept HTTP and HTTPS by default. Without an explicit Deny on ``aws:SecureTransport=false``, a plaintext request, typically from a misconfigured client or a SDK with a stale endpoint, is honored if signed. The bucket policy Deny is the only enforcement; no account-level switch covers it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a Deny statement for s3:* with Bool aws:SecureTransport=false.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SIGN-001: No AWS Signer profile defined for Lambda deploys { #sign-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-347</span>
</div>

AWS Signer profiles are the upstream of LMB-001's code-signing config. Without a profile defined, no function in the account can enforce code-signing, LMB-001's recommendation has nothing to point at. The profile is the foundation; the per-function code-signing config attaches it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create an AWS Signer profile with platform ``AWSLambda-SHA384-ECDSA`` and reference it from every Lambda code-signing config used by the pipeline. Without a profile, LMB-001 remediation isn't possible and release artifacts can't be signed at build time.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SIGN-002: AWS Signer profile is revoked or inactive { #sign-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-347</span>
</div>

A revoked or canceled Signer profile invalidates every signature it ever produced. Lambda functions configured to enforce code-signing fail to deploy until the profile is replaced (or, if ``UntrustedArtifactOnDeployment = Warn``, deploy with a CloudWatch warning the operator rarely reads).

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the signing profile: create a replacement and update every code-signing config that references the revoked profile. A revoked or canceled profile invalidates every signature it produced, lambdas relying on it will fail verification.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SM-001: Secrets Manager secret has no rotation configured { #sm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Only secrets actually referenced by CodeBuild are checked, secrets used purely by application workloads are out of scope for a CI/CD scanner.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable automatic rotation on every Secrets Manager secret referenced by a CodeBuild project or CodePipeline. Unrotated secrets persist indefinitely, so a single leak (e.g. a build log that echoed the value) compromises the secret for its full lifetime.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## SM-002: Secrets Manager resource policy allows wildcard principal { #sm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

A wildcard-principal Allow on a Secrets Manager resource policy means any principal in any AWS account can call ``GetSecretValue`` (subject to conditions, if any). Always combine with at least ``aws:SourceAccount`` or ``aws:PrincipalOrgID``, the lift-and-shift cross-account secret-access pattern needs scoping.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove Allow statements whose Principal is ``*`` from every Secrets Manager resource policy, or scope them with a ``Condition`` restricting the source account/org (``aws:PrincipalOrgID``). A wildcard-principal policy allows any AWS account to call ``GetSecretValue`` on the secret.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SSM-001: SSM Parameter with secret-like name is not a SecureString { #ssm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-312</span>
</div>

An SSM ``String`` parameter is plaintext at rest and at API; ``ssm:GetParameter`` without any KMS Decrypt authority returns the value. ``SecureString`` adds KMS-encryption + the ``WithDecryption=true`` flag (which forces an explicit KMS authorization step). Secret-named parameters (``TOKEN``, ``PASSWORD``, ``KEY``) are almost always intended to be SecureString and rarely should not be.

<div class="pg-rule__rec" markdown>

**Recommended action**

Recreate the parameter with ``Type=SecureString`` and migrate consumers to the new name if needed. Plain ``String`` parameters are visible via ``ssm:GetParameter`` without any KMS authorization.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SSM-002: SSM SecureString uses the default AWS-managed key { #ssm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

``alias/aws/ssm`` is the AWS-managed default for SecureString. Its key policy is fixed and account-wide. A customer-managed key gives you the same per-parameter key-policy + CloudTrail audit story you'd apply to Secrets Manager (which always uses a CMK).

<div class="pg-rule__rec" markdown>

**Recommended action**

Recreate SecureString parameters with ``KeyId`` pointing at a customer-managed KMS key. The default ``alias/aws/ssm`` key is shared across the account and its key policy cannot be audited or scoped per parameter.

</div>

</div>

---

## Adding a new AWS check

1. Drop a single module in
   `pipeline_check/core/checks/aws/rules/<id>_<slug>.py` exporting a
   `RULE` (metadata) and a `check(catalog: ResourceCatalog) -> list[Finding]`
   callable. The orchestrator (`AWSRuleChecks`) auto-discovers it and
   this doc's table picks it up on the next regen.
2. If the check needs a new enumeration, add a cached method to
   `ResourceCatalog` in `pipeline_check/core/checks/aws/_catalog.py`
   so every dependent rule reads from the same in-memory snapshot.
3. Add the check ID to
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
4. Add unit tests in `tests/aws/rules/test_<name>.py` using the
   `make_catalog` fixture.
5. (Recommended) Add a Terraform parity rule in
   `pipeline_check/core/checks/terraform/{extended,services,phase3}.py`
   so shift-left scans stay at parity with the runtime provider.
6. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py aws
   ```
