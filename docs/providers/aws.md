# AWS provider

The AWS provider uses a `boto3.Session` scoped to a single region. It
supports named AWS CLI profiles via `--profile` and honours the
`AWS_ENDPOINT_URL` environment variable (for LocalStack).

## Services covered

| Service       | Check IDs                                  |
|---------------|--------------------------------------------|
| CodeBuild     | CB-001, CB-002, CB-003, CB-004, CB-005     |
| CodePipeline  | CP-001, CP-002, CP-003                     |
| CodeDeploy    | CD-001, CD-002, CD-003                     |
| ECR           | ECR-001, ECR-002, ECR-003, ECR-004         |
| IAM           | IAM-001, IAM-002, IAM-003                  |
| PBAC (CodeBuild roles/VPC) | PBAC-001, PBAC-002            |
| S3            | S3-001, S3-002, S3-003, S3-004             |

Per-check detail below is sourced from the rule metadata under
`pipeline_check/core/checks/aws/rules/*.yml`.

---

## CodeBuild

### CB-001 — Secrets in plaintext environment variables
**Severity:** CRITICAL

Checks for environment variables whose names match common secret patterns
(PASSWORD, TOKEN, API_KEY, etc.) that are stored with type PLAINTEXT.
Plaintext values are visible in the AWS console, CloudTrail logs, and
build logs to anyone with read access.

**Recommended actions**
- Move secrets to AWS Secrets Manager or SSM Parameter Store (SecureString).
- Update the CodeBuild environment variable type to `SECRETS_MANAGER` or `PARAMETER_STORE`.
- Rotate any credentials that may have been exposed in plaintext.

### CB-002 — Privileged mode enabled
**Severity:** HIGH

Checks whether the CodeBuild project runs with Docker privileged mode
enabled. Privileged mode grants the build container root-level access to
the Docker daemon on the underlying host, which is required for
Docker-in-Docker builds but significantly increases the blast radius of a
compromised build.

**Recommended actions**
- Disable privileged mode unless the project explicitly requires Docker-in-Docker builds.
- If privileged mode is required, ensure the buildspec is peer-reviewed and sourced from a protected branch.
- Consider using Kaniko or AWS CodeBuild's native Docker layer caching instead of DinD.

### CB-003 — Build logging not enabled
**Severity:** MEDIUM

Checks whether the CodeBuild project sends build output logs to CloudWatch
Logs or S3. Without logs, build activity cannot be audited, security
incidents cannot be investigated, and anomalous build behaviour goes
undetected.

**Recommended actions**
- Enable CloudWatch Logs in the project's `logsConfig.cloudWatchLogs` setting.
- Alternatively, enable S3 logging to a protected bucket with restricted write access.
- Set a log retention period appropriate for your compliance requirements.

### CB-004 — No build timeout configured
**Severity:** LOW

Checks whether the CodeBuild project has a build timeout below the AWS
maximum of 480 minutes. Projects left at the default ceiling allow runaway
or abused builds to consume resources and delay detection of a compromised
pipeline stage.

**Recommended actions**
- Set a build timeout appropriate for your expected build duration (typically 15–60 minutes).
- Use build phase reports and CloudWatch alarms to alert on builds that approach their timeout.

### CB-005 — Outdated managed build image
**Severity:** MEDIUM

Checks whether projects using the AWS-managed CodeBuild standard image
are on the latest major version. Older managed images may contain
unpatched OS packages, runtimes, or build tools that introduce
supply-chain risk into every artifact produced by the pipeline.

**Recommended actions**
- Update the environment image to the latest `aws/codebuild/standard:X.0` version.
- Pin custom or third-party images to a specific digest rather than a mutable tag.
- Subscribe to AWS CodeBuild release notifications to stay informed of new image versions.

---

## CodePipeline

### CP-001 — No approval action before deploy stages
**Severity:** HIGH

Checks whether every Deploy stage in the pipeline is preceded by at least
one Manual approval action. Without an approval gate, any code change can
reach production automatically with no human review, violating flow
control principles.

**Recommended actions**
- Add a Manual approval action to a stage that precedes every Deploy stage targeting production.
- Integrate approval notifications with your team's communication tool (e.g. Slack, email).
- Consider using AWS CodePipeline approval rules for automated quality gates in addition to manual reviews.

### CP-002 — Artifact store not encrypted with customer-managed KMS key
**Severity:** MEDIUM

Checks whether the pipeline artifact store (S3 bucket) uses a
customer-managed KMS key rather than the default AWS-managed key (SSE-S3).
Default encryption reduces auditability and control over who can decrypt
pipeline artifacts.

**Recommended actions**
- Create a customer-managed KMS key and assign it as the `encryptionKey` in each artifact store configuration.
- Apply a key policy that restricts decrypt access to only the pipeline execution role.
- Enable CloudTrail logging of KMS API calls to audit all artifact decryption events.

### CP-003 — Source stage using polling instead of event-driven trigger
**Severity:** LOW

Checks whether any Source action has `PollForSourceChanges=true`, meaning
the pipeline polls for changes rather than being triggered by an event.
Polling increases API quota consumption, introduces latency, and may miss
rapid successive changes.

**Recommended actions**
- Set `PollForSourceChanges=false` on all Source actions.
- Configure an Amazon EventBridge rule or CodeCommit trigger to start the pipeline on change.
- For GitHub sources, use a CodeStar connection with webhook-based triggering.

---

## CodeDeploy

### CD-001 — Automatic rollback on failure not enabled
**Severity:** MEDIUM

Checks whether the CodeDeploy deployment group has
`autoRollbackConfiguration` enabled with the `DEPLOYMENT_FAILURE` event.
Without automatic rollback, a failed deployment leaves the environment in
an inconsistent or partially-deployed state until a developer manually
intervenes.

**Recommended actions**
- Enable `autoRollbackConfiguration` on the deployment group with at least the `DEPLOYMENT_FAILURE` event.
- Consider also adding `DEPLOYMENT_STOP_ON_ALARM` to roll back when health metrics degrade.
- Test rollback behaviour in a non-production environment to validate the configuration.

### CD-002 — AllAtOnce deployment config — no canary or rolling strategy
**Severity:** HIGH

Checks whether the deployment group uses an AllAtOnce configuration
(`CodeDeployDefault.AllAtOnce`, `LambdaAllAtOnce`, or `ECSAllAtOnce`).
This strategy routes 100% of traffic to the new revision simultaneously,
meaning a defective build immediately impacts all users with no canary
validation window.

**Recommended actions**
- Switch to a canary deployment configuration (e.g. `CodeDeployDefault.LambdaCanary10Percent5Minutes`).
- For EC2/on-premises workloads, use a rolling or half-at-a-time deployment config.
- Pair the graduated deployment with CloudWatch alarms to trigger automatic rollback on error spikes.

### CD-003 — No CloudWatch alarm monitoring on deployment group
**Severity:** MEDIUM

Checks whether the CodeDeploy deployment group has at least one CloudWatch
alarm configured in its `alarmConfiguration`. Without alarm-based
monitoring, error rate spikes or latency regressions introduced by a
deployment will not automatically halt or roll back the release.

**Recommended actions**
- Add CloudWatch alarms covering error rate, 5xx response count, or latency p99 to the deployment group.
- Enable `alarmConfiguration.enabled` and set `ignoreAlarmMembershipErrors` to false.
- Combine with auto-rollback on `DEPLOYMENT_STOP_ON_ALARM` to create a self-healing deployment pipeline.

---

## ECR

### ECR-001 — Image scanning on push not enabled
**Severity:** HIGH

Checks whether the ECR repository has
`imageScanningConfiguration.scanOnPush` enabled. Without scan-on-push,
vulnerabilities in base images or dependencies are not detected at push
time, allowing unvetted images to propagate through the pipeline and into
production.

**Recommended actions**
- Enable `imageScanningConfiguration.scanOnPush` on the repository.
- Consider enabling Amazon Inspector continuous scanning for ongoing CVE detection against images already in the registry.
- Integrate scan results into your CI/CD pipeline and fail builds on HIGH or CRITICAL findings.

### ECR-002 — Image tags are mutable
**Severity:** HIGH

Checks whether the repository has `imageTagMutability` set to `IMMUTABLE`.
With mutable tags, any principal with `ecr:PutImage` can silently overwrite
an existing tag (e.g. `:latest` or a semver tag), allowing a malicious or
accidental image swap to affect all deployments that pull by tag without
verifying a digest.

**Recommended actions**
- Set `imageTagMutability=IMMUTABLE` on the repository.
- Reference container images by digest (`sha256:...`) in deployment manifests for the strongest immutability guarantees.
- Enforce digest-pinning in your container admission controller or policy engine.

### ECR-003 — Repository policy allows public access
**Severity:** CRITICAL

Checks whether the repository resource-based policy contains any Allow
statement with a wildcard principal (`Principal: '*'`). Such statements
expose the repository to unauthenticated or cross-account access,
potentially allowing unauthorised image pulls or pushes.

**Recommended actions**
- Remove wildcard principals from the repository policy.
- Grant pull access only to specific AWS account IDs or IAM principals that require it.
- If cross-account access is needed, use explicit account principal ARNs with the minimum necessary actions.

### ECR-004 — No lifecycle policy configured
**Severity:** LOW

Checks whether the ECR repository has a lifecycle policy defined. Without
automated image cleanup, old and potentially vulnerable images accumulate
indefinitely, increasing storage costs and the attack surface for anyone
able to pull older tagged images.

**Recommended actions**
- Add a lifecycle policy that expires untagged images after a short period (e.g. 7 days).
- Limit the number of tagged image versions retained (e.g. keep the last 10 tagged images).
- Test the lifecycle policy in a non-production repository before applying it to critical repos.

---

## IAM

### IAM-001 — CI/CD role has AdministratorAccess policy attached
**Severity:** CRITICAL

Checks whether any IAM role with a CI/CD service trust (CodeBuild,
CodePipeline, or CodeDeploy) has the AWS-managed `AdministratorAccess`
policy attached. This grants unrestricted access to all AWS services and
resources; a compromised pipeline can perform any action in the account.

**Recommended actions**
- Replace `AdministratorAccess` with least-privilege policies scoped to the specific actions the role requires.
- Use IAM Access Analyzer to identify and remove unused permissions.
- Apply Service Control Policies (SCPs) at the AWS Organizations level to further constrain CI/CD role capabilities.

### IAM-002 — CI/CD role has wildcard Action in inline policy
**Severity:** HIGH

Checks whether any inline policy on a CI/CD service role contains an
Allow statement with `Action: '*'`. Wildcard actions grant unrestricted
access to one or more AWS services, violating least-privilege and widening
the blast radius of a compromised build or deployment.

**Recommended actions**
- Replace wildcard actions with the specific IAM actions the role actually requires.
- Use CloudTrail last-access data and IAM Access Analyzer to identify the minimal required action set.
- Periodically review and tighten inline policies as pipeline requirements evolve.

### IAM-003 — CI/CD role has no permission boundary
**Severity:** MEDIUM

Checks whether CI/CD service roles have a permissions boundary attached.
Without a boundary, the role's effective permissions are limited only by
its attached policies, and there is no guardrail preventing privilege
escalation if a policy is accidentally over-permissioned or modified by an
attacker.

**Recommended actions**
- Attach a permissions boundary to each CI/CD service role defining the maximum permissions it can ever be granted.
- Create a managed boundary policy that excludes sensitive actions (e.g. `iam:CreateRole`, `iam:AttachRolePolicy` without conditions).
- Enforce boundary attachment through an SCP or IAM condition on role creation.

---

## PBAC (Pipeline-Based Access Control)

PBAC checks target the boundary between the pipeline itself and the
resources it can reach — network reachability and service-role sharing
across projects.

### PBAC-001 — CodeBuild project has no VPC configuration
**Severity:** HIGH

Checks whether a CodeBuild project runs with an attached `vpcConfig`
block. Without VPC isolation the build container executes on a shared
AWS-managed network with unrestricted egress, so a compromised build can
exfiltrate secrets or artifacts to any destination on the public internet.

**Recommended actions**
- Attach `vpcConfig` pointing the project at a private subnet with an egress-controlled security group.
- Route required traffic through VPC endpoints (S3, ECR, Secrets Manager, CloudWatch Logs) instead of public internet.
- Deny `0.0.0.0/0` egress on the build security group unless strictly required.

### PBAC-002 — CodeBuild service role shared across projects
**Severity:** MEDIUM

Checks whether multiple CodeBuild projects reuse the same `serviceRole`.
A shared role means any single project's compromise grants the attacker
the combined permissions of every project that uses the role — the exact
cross-pipeline escalation path PBAC is meant to prevent.

**Recommended actions**
- Give each CodeBuild project its own dedicated service role scoped to only the secrets, buckets, and ECR repos that project needs.
- If role duplication is unavoidable, group only projects with identical trust boundaries.
- Detect new shared-role situations with an AWS Config rule or a recurring scan via this tool.

---

## S3

### S3-001 — Artifact bucket public access block not fully enabled
**Severity:** CRITICAL

Checks whether all four S3 Block Public Access settings are enabled on
CodePipeline artifact buckets: `BlockPublicAcls`, `IgnorePublicAcls`,
`BlockPublicPolicy`, and `RestrictPublicBuckets`. Missing settings could
expose pipeline artifacts if a bucket ACL or policy is accidentally
permissive.

**Recommended actions**
- Enable all four Block Public Access settings on every artifact bucket.
- Apply the same settings at the AWS account level as a catch-all default.
- Use AWS Config rule `s3-bucket-public-read-prohibited` to continuously audit public access.

### S3-002 — Artifact bucket server-side encryption not configured
**Severity:** HIGH

Checks whether the CodePipeline artifact bucket has a default server-side
encryption rule configured. Without encryption at rest, pipeline artifacts
(source zips, compiled binaries, deployment packages) are stored
unencrypted, increasing exposure if S3 access controls are misconfigured.

**Recommended actions**
- Enable default bucket encryption using at minimum AES256 (SSE-S3).
- For stronger key control, use SSE-KMS with a customer-managed key.
- Enforce encryption-in-transit by adding a bucket policy that denies requests without `aws:SecureTransport`.

### S3-003 — Artifact bucket versioning not enabled
**Severity:** MEDIUM

Checks whether versioning is enabled on the CodePipeline artifact bucket.
Without versioning, overwritten or deleted artifacts cannot be recovered,
making it impossible to roll back to a known-good build artifact after an
incident or accidental overwrite.

**Recommended actions**
- Enable S3 versioning on every artifact bucket.
- Pair versioning with a lifecycle rule that expires non-current versions after your retention period.
- Consider enabling MFA Delete for additional protection against accidental or malicious deletion.

### S3-004 — Artifact bucket access logging not enabled
**Severity:** LOW

Checks whether S3 server access logging is enabled on CodePipeline
artifact buckets. Without access logs it is not possible to audit who
accessed, downloaded, or tampered with pipeline artifacts during an
investigation.

**Recommended actions**
- Enable S3 server access logging and direct logs to a separate, centralised logging bucket.
- Restrict write access to the logging bucket so log entries cannot be tampered with.
- Use Amazon Athena or CloudWatch Logs Insights to query access logs for anomalous patterns.

---

## Adding a new AWS check

1. Create `pipeline_check/core/checks/aws/<service>.py` subclassing
   `AWSBaseCheck`. Each public check method should return one or more
   `Finding` objects.
2. Import it and append to `check_classes` in
   `pipeline_check/core/providers/aws.py`.
3. Add rule metadata to
   `pipeline_check/core/checks/aws/rules/<service>.yml` so the HTML
   report and this documentation can render consistent descriptions and
   recommended actions.
4. Add unit tests in `tests/aws/test_<service>.py`.
5. Add mappings for the new check IDs in the relevant standard file(s) under
   `pipeline_check/core/standards/data/`.
6. Extend the corresponding service section in this document with the new
   check entry (title, severity, description, recommended actions).
