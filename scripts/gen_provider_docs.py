"""Generate provider reference documentation from the rule registry.

Before this existed, ``docs/providers/<provider>.md`` was a
hand-maintained markdown file that duplicated rule metadata
(check IDs, titles, severities, recommendations) already declared
in Python. The parallel state rotted: a new check meant edits in
three places (the check class, the standards mapping, and the doc)
and any of them could drift.

With the per-rule-module refactor (see
``pipeline_check/core/checks/<provider>/rules/``), every rule
exports a ``RULE`` object carrying its metadata plus prose fields
(``recommendation``, ``docs_note``). This script walks that
registry and writes a fully-derived provider doc, the code is
the source of truth and the doc can never drift.

Usage
-----
    python scripts/gen_provider_docs.py             # write every supported provider
    python scripts/gen_provider_docs.py github      # write just one provider
    python scripts/gen_provider_docs.py --check     # exit 1 if any doc is stale
    python scripts/gen_provider_docs.py --check aws # check just one

The supported provider list is enumerated by ``SUPPORTED_PROVIDERS``
below; pass ``--help`` to a fresh checkout to see the current set.
"""
from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from pathlib import Path

# Make ``pipeline_check`` importable when the script is run directly.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from pipeline_check.core.autofix import _FIXERS
from pipeline_check.core.checks.rule import Rule, discover_rules

#: Set of check_ids that have a registered autofix patch. Read once
#: at module import; the rule-section renderer flips a "🔧 autofix"
#: badge on for rules in this set so users skimming a provider page
#: can see at a glance which findings ``pipeline_check --fix`` will
#: patch automatically vs which need manual remediation.
_AUTOFIXABLE: frozenset[str] = frozenset(_FIXERS.keys())

# ``provider_slug -> (display_title, rules_package_fqn, docs_output_path,
#                     per-provider header markdown)``
SUPPORTED_PROVIDERS: dict[str, tuple[str, str, Path, str]] = {
    "aws": (
        "AWS",
        "pipeline_check.core.checks.aws.rules",
        _REPO_ROOT / "docs" / "providers" / "aws.md",
        """\
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
""",
    ),
    "github": (
        "GitHub Actions",
        "pipeline_check.core.checks.github.rules",
        _REPO_ROOT / "docs" / "providers" / "github.md",
        """\
# GitHub Actions provider

Parses workflow YAML files under a `.github/workflows` directory. No
GitHub API token or installed Actions runner is required by default;
the scanner stays read-from-disk-only unless `--resolve-remote` opts
in to fetching reusable-workflow callees over HTTPS.

## Producer workflow

```bash
# --gha-path is auto-detected when .github/workflows exists at cwd;
# the CLI announces the pick on stderr.
pipeline_check --pipeline github

# …or pass it explicitly.
pipeline_check --pipeline github --gha-path .github/workflows
```

A single workflow file can also be passed directly:

```bash
pipeline_check --pipeline github --gha-path .github/workflows/release.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the AWS and Terraform providers.

## Reusable workflow resolution

`jobs.<id>.uses: owner/repo/.github/workflows/x.yml@<sha>` references
a workflow body that runs with the *caller's* `GITHUB_TOKEN` and
secrets. By default the scanner stops at the call site (it flags the
ref via `GHA-025` when unpinned and emits a one-line nudge listing
how many remote refs were skipped); `--resolve-remote` opts in to
fetching the called body and running the full GHA rule pack against
it with the caller's permissions context.

```bash
# Fetch via raw.githubusercontent.com (works for public repos).
pipeline_check --pipeline github --resolve-remote

# Private callees: pass a token, or set $GITHUB_TOKEN.
pipeline_check --pipeline github --resolve-remote --gh-token "$GH_PAT"

# Fully offline: search a sibling on-disk checkout instead.
pipeline_check --pipeline github --resolve-remote \\
    --gha-search-path ../shared-workflows
```

Resolution rules:

- **Only SHA-pinned refs are fetched.** A tag-pinned ref (`@v1`,
  `@main`) is skipped with a warning, resolution against a movable
  upstream tag would defeat `GHA-025`'s value.
- **Recursion** follows transitive `uses:` calls to a depth of 3
  (configurable with `--gha-resolve-depth`; hard ceiling 10). Cycles
  are detected.
- **Cache.** Fetched bodies live under
  `~/.cache/pipeline-check/gha-resolver/` for 7 days. Use `--no-cache`
  to bypass.
- **Failure mode.** Network errors, 404s, and malformed YAML never
  abort the scan. They land in the context's warnings stream.
- **Attribution.** Findings on a resolved callee carry a synthetic
  `<caller-path> -> <owner>/<repo>/<path>@<ref>` resource string so
  the report points at both the call site and the upstream body.
- **Permissions inheritance.** A callee without its own
  `permissions:` runs with the caller's; `GHA-004` doesn't fire on a
  callee whose caller declared one.
- **`secrets: inherit`.** When the call site passes
  `secrets: inherit`, `GHA-019` annotates findings with the inherit
  note so report readers see the full credential surface.
""",
    ),
    "gitlab": (
        "GitLab CI",
        "pipeline_check.core.checks.gitlab.rules",
        _REPO_ROOT / "docs" / "providers" / "gitlab.md",
        """\
# GitLab CI provider

Parses `.gitlab-ci.yml` on disk, no GitLab API token, no runner install.
Works against the file in a detached clone or a merged-result pipeline
export.

## Producer workflow

```bash
# --gitlab-path auto-detected when .gitlab-ci.yml exists at cwd.
pipeline_check --pipeline gitlab

# …or pass it explicitly (file or directory).
pipeline_check --pipeline gitlab --gitlab-path ci/
```
""",
    ),
    "bitbucket": (
        "Bitbucket Pipelines",
        "pipeline_check.core.checks.bitbucket.rules",
        _REPO_ROOT / "docs" / "providers" / "bitbucket.md",
        """\
# Bitbucket Pipelines provider

Parses `bitbucket-pipelines.yml` on disk, no Bitbucket API token, no
runner install.

## Producer workflow

```bash
# --bitbucket-path auto-detected when bitbucket-pipelines.yml exists at cwd.
pipeline_check --pipeline bitbucket

# …or pass it explicitly (file or directory).
pipeline_check --pipeline bitbucket --bitbucket-path ci/
```
""",
    ),
    "azure": (
        "Azure DevOps Pipelines",
        "pipeline_check.core.checks.azure.rules",
        _REPO_ROOT / "docs" / "providers" / "azure.md",
        """\
# Azure DevOps Pipelines provider

Parses an `azure-pipelines.yml` from disk, no network calls, no ADO
personal access token.

## Producer workflow

```bash
# --azure-path is auto-detected when azure-pipelines.yml is present at cwd;
# the CLI announces the pick on stderr.
pipeline_check --pipeline azure

# …or pass it explicitly.
pipeline_check --pipeline azure --azure-path azure-pipelines.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Shape coverage

The walker handles every layout ADO supports:

- Flat single-job pipeline, top-level `steps:`
- Single-stage multi-job, top-level `jobs:`
- Multi-stage, `stages: → jobs: → steps:`
- Deployment jobs, steps under
  `strategy.{runOnce|rolling|canary}.{preDeploy|deploy|routeTraffic|postRouteTraffic}.steps`
  and `strategy.*.on.{success|failure}.steps`.
""",
    ),
    "jenkins": (
        "Jenkins",
        "pipeline_check.core.checks.jenkins.rules",
        _REPO_ROOT / "docs" / "providers" / "jenkins.md",
        """\
# Jenkins provider

Parses Jenkinsfile text. Declarative or Scripted Pipeline, without
talking to a Jenkins controller. No Groovy interpreter, no plugin
install, no API token.

## Producer workflow

```bash
# --jenkinsfile-path is auto-detected when ./Jenkinsfile exists at cwd.
pipeline_check --pipeline jenkins

# …or pass it explicitly.
pipeline_check --pipeline jenkins --jenkinsfile-path Jenkinsfile

# Scan a directory of multiple Jenkinsfiles (e.g. monorepo with per-app pipelines).
pipeline_check --pipeline jenkins --jenkinsfile-path ci/
```

The loader recognizes files named `Jenkinsfile` exactly, plus anything
ending in `.jenkinsfile` or `.groovy`. It treats every file as text,
no Groovy parsing, and applies the same regex-driven heuristics the
other workflow providers use for `run:` blocks. False positives are
intentional: better to flag and let the operator suppress than to
miss a real injection because the parser couldn't follow a dynamic
expression.
""",
    ),
    "circleci": (
        "CircleCI",
        "pipeline_check.core.checks.circleci.rules",
        _REPO_ROOT / "docs" / "providers" / "circleci.md",
        """\
# CircleCI provider

Parses `.circleci/config.yml` on disk, no CircleCI API token, no
runner install.

## Producer workflow

```bash
# --circleci-path is auto-detected when .circleci/config.yml exists at cwd.
pipeline_check --pipeline circleci

# …or pass it explicitly.
pipeline_check --pipeline circleci --circleci-path .circleci/config.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### CircleCI-specific checks

Several checks target CircleCI concepts that have no direct analogue
in other providers:

- **CC-001**, orb version pinning (`@volatile`, `@1` → `@5.1.0`)
- **CC-009**, approval gate via `type: approval` predecessor job
- **CC-012**, dynamic config generation via `setup: true`
- **CC-019**, `add_ssh_keys` fingerprint restriction
""",
    ),
    "cloudbuild": (
        "Google Cloud Build",
        "pipeline_check.core.checks.cloudbuild.rules",
        _REPO_ROOT / "docs" / "providers" / "cloudbuild.md",
        """\
# Google Cloud Build provider

Parses `cloudbuild.yaml` on disk, no Google Cloud credentials, no
`gcloud` install, no Cloud Build API token required. Each document
must declare a top-level `steps:` list; files without it (SAM
templates, ordinary YAML configs) are skipped by the loader.

## Producer workflow

```bash
# --cloudbuild-path is auto-detected when cloudbuild.yaml/cloudbuild.yml
# exists at cwd.
pipeline_check --pipeline cloudbuild

# …or pass it explicitly.
pipeline_check --pipeline cloudbuild --cloudbuild-path ci/cloudbuild.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Cloud Build-specific checks

Several checks target Cloud Build concepts that have no direct
analogue in other providers:

- **GCB-002**, `serviceAccount:` must be set; the default Cloud Build
  SA is typically broader than any single pipeline needs.
- **GCB-003**, secrets must flow through `availableSecrets.secret
  Manager[].env` + `secretEnv:`, never via inline `gcloud secrets
  versions access` in `args`.
- **GCB-004**, `options.dynamicSubstitutions: true` combined with a
  user-substitution (`$_FOO`) in step args opens a trigger-editor-
  controlled shell-injection path.
""",
    ),
    "kubernetes": (
        "Kubernetes",
        "pipeline_check.core.checks.kubernetes.rules",
        _REPO_ROOT / "docs" / "providers" / "kubernetes.md",
        """\
# Kubernetes manifest provider

Parses Kubernetes API documents (`apiVersion:` + `kind:`) from `.yaml`
/ `.yml` files on disk, text-only static analysis. No `kubectl`, no
cluster access, no Helm or Kustomize rendering. Multi-document YAML
(`---`-separated) is fully supported; each document is parsed into
its own `Manifest` record.

Helm chart values, kustomization base files, and other YAML that
doesn't carry the canonical `apiVersion` + `kind` shape are silently
skipped, so a directory mixing manifests with `Chart.yaml` /
`values.yaml` / `kustomization.yaml` won't trip the loader.

## Producer workflow

```bash
# --k8s-path is auto-detected when ./kubernetes/, ./k8s/, or
# ./manifests/ exist at cwd.
pipeline_check --pipeline kubernetes

# …or pass it explicitly (file or directory).
pipeline_check --pipeline kubernetes --k8s-path k8s/

# A single multi-document manifest works too.
pipeline_check --pipeline kubernetes --k8s-path deploy.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Workload coverage

The walker recognizes every kind that carries a pod spec:

- `Pod`, pod spec at `spec`
- `Deployment` / `StatefulSet` / `DaemonSet` / `ReplicaSet` / `Job`
 , pod spec at `spec.template.spec`
- `CronJob`, pod spec at `spec.jobTemplate.spec.template.spec`

Container-level rules walk all three container lists (`containers`,
`initContainers`, `ephemeralContainers`), so init-time and ephemeral
debug containers are covered along with the long-lived workload.

### RBAC and Service rules

Four rules target non-workload kinds:

- **K8S-018**, `Kind: Secret` carrying credential-shaped literals
  in `stringData` or `data`. Base64 values in `data:` are decoded
  and re-checked for AKIA-shaped AWS keys.
- **K8S-020**, `ClusterRoleBinding` to `cluster-admin`, `admin`,
  or `system:masters`.
- **K8S-021**, `Role` / `ClusterRole` granting wildcard verbs+
  resources (both `verbs: ["*"]` and `resources: ["*"]`).
- **K8S-022**, `Service` exposing port 22 (SSH).
""",
    ),
    "buildkite": (
        "Buildkite",
        "pipeline_check.core.checks.buildkite.rules",
        _REPO_ROOT / "docs" / "providers" / "buildkite.md",
        """\
# Buildkite provider

Parses `.buildkite/pipeline.yml` (or any user-named pipeline file) on
disk, no Buildkite API token, no agent install required. Each
document must declare a top-level `steps:` list; files without it are
skipped by the loader.

## Producer workflow

```bash
# --buildkite-path is auto-detected when .buildkite/pipeline.yml
# exists at cwd.
pipeline_check --pipeline buildkite

# …or pass it explicitly.
pipeline_check --pipeline buildkite --buildkite-path .buildkite/pipeline.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Buildkite-specific checks

- **BK-001**, plugin refs must be pinned to an exact tag
  (`docker-compose#v4.13.0`) or a 40-char SHA. Branch refs (`#main`)
  and bare names float and let a compromised plugin release execute
  in the pipeline.
- **BK-007**, every step that looks like a deploy (label / command
  matches `deploy`, `kubectl apply`, `terraform apply`, `helm
  upgrade`, …) must be preceded by a `block:` or `input:` step in
  the same pipeline file. Buildkite waits for a human to click
  *Unblock* before the gated steps run.
""",
    ),
    "tekton": (
        "Tekton",
        "pipeline_check.core.checks.tekton.rules",
        _REPO_ROOT / "docs" / "providers" / "tekton.md",
        """\
# Tekton provider

Parses Tekton API documents (`apiVersion: tekton.dev/*`) from `.yaml`
/ `.yml` files on disk, text-only static analysis, no `tkn` binary,
no cluster access. Recognized kinds: `Task`, `ClusterTask`,
`Pipeline`, `TaskRun`, `PipelineRun`. Documents that don't carry a
`tekton.dev/*` apiVersion are silently skipped, so a directory mixing
Tekton with plain Kubernetes manifests is safe to point at.

## Producer workflow

```bash
pipeline_check --pipeline tekton --tekton-path tekton/

# A single multi-document file works too.
pipeline_check --pipeline tekton --tekton-path tekton/build-task.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Tekton-specific checks

- **TKN-003**. Tekton substitutes `$(params.X)` *before* the shell
  parses the script, so any unquoted use is a command-injection
  primitive. The safe pattern is to receive the parameter through
  `env:` and reference the env var quoted (`"$NAME"`).
- **TKN-007**, `TaskRun` / `PipelineRun` must set
  `serviceAccountName` to a least-privilege ServiceAccount. The
  default SA inherits whatever cluster-admin or wildcard role
  someone later binds to it.
""",
    ),
    "argo": (
        "Argo Workflows",
        "pipeline_check.core.checks.argo.rules",
        _REPO_ROOT / "docs" / "providers" / "argo.md",
        """\
# Argo Workflows provider

Parses Argo API documents (`apiVersion: argoproj.io/*`) from `.yaml`
/ `.yml` files on disk, text-only static analysis, no `argo` binary,
no cluster access. Recognized kinds: `Workflow`, `WorkflowTemplate`,
`ClusterWorkflowTemplate`, `CronWorkflow`. Documents that don't
carry an `argoproj.io/*` apiVersion are silently skipped.

## Producer workflow

```bash
pipeline_check --pipeline argo --argo-path workflows/

# A single workflow file works too.
pipeline_check --pipeline argo --argo-path workflows/release.yaml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Argo-specific checks

- **ARGO-005**, `{{inputs.parameters.X}}` substitution happens
  before the shell parses the script, so any unquoted use in
  `script.source` / `container.args` is a command-injection
  primitive. Pass the parameter via `env:` and reference quoted.
- **ARGO-003**, `Workflow` / `CronWorkflow` must set
  `serviceAccountName`. Workflows that fall back to the namespace's
  `default` SA inherit whatever role someone later binds to
  `default`.
""",
    ),
    "argocd": (
        "Argo CD",
        "pipeline_check.core.checks.argocd.rules",
        _REPO_ROOT / "docs" / "providers" / "argocd.md",
        """\
# Argo CD provider

Parses Argo CD documents from `.yaml` / `.yml` files on disk, text-
only static analysis, no `argocd` binary, no cluster access.
Recognized kinds: `Application`, `ApplicationSet`, `AppProject`
(all under `apiVersion: argoproj.io/v1alpha1`), plus the core `v1
ConfigMap` documents named `argocd-cm` or `argocd-rbac-cm` where
Argo CD's instance-wide config lives. Other documents (including
Argo Workflows CRDs, which belong to the `argo` provider) are
silently skipped.

## Producer workflow

```bash
pipeline_check --pipeline argocd --argocd-path applications/

# A single Application file works too.
pipeline_check --pipeline argocd --argocd-path applications/payments.yaml

# Argo CD + Argo Workflows together; each provider's kind filter
# is disjoint so pointing both at the same dir produces disjoint
# findings, not duplicates.
pipeline_check --pipelines argo,argocd --argo-path ci/ --argocd-path ci/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Argo CD-specific checks

- **ARGOCD-004** walks `data.policy.csv` (and any `data.policy.<role>.csv`)
  on the `argocd-rbac-cm` ConfigMap line by line, ignoring comments
  and explicit denies. The unintuitive bit: `argocd-rbac-cm` is a
  plain `kind: ConfigMap`, not an `argoproj.io` CRD, so this rule
  fires off Kubernetes ConfigMap docs that have to be passed in
  alongside the Application manifests.
- **ARGOCD-007** flags Helm `valueFiles` / `parameters` that
  interpolate generator placeholders (`{{branch}}`, `{{repo}}`)
  without the ApplicationSet setting `spec.goTemplate: true`. Argo
  CD's default fasttemplate substitution is a literal string-splice
  and a generator-controlled value containing YAML structural
  characters lands verbatim in the rendered values.
""",
    ),
    "drone": (
        "Drone CI",
        "pipeline_check.core.checks.drone.rules",
        _REPO_ROOT / "docs" / "providers" / "drone.md",
        """\
# Drone CI provider

Parses ``.drone.yml`` / ``.drone.yaml`` documents on disk. Drone
pipelines are multi-document YAML; each document is a top-level
pipeline gated by a ``kind: pipeline`` discriminator and a ``type:``
(``docker``, ``kubernetes``, ``ssh``, ``exec``, ``digitalocean``).
The rule pack focuses on the container-flavored types
(``docker`` / ``kubernetes``); ``ssh`` / ``exec`` / ``digitalocean``
pipelines have no container surface and most rules pass-by-default
on them.

## Producer workflow

```bash
# --drone-path is auto-detected when .drone.yml or .drone.yaml exists at cwd.
pipeline_check --pipeline drone

# ...or pass it explicitly.
pipeline_check --pipeline drone --drone-path .drone.yml

# A directory of services with one .drone.yml each.
pipeline_check --pipeline drone --drone-path services/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, ...) behave the same as with the other providers.

### Drone-specific checks

- **DR-002**, ``privileged: true`` is a step-scoped switch that
  removes the container's syscall and capability boundary,
  giving the step kernel-level access to the agent host. Most
  workloads reaching for it can use a rootless alternative
  (``buildx``, ``kaniko``, ``buildah``); when DR-002 fires,
  treat it as a build-system review item rather than a quick
  fix.
- **DR-003**, Drone substitutes ``${DRONE_*}`` template
  variables *before* the shell parses the script. Author-
  controllable variables (``DRONE_COMMIT_MESSAGE``,
  ``DRONE_PULL_REQUEST_TITLE``, branch / repo names in fork
  PRs, tag annotations) are tainted; an unquoted use is a
  command-injection primitive. Same model as TKN-003 / ARGO-005
  / BK-003 in this catalog.
- **DR-005**, plugin steps (steps with a ``settings:`` block)
  are a sharper attack surface than ordinary steps because
  Drone passes every ``settings:`` key to the plugin as an env
  var, including any secret references. The rule fires
  specifically on plugin steps using a floating image tag, so
  a maintainer can ratchet plugin pinning up first.
""",
    ),
    "oci": (
        "OCI image manifest",
        "pipeline_check.core.checks.oci.rules",
        _REPO_ROOT / "docs" / "providers" / "oci.md",
        """\
# OCI image manifest provider

Parses OCI image manifests / image-indexes from disk, pure JSON, no
registry pull, no image build, no daemon access. The user captures
the manifest with ``docker buildx imagetools inspect --raw <ref>``
(or the equivalent ``oras manifest fetch`` / ``crane manifest``)
and points the scanner at the resulting JSON. Recognized media
types: the OCI 1.0 / 1.1 spec types
(``application/vnd.oci.image.{index,manifest}.v1+json``) and the
Docker-distribution-v2 equivalents BuildKit still emits by default.

## Producer workflow

```bash
# Capture the index from a registry into a JSON file.
docker buildx imagetools inspect --raw \\
    ghcr.io/example/app:1.0.0 > image.json

# Run the scanner.
pipeline_check --pipeline oci --oci-manifest image.json

# Or point at a directory; ./index.json is auto-detected.
pipeline_check --pipeline oci --oci-manifest ./oci-layout/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### What the rules expect

OCI rules operate on the manifest *shape* alone, the scanner never
fetches the config blob or layer contents. That keeps the provider
read-from-disk-only and avoids taking on a registry-credential
surface, but it also bounds what's detectable: anything that
requires the config (entrypoint, labels written via
``--label`` rather than ``--annotation``, layer history) is out
of scope. Use the Dockerfile provider in tandem to catch
authoring-time gaps that don't survive into the manifest.

### OCI-specific checks

- **OCI-001**, image manifest must carry
  ``org.opencontainers.image.source`` and
  ``org.opencontainers.image.revision`` annotations. Mirrors
  DF-016 (Dockerfile-time) at the image-manifest layer so a build
  that overrides annotations via ``docker buildx --annotation``
  is still scored.
- **OCI-002**, image index must include at least one attestation
  manifest (BuildKit-style sub-manifest annotated with
  ``vnd.docker.reference.type: attestation-manifest``). This is
  where ``--attest=type=provenance`` and ``--attest=type=sbom``
  land their data; without one, neither SLSA provenance nor an
  SBOM is reachable from the image.
- **OCI-003**, image manifest must carry
  ``org.opencontainers.image.created``. CVE triage uses this to
  determine the image's build date without pulling the config
  blob.
""",
    ),
    "scm": (
        "SCM (GitHub / GitLab / Bitbucket) posture",
        "pipeline_check.core.checks.scm.rules",
        _REPO_ROOT / "docs" / "providers" / "scm.md",
        """\
# SCM (source control management) posture provider

Scans repository governance via the platform's REST API: branch
protection, required reviews, code scanning, secret scanning,
Dependabot, signed commits, and the rest of the controls that
live at the repo / org settings layer rather than in workflow YAML.
Maps each rule to the OpenSSF Scorecard check it evidences and to
the CIS Software Supply Chain Security Guide section it satisfies.

Three platforms today: **GitHub** (full 42-rule pack), **GitLab**
and **Bitbucket Cloud** (universal subset of seven rules:
``SCM-001``, ``SCM-002``, ``SCM-006``, ``SCM-007``, ``SCM-008``,
``SCM-009``, ``SCM-017``). GitHub-only rules pass on the other
platforms with a "not applicable on PLATFORM" note in the
description so the operator sees the deliberate skip rather than
a silent absence.

Closes the gap between this scanner and Legitify / OpenSSF
Scorecard, neither of which scan pipeline-config files. Together
with the GitHub Actions provider, the posture coverage spans both
the repo settings and the workflows the repo runs.

## Producer workflow

```bash
# GitHub. Token comes from --gh-token or $GITHUB_TOKEN. Without
# admin scope on the repo, security_and_analysis features
# (SCM-004 / SCM-005 / SCM-015 / SCM-016) cannot distinguish
# "really disabled" from "I lacked visibility" — re-run with
# admin scope to confirm those rules' verdicts.
pipeline_check --pipeline scm --scm-platform github \\
    --scm-repo octocat/hello-world

# GitLab. Token comes from --gh-token (the flag is shared across
# platforms) or $GITLAB_TOKEN; needs the ``read_api`` scope. Repo
# spec is the full project path (nested subgroups allowed).
pipeline_check --pipeline scm --scm-platform gitlab \\
    --scm-repo group/subgroup/project

# Bitbucket Cloud. Token is ``user:app_password`` or the existing
# ``Basic <b64>`` Authorization value; falls back to
# $BITBUCKET_TOKEN. Repo spec is ``workspace/repo_slug``.
pipeline_check --pipeline scm --scm-platform bitbucket \\
    --scm-repo acme/widget

# Offline / CI mode: read JSON responses from disk instead of
# hitting the network. Each endpoint maps to
# <endpoint-with-slashes-as-underscores>.json under DIR. Works on
# every platform.
pipeline_check --pipeline scm --scm-platform github \\
    --scm-repo octocat/hello-world \\
    --scm-fixture-dir ./scm-fixtures/
```

### Per-platform rule coverage

| Rule | GitHub | GitLab | Bitbucket | Notes |
|------|--------|--------|-----------|-------|
| SCM-001 (branch protection presence) | yes | yes | yes | Universal |
| SCM-002 (required reviews) | yes | yes | yes | GitLab: ``approvals_before_merge``; Bitbucket: ``require_approvals_to_merge`` |
| SCM-003 (default code scanning) | yes | skip | skip | GitHub-only |
| SCM-004 (secret scanning) | yes | skip | skip | GitHub-only |
| SCM-005 (Dependabot updates) | yes | skip | skip | GitHub-only |
| SCM-006 (signed commits required) | yes | yes | yes | GitLab: ``push_rules.reject_unsigned_commits``; Bitbucket: no enforcement, always fires |
| SCM-007 (force push allowed) | yes | yes | yes | Universal |
| SCM-008 (required status checks) | yes | yes | yes | GitLab: pipeline-must-succeed; Bitbucket: ``require_passing_builds_to_merge`` |
| SCM-009 (branch deletion allowed) | yes | yes | yes | GitLab protected branches block deletion implicitly; Bitbucket ``delete`` restriction |
| SCM-010..SCM-016 | yes | skip | skip | GitHub-only protection knobs / security features |
| SCM-017 (CODEOWNERS file present) | yes | yes | yes | GitLab also probes ``.gitlab/CODEOWNERS``; Bitbucket probes ``.bitbucket/CODEOWNERS`` |
| SCM-018, SCM-019 | yes | skip | skip | GitHub-only protection-payload shape |

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Token permissions per scan

Token requirements split into three tiers per platform: **none /
public** runs the universal rule subset against public repos only
and gets rate-limited; **read** gets the full branch-protection
and CODEOWNERS coverage; **admin** unlocks the
``security_and_analysis`` block, Actions / environments / deploy
keys / webhooks / outside collaborators / rulesets endpoints. Rules
whose endpoint comes back 401 / 403 / 404 pass silently with a
"data unavailable" note, so a lower-privilege token degrades
gracefully (it does not crash the scan), but the rules listed
under ``admin`` below report no signal.

#### GitHub

Pass the token via ``--gh-token`` or ``$GITHUB_TOKEN``. Classic PAT
scopes and fine-grained PAT permissions are listed side-by-side; on
GitHub Enterprise Cloud the fine-grained permissions also map to
the same names on a GitHub App installation token.

| Tier | Classic PAT scope | Fine-grained PAT / GitHub App | Rules unlocked |
|------|-------------------|-------------------------------|----------------|
| public (no token) | — | — | SCM-001, -002, -006, -007, -008, -009, -017 on public repos; rate-limited to 60 req/hr |
| read (public + private) | ``repo`` (or ``public_repo`` for public-only) | ``Metadata: read`` + ``Contents: read`` | adds private-repo coverage for the universal rules; raises rate limit to 5000 req/hr |
| admin | ``repo`` + ``admin:repo_hook`` + ``read:org`` | ``Administration: read`` + ``Webhooks: read`` + ``Members: read`` + ``Environments: read`` + ``Code scanning alerts: read`` | adds SCM-003, -004, -005, -010..016, -018, -019, -020, -021, -022, -023, -024, -025, -026, -027, -028, -029..047 |

Per-rule scope notes (admin-tier rules only; the universal rules
work at read tier):

  * **SCM-003 / SCM-004 / SCM-005 / SCM-015 / SCM-016** read
    ``security_and_analysis.<feature>.status`` from the repo
    metadata payload. GitHub omits the entire
    ``security_and_analysis`` block unless the token has admin
    scope on the repo, so without it the rules cannot tell
    ``disabled`` from ``unknown`` and pass with an unavailability
    note.
  * **SCM-010 / SCM-011 / SCM-012 / SCM-013 / SCM-014 / SCM-018 /
    SCM-019** read GitHub-only protection-payload knobs
    (``enforce_admins``, ``require_code_owner_reviews``,
    ``dismiss_stale_reviews``, ``required_conversation_resolution``,
    ``require_last_push_approval``,
    ``bypass_pull_request_allowances``, ``restrictions``). The
    branch-protection endpoint returns these only when the token
    has at least ``Administration: read`` (fine-grained) / ``repo``
    scope (classic).
  * **SCM-020 / SCM-021 / SCM-022** hit
    ``/actions/permissions`` and ``/actions/permissions/workflow``.
    Both require ``Administration: read``.
  * **SCM-023 / SCM-024** walk ``/environments``. Requires
    ``Environments: read``.
  * **SCM-025** reads ``/keys`` (deploy keys). Requires
    ``Administration: read``.
  * **SCM-026** reads ``/hooks`` (webhooks). Requires
    ``Webhooks: read``.
  * **SCM-027** reads ``/collaborators?affiliation=outside``.
    Requires ``Members: read`` on the org; ``Administration: read``
    on the repo is the per-repo equivalent.
  * **SCM-028** reads ``private`` and ``allow_forking`` from the
    repo metadata. Available at read tier (no admin needed).
  * **SCM-029, SCM-030, SCM-032..SCM-042** walk ``/rulesets`` and
    the per-ruleset detail endpoint. Both require
    ``Administration: read``.
  * **SCM-043 / SCM-044** read tag-targeted rulesets / branch
    protection ``required_signatures`` + ``enforce_admins``.
    Requires ``Administration: read``.
  * **SCM-045 / SCM-046 / SCM-047** read the code-scanning
    default-setup endpoint and the languages endpoint. Requires
    ``Code scanning alerts: read``; the languages endpoint is
    available at read tier.

GitHub Apps: the same fine-grained permission names apply to App
installation tokens. The App needs to be installed on the target
repo (or org); installation-only access is enough for repo-scoped
endpoints. ``Members: read`` is org-level; install the App on the
org to enumerate outside collaborators.

#### GitLab

Pass the token via ``--gh-token`` (the flag is shared across
platforms) or ``$GITLAB_TOKEN``.

| Tier | GitLab token scope | Rules unlocked |
|------|--------------------|----------------|
| public (no token) | — | SCM-001, -002, -006, -007, -008, -009, -017 on public projects only |
| read | ``read_api`` | full universal-rule coverage on private projects (and the rate-limit raise) |
| maintainer-equivalent | ``read_api`` issued by a project Maintainer (or higher) | adds SCM-006's ``push_rules.reject_unsigned_commits`` signal (the push-rules endpoint is gated on Maintainer access to the project) |

Notes:

  * SCM-001 / -007 / -009 read
    ``/projects/:id/protected_branches``. Available to any project
    member with ``read_api``.
  * SCM-002 reads ``approvals_before_merge`` from
    ``/projects/:id``. Available at read tier.
  * SCM-006 reads ``push_rules.reject_unsigned_commits`` from
    ``/projects/:id/push_rule``. The push-rules endpoint is a
    GitLab Premium feature and additionally requires Maintainer
    access to the project to read; lower-privilege tokens get a
    silent pass because the rule treats endpoint absence the same
    as "feature disabled".
  * SCM-008 reads
    ``only_allow_merge_if_pipeline_succeeds`` from
    ``/projects/:id``. Available at read tier.
  * SCM-017 probes ``/projects/:id/repository/files/<path>`` for
    the three CODEOWNERS locations. Available at read tier.

Self-hosted GitLab: ``--scm-platform gitlab`` accepts a custom
host via the fetcher's ``host=`` constructor argument. Self-hosted
tokens use the same scope name.

#### Bitbucket Cloud

Pass the credential as ``user:app_password`` via ``--gh-token`` (or
``$BITBUCKET_TOKEN``). Bitbucket Server is a different surface and
not currently in scope.

| Tier | App-password permissions | Rules unlocked |
|------|--------------------------|----------------|
| public (no credential) | — | SCM-001, -002, -007, -008, -009, -017 on public repos only |
| read | ``repositories:read`` | full universal-rule coverage on private repos |

Notes:

  * SCM-001 / -007 / -009 read
    ``/repositories/{workspace}/{repo}/branch-restrictions``
    (``push`` / ``force`` / ``delete`` restriction kinds).
    Available at ``repositories:read``.
  * SCM-002 / SCM-008 read ``require_approvals_to_merge`` and
    ``require_passing_builds_to_merge`` from the same endpoint.
    Available at ``repositories:read``.
  * **SCM-006 has no Bitbucket Cloud equivalent** — Bitbucket
    Cloud has no per-branch signed-commit enforcement (GPG
    signing is a personal-account UI setting, not a protection
    rule). The rule always fires on Bitbucket snapshots; suppress
    per repo with a rationale if the team enforces signing via a
    different mechanism.
  * SCM-017 probes
    ``/repositories/{workspace}/{repo}/src/<branch>/<path>?format=meta``
    for the three CODEOWNERS locations. Available at
    ``repositories:read``.

#### Offline / fixture mode

``--scm-fixture-dir DIR`` reads JSON responses from disk instead of
hitting the network on every platform. No token is required and no
HTTP traffic leaves the host. Useful for CI runs, air-gapped
evaluation, and reproducing a customer's posture against a captured
fixture set. Endpoint paths map to
``<endpoint-with-slashes-as-underscores>.json`` under DIR; a
missing file is treated as a 404 (the rule passes silently with an
unavailability note, same as when a real call fails).

### What the rules expect

The provider hits three endpoints per repo:

  * ``GET /repos/{owner}/{repo}`` — repo metadata, default
    branch name, ``security_and_analysis`` feature states.
  * ``GET /repos/{owner}/{repo}/branches/{default}/protection`` —
    branch protection rule (404 = no rule).
  * ``GET /repos/{owner}/{repo}/code-scanning/default-setup`` —
    default code scanning state.

Three production cases produce ``security_and_analysis``-omitted
responses (which the rules treat as "not enabled" but flag in the
description):

  * The token lacks ``admin`` scope on the repo.
  * The repo is on a plan that doesn't expose the feature
    (e.g. private-repo Dependabot on a free org).
  * The repo metadata fetch itself failed.

Three FP-prevention guards keep noise out of the report:

  * **Empty repos** (``repo_meta.size == 0`` and no protection
    rule). SCM-001 passes with an "Empty repo" note rather than
    fail "no protection rule" on a brand-new repo with no commits.
  * **Archived / disabled repos**. GitHub auto-disables
    Dependabot, secret scanning, push protection, code scanning,
    and private vulnerability reporting on archived repos.
    SCM-003 / SCM-004 / SCM-005 / SCM-015 / SCM-016 detect the
    archive flag and pass with a "Skipped: archived repo" note.
    Branch-protection rules deliberately still evaluate — the
    audit-trail signal stays meaningful even when the repo is
    read-only.
  * **Repo-metadata-unavailable**. When the
    ``repos/{owner}/{repo}`` fetch fails, the provider does NOT
    probe ``branches/main/protection`` (which would FP for any
    repo whose default branch is not literally ``main``).
    SCM-001 surfaces a "Repo metadata unavailable" finding so
    the gap is visible rather than silent.

### SCM-specific checks

- **SCM-001 / SCM-007 / SCM-009**, branch protection presence,
  force-push denial, and deletion denial. Together they cover
  the rewrite-history attack class — without them, every other
  branch-protection knob the team configured can be erased
  after the fact.
- **SCM-002 / SCM-011 / SCM-012 / SCM-013 / SCM-014**, the review
  side of branch protection. Required count, CODEOWNERS
  routing, stale-review dismissal on force-push, conversation
  resolution, last-push approval. SCM-014 is the one that blocks
  the two-account collab review bypass.
- **SCM-003 / SCM-004 / SCM-005 / SCM-015 / SCM-016**, the
  ``security_and_analysis``-driven feature checks: code
  scanning, secret scanning, Dependabot security updates, secret-
  scanning push protection, private vulnerability reporting.
  All five share the archived-repo skip behavior.
- **SCM-006**, signed-commit enforcement on the default branch.
  Pairs with GHA-006 in the **XPC-005** chain to flag end-to-end
  provenance gaps (source unsigned + artifact unsigned = no
  cryptographic chain of custody).
- **SCM-010**, the meta-rule: branch protection enforces against
  administrators. Without it, every other protection knob is
  advisory rather than enforced.

### Cross-provider chains

When ``--pipelines github,scm`` (or ``--pipelines dockerfile,scm``)
is used together, five attack-chain rules in the ``XPC-NNN`` family
compose SCM findings with workflow / Dockerfile findings:

- **XPC-004**, ``SCM-001 ∨ SCM-007`` + ``GHA-019`` → token
  persistence on an unprotected default branch. CRITICAL composite
  because the attacker primitive collapses from "compromise the
  build runtime" to "open a PR, fetch the next build's
  artifacts."
- **XPC-005**, ``SCM-006`` + ``GHA-006`` → end-to-end provenance
  gap. Source unsigned and artifact unsigned together mean
  consumers can't verify what built from what, anywhere along
  the pipeline.
- **XPC-006**, ``SCM-002`` + ``GHA-002`` → unreviewed fork-PR
  privilege escalation. The pwn-request primitive (workflow uses
  ``pull_request_target`` and checks out PR head) plus a
  protection rule with no required reviews means a single
  insider can introduce or maintain the vulnerability without
  any human-review gate. CRITICAL composite.
- **XPC-007**, ``SCM-005`` + ``GHA-001`` → unpinned actions with
  no automated remediation. Tag-pinned ``uses:`` references plus
  Dependabot disabled means an upstream maintainer compromise
  propagates immediately to every workflow run AND there's no
  automated PR to move the team off the malicious version when
  the public CVE drops. The tj-actions/changed-files
  CVE-2025-30066 incident is the canonical instance.
- **XPC-008**, ``SCM-001 ∨ SCM-007`` + ``DF-001`` → unreviewed
  source ships a mutable runtime image. Insider-introducible
  Dockerfile change AND floating-tag base image: the team has
  two unrelated trust boundaries open at once and no compensating
  control to break the chain at.
""",
    ),
    "npm": (
        "npm",
        "pipeline_check.core.checks.npm.rules",
        _REPO_ROOT / "docs" / "providers" / "npm.md",
        """\
# npm provider

Parses ``package.json`` / ``package-lock.json`` /
``npm-shrinkwrap.json`` documents on disk for supply-chain hygiene.
Text-only static analysis, no ``npm install``, no registry pull, no
daemon access. Rule modules see either an ``NpmManifest`` (the
parsed ``package.json``) or an ``NpmLock`` (the parsed lockfile) and
flag the patterns that turned the Shai-Hulud / TanStack / PyTorch-
``torchtriton`` class of incidents into mass-propagation events.

## Producer workflow

```bash
# --npm-path is auto-detected when package.json / package-lock.json
# exist at cwd; the CLI announces the pick on stderr.
pipeline_check --pipeline npm

# …or pass it explicitly.
pipeline_check --pipeline npm --npm-path path/to/package.json

# Recursively scan a monorepo: every package.json / package-lock.json
# outside node_modules/ is picked up.
pipeline_check --pipeline npm --npm-path packages/
```

The loader skips anything under ``node_modules/`` so transitive
manifests don't dilute the signal; only the manifests + lockfiles you
authored are evaluated.

## Scope

* ``package.json`` (root manifest, ``dependencies`` /
  ``devDependencies`` / ``optionalDependencies`` /
  ``peerDependencies`` / ``scripts``)
* ``package-lock.json`` / ``npm-shrinkwrap.json`` (npm 6 v1 and npm
  7+ v2 / v3 schemas)

``yarn.lock`` and ``pnpm-lock.yaml`` are out of scope for the
initial pack; both formats are distinct enough to warrant their own
parsers and are queued for a follow-up.
""",
    ),
    "pypi": (
        "pypi",
        "pipeline_check.core.checks.pypi.rules",
        _REPO_ROOT / "docs" / "providers" / "pypi.md",
        """\
# pypi provider

Parses pip ``requirements*.txt`` / ``*.in`` files on disk for
supply-chain hygiene. Text-only static analysis, no ``pip install``,
no PyPI API access, no resolver run. Rule modules see a
``RequirementsFile`` (parsed lines + top-level options) and flag the
patterns that produced the dependency-confusion (Birsan 2021),
typosquat (PyTorch ``torchtriton`` 2022), and TLS-bypass
historical incidents.

## Producer workflow

```bash
# --pypi-path is auto-detected when requirements.txt exists at cwd.
pipeline_check --pipeline pypi

# …or pass it explicitly.
pipeline_check --pipeline pypi --pypi-path requirements.txt

# Recursively scan a project tree: every requirements*.txt and *.in
# under the path is picked up.
pipeline_check --pipeline pypi --pypi-path .
```

## Scope

* ``requirements.txt`` (and any ``requirements*.txt`` variant)
* ``requirements/*.txt`` (split-by-environment layout)
* ``*.in`` (pip-tools input files)

``pyproject.toml`` (PEP 621 / Poetry), ``Pipfile.lock``, and
``poetry.lock`` are out of scope for the initial pack and queued for
a follow-up. Most of the strongest supply-chain signals — pinning,
hashing, ``--extra-index-url`` confusion, ``--trusted-host`` —
live in the requirements file the build actually feeds to pip, which
this provider covers.

## ``*.in`` exemptions

``*.in`` files are pip-tools *inputs*: declarative ranges that get
compiled (via ``pip-compile``) into resolved, hash-bearing
``requirements.txt`` outputs. PYPI-001 (pin) and PYPI-002 (hash) are
intentionally skipped on ``.in`` files — pinning at the input layer
is the wrong layer. The rules still fire on the compiled
``requirements.txt`` so the artifact pip actually installs is
covered.
""",
    ),
    "maven": (
        "maven",
        "pipeline_check.core.checks.maven.rules",
        _REPO_ROOT / "docs" / "providers" / "maven.md",
        """\
# maven provider

Parses Maven `pom.xml` project descriptors and per-user / per-CI
`settings.xml` files on disk. Text-only static analysis, no
`mvn install`, no Maven Central API access, no resolver run. Rule
modules see a parsed `PomFile` (dependencies, repositories,
properties, mirrors) and flag the patterns that produced the
Log4Shell (Dec 2021), Spring4Shell (March 2022), and Text4Shell (Oct
2022) historical incidents.

## Producer workflow

```bash
# --maven-path is auto-detected when pom.xml exists at cwd.
pipeline_check --pipeline maven

# …or pass it explicitly.
pipeline_check --pipeline maven --maven-path pom.xml

# Recursively scan a multi-module reactor: every pom.xml under the
# path (excluding ``target/`` and ``.m2/``) is picked up.
pipeline_check --pipeline maven --maven-path .
```

## Scope

* `pom.xml` (project descriptor, both top-level and submodule)
* `settings.xml` (per-user / per-CI Maven config, scanned for
  `<mirrors>` posture)
* `<dependencyManagement>` entries are surfaced separately from real
  dependencies so version-management blocks don't trigger consumption-
  side rules.

`gradle.lockfile`, `build.gradle`, and `build.gradle.kts` are out of
scope for the initial pack; a separate `gradle` provider is queued
for a follow-up. The Maven half covers Maven Central and any
Maven-compatible registry (Nexus, Artifactory, GitHub Packages) the
project resolves through `pom.xml`.

## Property resolution

Single-level `${prop}` substitution against the POM's `<properties>`
block is performed before each rule evaluates a version literal, so a
property pointing at a floating range or a known-compromised version
still trips the relevant rule. Nested substitution is intentionally
left unresolved; deeply-recursive property graphs are rare in
real-world POMs and out of scope for static analysis.
""",
    ),
    "nuget": (
        "NuGet",
        "pipeline_check.core.checks.nuget.rules",
        _REPO_ROOT / "docs" / "providers" / "nuget.md",
        """\
# NuGet provider

Parses .NET NuGet project files and configuration on disk. Text-only
static analysis, no `dotnet restore`, no NuGet API access (offline
rules). Behind `--resolve-remote`, NUGET-008 queries
`api.nuget.org` for publish-time metadata and NUGET-009 queries the
OSV advisory database.

## Producer workflow

```bash
# --nuget-path is auto-detected when Directory.Packages.props exists.
pipeline_check --pipeline nuget
pipeline_check --pipeline nuget --nuget-path ./src/
```

## Supported file formats

| File | Parse shape |
|------|-------------|
| `*.csproj` | `<PackageReference Include="..." Version="..." />` entries |
| `Directory.Packages.props` | Central package management (`<PackageVersion>` entries) |
| `packages.config` | Legacy format (`<package id="..." version="..." />`) |
| `NuGet.config` | Package sources and `packageSourceMapping` sections |
| `packages.lock.json` | SDK-generated lock file (resolved versions) |

`bin/`, `obj/`, and `.nuget/` directories are skipped.
""",
    ),
    "cloudformation": (
        "CloudFormation",
        "pipeline_check.core.checks.cloudformation.rules",
        _REPO_ROOT / "docs" / "providers" / "cloudformation.md",
        """\
# CloudFormation provider

Scans a **CloudFormation template** (YAML or JSON), no live AWS
credentials required. Short-form intrinsics (`!Ref`, `!Sub`, `!GetAtt`,
`!Join`, `!If`, …) are normalized to their JSON-form equivalents at
parse time so rules operate on one uniform structure.

Every AWS-mirrored check ID (CB-*, CP-*, CD-*, ECR-*, IAM-*, PBAC-*,
S3-*, CT-*, CWL-*, SM-*, CA-*, CCM-*, LMB-*, KMS-*, SSM-*, EB-*,
SIGN-*, CW-*) maps one-to-one to its AWS-provider counterpart. The
semantics are identical, only the data source differs (template
properties instead of boto3 list/describe). CF-* rules are
CloudFormation-only and have no AWS-runtime analogue.

## Producer workflow

```bash
pipeline_check --pipeline cloudformation --cfn-template path/to/template.yaml
# or point at a directory and every *.yml / *.yaml / *.json / *.template is scanned
pipeline_check --pipeline cloudformation --cfn-template infra/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the AWS provider.

## Intrinsic handling

CFN values may be literals (``"ap-southeast-2"``), booleans,
unresolved intrinsics (``{"Ref": "Region"}``, ``{"Fn::Sub": "..."}``),
or condition references. The scanner follows two conventions:

1. **Anything not provably safe is treated as a potential offender
   unless the rule explicitly skips unresolved values.** For
   instance, ``is_true(value)`` returns ``True`` only for ``True`` or
   ``"true"``, so a template that hides a ``Ref`` behind a
   boolean-typed property is scored as if the flag were disabled.
2. **Statically-reducible intrinsics are reduced before matching.**
   ``resolve_literal(value, parameters)`` in
   ``cloudformation/base.py`` evaluates
   ``{"Ref": "ParamName"}`` against the template's
   ``Parameters.<Name>.Default``, ``{"Fn::Sub": "literal"}`` /
   ``{"Fn::Sub": "...${Var}..."}`` including the
   ``[template, {var-map}]`` form, and ``{"Fn::Join": [delim,
   [list]]}`` when every list item resolves. Rules that benefit
   (``EB-002`` target ARNs, ``CF-003`` VPC IDs) call the resolver
   first and fall back to the old "skip unresolved" path only when
   the intrinsic references a pseudo-parameter (``AWS::Region``) or
   a runtime-dependent intrinsic (``Fn::GetAtt``,
   ``Fn::ImportValue``, ``Fn::If``).

Rule helpers (importable from ``cloudformation/base.py``):

- ``as_str(value)`` — literal-only accessor, returns ``""`` for intrinsics.
- ``resolve_literal(value, parameters)`` — tries to reduce every
  statically-resolvable intrinsic; returns ``None`` when it can't.
- ``is_true(value)`` — strict boolean gate.
- ``is_intrinsic(value)`` — predicate used by ``CF-002`` to skip
  intrinsic dicts entirely when walking for hard-coded secrets.

This matches cfn-lint and cfn-nag conventions and keeps findings
useful under the common case where templates are parameterised.

## Resource-type coverage

| Service          | IDs               | CloudFormation resources consumed |
|------------------|-------------------|-----------------------------------|
| CodeBuild        | `CB-001…011`      | `AWS::CodeBuild::Project`, `AWS::CodeBuild::SourceCredential` |
| CodePipeline     | `CP-001…005`, `CP-007` | `AWS::CodePipeline::Pipeline` |
| CodeDeploy       | `CD-001…003`      | `AWS::CodeDeploy::DeploymentGroup` |
| ECR              | `ECR-001…006`     | `AWS::ECR::Repository`, `AWS::ECR::PullThroughCacheRule` |
| IAM              | `IAM-001…006`, `IAM-008` | `AWS::IAM::Role`, `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy` |
| PBAC             | `PBAC-001…003`, `PBAC-005` | `AWS::CodeBuild::Project`, `AWS::EC2::SecurityGroup` |
| S3               | `S3-001…005`      | `AWS::S3::Bucket` (artifact buckets discovered from pipelines) |
| CloudTrail       | `CT-001…003`      | `AWS::CloudTrail::Trail` |
| CloudWatch Logs  | `CWL-001…002`     | `AWS::Logs::LogGroup` |
| Secrets Manager  | `SM-001…002`      | `AWS::SecretsManager::Secret`, `AWS::SecretsManager::RotationSchedule` |
| CodeArtifact     | `CA-001…004`      | `AWS::CodeArtifact::Domain`, `AWS::CodeArtifact::Repository` |
| CodeCommit       | `CCM-002…003`     | `AWS::CodeCommit::Repository` (CCM-001 omitted, no equivalent CFN resource) |
| Lambda           | `LMB-001…004`     | `AWS::Lambda::Function`, `AWS::Lambda::Url`, `AWS::Lambda::Permission` |
| KMS              | `KMS-001…002`     | `AWS::KMS::Key` |
| SSM              | `SSM-001…002`     | `AWS::SSM::Parameter` |
| EventBridge      | `EB-001…002`      | `AWS::Events::Rule` (targets are inline) |
| Signer           | `SIGN-001`        | `AWS::Lambda::Function.CodeSigningConfigArn`, `AWS::Signer::SigningProfile` |
| CloudWatch       | `CW-001`          | `AWS::CloudWatch::Alarm` (namespace=`AWS/CodeBuild`, metric=`FailedBuilds`) |
| CFN-native       | `CF-001…003`      | `AWS::IAM::AccessKey`, stateful data-store types, `AWS::EC2::Subnet` |

## Limitations

- **Template-level only.** Resources provisioned outside the
  template (console, SDK, sister stacks) are not scanned — use
  `--pipeline aws` alongside for a live view.
- **Intrinsics are not evaluated** beyond the statically-reducible
  forms above. A ``Fn::GetAtt``, ``Fn::ImportValue``, or ``Fn::If``
  passes through as an opaque dict; rules that require a literal
  value silently skip the finding rather than guess at the resolved
  shape.
- **No cross-stack resolution.** ``Fn::ImportValue`` references are
  preserved as-is; the exporting stack is not fetched.
- **Transform macros are ignored.** ``AWS::Serverless-2016-10-31``
  (SAM) and custom transforms run server-side; the pre-transform
  resources are what the scanner sees.
""",
    ),
    "terraform": (
        "Terraform",
        "pipeline_check.core.checks.terraform.rules",
        _REPO_ROOT / "docs" / "providers" / "terraform.md",
        """\
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

| Check   | Primary input |
|---------|---------------|
| IAM-001 | `managed_policy_arns` + `aws_iam_role_policy_attachment.policy_arn` |
| IAM-002 | inline + attached policy JSON (Action `*`) |
| IAM-003 | `aws_iam_role.permissions_boundary` |
| IAM-004 | inline + attached policy JSON (`iam:PassRole` on `Resource = "*"`) |
| IAM-005 | `aws_iam_role.assume_role_policy` (external principal w/o `sts:ExternalId`) |
| IAM-006 | inline + attached policy JSON (sensitive actions on `Resource = "*"`) |
| IAM-008 | `aws_iam_role.assume_role_policy` (OIDC `:aud` / `:sub` pin) |

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
""",
    ),
    "helm": (
        "Helm",
        "pipeline_check.core.checks.helm.rules",
        _REPO_ROOT / "docs" / "providers" / "helm.md",
        """\
# Helm chart provider

Renders Helm charts via `helm template` and runs the [Kubernetes
provider's](kubernetes.md) full K8S-* rule pack against the resulting
manifests, plus a chart-supply-chain rule pack
(`HELM-001`--`010`) that reads `Chart.yaml` and `Chart.lock`
straight off disk. The K8s pass scores rendered workloads
(securityContext, hostPath, RBAC, …); the HELM pass scores the
chart's own posture (legacy schema, lockfile drift, plaintext
dependency repos).

Most production Kubernetes ships through Helm, so a chart-aware
front-end means today's K8S-* rules finally see the bulk of real
workloads instead of the hand-written manifests that happen to land
in `k8s/`. Findings from the K8s pass carry the source-template path
(e.g. `mychart/templates/deployment.yaml`) so a "privileged
container" finding points at the actual template file, not the
rendered output.

## Requirements

- **`helm` (Helm 3) on PATH.** The provider shells out to `helm
  template`. Helm 2 is rejected on probe. It has been EOL since
  November 2020. Install instructions:
  [helm.sh/docs/intro/install](https://helm.sh/docs/intro/install/).
- **Chart dependencies pre-resolved.** If your chart declares
  dependencies in `Chart.yaml`, run `helm dependency update` first.
  The provider does not fetch dependencies for you (network access
  during scanning is out of scope for the static-analysis posture
  the tool keeps everywhere else).

## Producer workflow

```bash
# --helm-path is auto-detected when Chart.yaml exists at cwd, or
# when a charts/ directory holds one or more sub-charts.
pipeline_check --pipeline helm

# …or pass it explicitly. Either a single chart directory or a
# packaged chart .tgz works.
pipeline_check --pipeline helm --helm-path ./charts/myapp
pipeline_check --pipeline helm --helm-path ./dist/myapp-1.2.3.tgz

# A parent directory containing multiple charts renders each one
# (one Chart.yaml per immediate subdirectory). Vendored
# dependencies under <chart>/charts/ are not double-rendered.
pipeline_check --pipeline helm --helm-path ./charts/
```

### Values and overrides

`--helm-values` and `--helm-set` map straight onto `helm template -f`
and `helm template --set`. Repeat each flag for multiple values:

```bash
pipeline_check --pipeline helm --helm-path ./mychart \\
    --helm-values values-prod.yaml \\
    --helm-values values-prod-overrides.yaml \\
    --helm-set image.tag=v1.2.3 \\
    --helm-set replicas=3
```

Precedence matches Helm's: later `-f` files override earlier ones,
and `--set` overrides files. The chart's own `values.yaml` is
applied automatically by Helm; you don't need to pass it.

Scanning a chart with the **production** values is usually what you
want. A chart that only exposes a `privileged: true` workload when
`debug: true` is set should not fail the gate during routine
scanning.

## Rendered Kubernetes manifests

The full K8S-* rule pack listed on the [Kubernetes provider
page](kubernetes.md) applies to rendered chart output identically
(`securityContext`, `hostPath`, RBAC blast radius, Secret hygiene,
control-plane scheduling). The rules see the manifest output of
`helm template`, so values-driven toggles and conditional templates
are scored as they would actually deploy.

The HELM-* pack below is additive: those rules score the chart's
own packaging metadata, read straight off `Chart.yaml` /
`Chart.lock` rather than the rendered output. A chart can have a
perfect `securityContext` posture and still ship a v1 schema, an
unlocked dependency, or no maintainers.
""",
    ),
    "dockerfile": (
        "Dockerfile",
        "pipeline_check.core.checks.dockerfile.rules",
        _REPO_ROOT / "docs" / "providers" / "dockerfile.md",
        """\
# Dockerfile provider

Parses `Dockerfile` / `Containerfile` documents on disk, text-only
static analysis, no image build, no registry pull, no daemon access.
Multi-stage builds are flattened: rules see the full instruction
stream and decide for themselves whether to scope by stage (e.g.
DF-002 only checks the *final* stage's `USER`).

## Producer workflow

```bash
# --dockerfile-path is auto-detected when Dockerfile/Containerfile
# exists at cwd.
pipeline_check --pipeline dockerfile

# …or pass it explicitly.
pipeline_check --pipeline dockerfile --dockerfile-path docker/api.Dockerfile

# Recursively scan a service directory containing many per-service
# Dockerfiles. The loader matches Dockerfile, Containerfile,
# Dockerfile.<suffix>, and *.Dockerfile by default.
pipeline_check --pipeline dockerfile --dockerfile-path services/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Dockerfile-specific checks

Several checks target Dockerfile concepts that have no direct
analogue in other providers:

- **DF-001**, `FROM` must pin by `@sha256:<digest>`. Reuses the same
  classifier as GL-001 / JF-009 / ADO-009 / CC-003 so the
  floating-tag vocabulary matches across the tool.
- **DF-002**, final stage must run as a non-root `USER`. Multi-stage
  builds: only the runtime image's identity matters, so this rule
  scopes USER tracking to the directives after the *last* `FROM`.
- **DF-003**, `ADD <url>` must carry a BuildKit `--checksum=sha256:`
  flag, otherwise it pulls remote content with no integrity check.
- **DF-006**, `ENV` / `ARG` values are baked into image layers;
  ``docker history`` reads them even after they're overwritten. Any
  literal credential-shaped value (AKIA-prefixed, or a key named
  `*_PASSWORD` / `*_TOKEN` / `*_SECRET` with a non-empty literal) is
  CRITICAL.
""",
    ),
    "azure_cloud": (
        "Azure Cloud",
        "pipeline_check.core.checks.azure_cloud.rules",
        _REPO_ROOT / "docs" / "providers" / "azure_cloud.md",
        """\
# Azure Cloud provider

Scans a live Azure subscription via the ``azure-mgmt-*`` management
SDKs. Requires ``pip install pipeline-check[azure-cloud]`` and Azure
CLI authentication (``az login``).

## Producer workflow

```bash
pipeline_check --pipeline azure_cloud --subscription-id 00000000-0000-0000-0000-000000000000
pipeline_check --pipeline azure_cloud --subscription-id $AZURE_SUBSCRIPTION_ID --azure-tenant-id $AZURE_TENANT_ID
```

## Covered services

| Service | Prefix | Rules |
|---------|--------|-------|
| Entra ID (identity) | ENTRA- | Service principal roles, app credentials, password vs certificate |
| Storage | AZST- | Public access, HTTPS enforcement, CMK encryption |
| Key Vault | AKV- | Soft delete, purge protection, network ACLs |
| Container Registry | ACR- | Admin user, public access, content trust |
| Monitor | AZMON- | Diagnostic settings, log retention, alert rules |
""",
    ),
    "gcp": (
        "GCP",
        "pipeline_check.core.checks.gcp.rules",
        _REPO_ROOT / "docs" / "providers" / "gcp.md",
        """\
# GCP provider

Scans a live GCP project via the ``google-cloud-*`` client libraries.
Requires ``pip install pipeline-check[gcp]`` and Application Default
Credentials (``gcloud auth application-default login``).

## Producer workflow

```bash
pipeline_check --pipeline gcp --gcp-project my-project-id
pipeline_check --pipeline gcp --gcp-project $GCP_PROJECT
```

## Covered services

| Service | Prefix | Rules |
|---------|--------|-------|
| IAM | GCIAM- | Service account admin roles, user-managed keys, impersonation |
| Cloud Storage | GCS- | Public buckets, uniform access, versioning |
| Cloud KMS | GCKMS- | Key rotation, public access, HSM protection |
| Artifact Registry | GAR- | Vulnerability scanning, public repos, cleanup policies |
| Cloud Logging | GCLOG- | Audit log config, log sinks, retention |
""",
    ),
}


_FOOTER_TEMPLATE = """\
---

## Adding a new {title} check

1. Create a new module at
   `pipeline_check/core/checks/{pkg}/rules/{prefix_lc}NNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `{signature}`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the {arg_kind}.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/{pkg}/{prefix}-NNN.{{unsafe,safe}}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py {slug}
   ```
"""


# Per-provider footer overrides. The default ``_FOOTER_TEMPLATE`` above
# assumes a single rule-id prefix per provider and a ``tests/fixtures/
# per_check/<pkg>/`` fixture layout. AWS rules cross many prefixes
# (CB / CP / IAM / ECR / ...) and the tests live under
# ``tests/aws/rules/`` against a ``ResourceCatalog`` mock, not against
# YAML snippets, so the standard recipe doesn't apply verbatim.
_FOOTER_OVERRIDES: dict[str, str] = {
    "cloudformation": """\
---

## Adding a new CloudFormation check

1. Drop a single module at
   `pipeline_check/core/checks/cloudformation/rules/<id>_<slug>.py`
   exporting a `RULE` (metadata) and a
   `check(ctx: CloudFormationContext) -> list[Finding]` callable. The
   orchestrator (`CloudFormationRuleChecks`) auto-discovers it and
   this doc's table picks it up on the next regen.
2. If the rule needs side resources (managed-policy dereferencing,
   artifact-bucket discovery, policy documents joined on
   ``Bucket`` / ``RoleName``), add a private helper to
   `pipeline_check/core/checks/cloudformation/rules/_<service>_context.py`
   following the `_iam_context.py` / `_s3_context.py` pattern.
3. Add the check ID to
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
4. Add unit tests in `tests/cloudformation/test_<service>.py` using
   `make_cfn_ctx` or one of the existing template fixtures.
5. (Recommended) Add an AWS-runtime parity rule under
   `pipeline_check/core/checks/aws/rules/` and a Terraform parity
   rule under `pipeline_check/core/checks/terraform/rules/` so the
   three IaC entry points stay aligned.
6. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py cloudformation
   ```
""",
    "terraform": """\
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
""",
    "helm": """\
---

## What it can't see

`helm template` renders charts against a synthetic release context.
A few constructs aren't represented faithfully:

- **`.Capabilities.APIVersions`** renders against Helm's default
  capability set, not your real cluster. Charts that conditionally
  emit a `NetworkPolicy` only when the `networking.k8s.io/v1` API
  is present will render assuming it is.
- **`lookup`** functions return empty maps: there's no cluster
  to query, so resources gated on a live `lookup` won't render.
- **Hooks** (`helm.sh/hook` annotations) render like any other
  manifest. K8S-* rules apply to them equally; this is the right
  call because a privileged hook pod is just as dangerous as a
  privileged long-lived workload.
- **Library charts** (`Chart.yaml` `type: library`) produce no
  output and are skipped with an info-level warning.

The render context uses synthetic `.Release.Name = "pipeline-check"`
and `.Release.Namespace = "default"`. Templates that hardcode
namespace logic against `.Release.Namespace` see `default` and
behave accordingly.

## Render failures

If `helm template` exits non-zero (bad template syntax, undefined
values, missing dependency), the chart is recorded in
`ctx.warnings` and skipped. Other charts in the same scan continue
to render. The first non-empty stderr line is surfaced so the user
can find the template error without re-running helm by hand.

## Source attribution

`helm template` injects `# Source: <chart>/templates/<file>.yaml`
above each rendered document. The provider parses these and
attaches the chart-relative template path to the parsed manifest,
which surfaces in:

- the inventory output (`source` column points at the template
  file, not the synthetic `<rendered>` path)
- the Kubernetes manifest's display string used by reporters
- the `Manifest.source_template` field exposed via the public
  Python API

Per-finding location attribution at the line level is a separate
concern that affects the K8s rule pack as a whole; in this
release, finding offenders are listed by `Kind/name` and the
template file shows up in inventory.

---

## Adding a new Helm check

1. Create a new module at
   `pipeline_check/core/checks/helm/rules/helmNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a
   `check(ctx: HelmContext) -> Finding` function. The orchestrator
   (`HelmChartChecks`) auto-discovers `RULE` and calls `check` with
   the shared `HelmContext` (parsed `Chart` records).
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and
   any other standard that applies).
3. Add unit tests in `tests/helm/rules/test_<name>.py`. Use the
   `make_helm_ctx` fixture to build a synthetic `Chart` record
   without invoking `helm template`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py helm
   ```
""",
    "aws": """\
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
""",
}


# Per-provider check signature strings. Tekton and Argo (and other
# context-based providers) hand the rule a typed context; the older
# workflow providers still take ``(path, doc)``.
_DEFAULT_SIGNATURE = "check(path, doc) -> Finding"
_DEFAULT_ARG_KIND = "parsed YAML document"

_FOOTER_CONFIG: dict[str, dict[str, str]] = {
    "github":    {"prefix": "GHA", "prefix_lc": "gha", "pkg": "github"},
    "gitlab":    {"prefix": "GL",  "prefix_lc": "gl",  "pkg": "gitlab"},
    "bitbucket": {"prefix": "BB",  "prefix_lc": "bb",  "pkg": "bitbucket"},
    "azure":     {"prefix": "ADO", "prefix_lc": "ado", "pkg": "azure"},
    "jenkins":   {"prefix": "JF",  "prefix_lc": "jf",  "pkg": "jenkins"},
    "circleci":  {"prefix": "CC",  "prefix_lc": "cc",  "pkg": "circleci"},
    "cloudbuild": {"prefix": "GCB", "prefix_lc": "gcb", "pkg": "cloudbuild"},
    "buildkite": {"prefix": "BK",  "prefix_lc": "bk",  "pkg": "buildkite"},
    "tekton":    {
        "prefix": "TKN", "prefix_lc": "tkn", "pkg": "tekton",
        "signature": "check(ctx: TektonContext) -> Finding",
        "arg_kind": "``TektonContext``",
    },
    "argo":      {
        "prefix": "ARGO", "prefix_lc": "argo", "pkg": "argo",
        "signature": "check(ctx: ArgoContext) -> Finding",
        "arg_kind": "``ArgoContext``",
    },
    "argocd":    {
        "prefix": "ARGOCD", "prefix_lc": "argocd", "pkg": "argocd",
        "signature": "check(ctx: ArgoCDContext) -> Finding",
        "arg_kind": "``ArgoCDContext``",
    },
    "dockerfile": {"prefix": "DF",  "prefix_lc": "df",  "pkg": "dockerfile"},
    "kubernetes": {"prefix": "K8S", "prefix_lc": "k8s", "pkg": "kubernetes"},
    "npm": {
        "prefix": "NPM", "prefix_lc": "npm", "pkg": "npm",
        "signature": "check(manifest: NpmManifest) -> Finding",
        "arg_kind": "``NpmManifest`` or ``NpmLock`` (chosen by annotation)",
    },
    "pypi": {
        "prefix": "PYPI", "prefix_lc": "pypi", "pkg": "pypi",
        "signature": "check(rf: RequirementsFile) -> Finding",
        "arg_kind": "``RequirementsFile``",
    },
    "maven": {
        "prefix": "MVN", "prefix_lc": "mvn", "pkg": "maven",
        "signature": "check(pom: PomFile) -> Finding",
        "arg_kind": "``PomFile``",
    },
    "oci": {
        "prefix": "OCI", "prefix_lc": "oci", "pkg": "oci",
        "signature": "check(manifest: OCIManifest) -> Finding",
        "arg_kind": "``OCIManifest``",
    },
    "drone": {
        "prefix": "DR", "prefix_lc": "dr", "pkg": "drone",
        "signature": "check(pipeline: Pipeline) -> Finding",
        "arg_kind": "``Pipeline``",
    },
    "scm": {
        "prefix": "SCM", "prefix_lc": "scm", "pkg": "scm",
        "signature": "check(snapshot: SCMRepoSnapshot) -> Finding",
        "arg_kind": "``SCMRepoSnapshot``",
    },
}


def _render_provider(title: str, header: str, rules_fqn: str, slug: str = "") -> str:
    """Walk the rule registry and stitch together the full provider doc."""
    pairs = discover_rules(rules_fqn)
    lines: list[str] = [header.rstrip() + "\n\n"]

    # ── Summary table ──
    # Each check ID links to the per-rule section further down via a
    # pinned attr-list anchor (``{ #gha-001 }``) on the rendered H2.
    # The severity column emits a color-coded chip so the table
    # doubles as a click-through priority list. The ``Fix`` column
    # marks rules with a registered autofix patch, useful for
    # filtering with the sortable-table JS layered over markdown
    # tables ("show me all the things ``--fix`` will patch").
    fix_count = sum(1 for r, _ in pairs if r.id in _AUTOFIXABLE)
    lines.append("## What it covers\n\n")
    lines.append(
        f"{len(pairs)} checks · {fix_count} have an autofix patch "
        f"(``--fix``).\n\n"
    )
    lines.append("| Check | Title | Severity | Fix |\n")
    lines.append("|-------|-------|----------|-----|\n")
    for rule, _ in pairs:
        anchor = _rule_anchor(rule.id)
        sev_chip = _severity_chip(rule.severity.value)
        fix_cell = _autofix_chip(rule.id)
        lines.append(
            f"| [{rule.id}](#{anchor}) | {rule.title} | {sev_chip} | {fix_cell} |\n"
        )
    lines.append("\n---\n\n")

    # ── Per-rule section ──
    for rule, _ in pairs:
        lines.append(_render_rule(rule))

    # Per-provider footer override wins over the templated default;
    # see ``_FOOTER_OVERRIDES`` for the rationale (AWS, etc.).
    override = _FOOTER_OVERRIDES.get(slug)
    if override is not None:
        lines.append(override)
    else:
        footer_cfg = dict(_FOOTER_CONFIG.get(slug, {"prefix": "", "prefix_lc": "", "pkg": slug}))
        footer_cfg.setdefault("signature", _DEFAULT_SIGNATURE)
        footer_cfg.setdefault("arg_kind", _DEFAULT_ARG_KIND)
        lines.append(_FOOTER_TEMPLATE.format(title=title, slug=slug, **footer_cfg))
    return "".join(lines)


def _rule_anchor(rule_id: str) -> str:
    """Stable in-page anchor for a rule_id.

    Pinned via ``attr_list`` ``{ #gha-001 }`` on the H2, so the slug
    is deterministic regardless of the title text or its punctuation.
    Markdown's default ``toc`` slugifier would strip the em-dash and
    derive the slug from the title, fine, but couples the anchor to
    the wording. A pinned ID survives title rephrases.
    """
    return rule_id.lower()


def _severity_chip(severity: str) -> str:
    """HTML chip used in summary tables. Uses a CSS class per severity
    so the color is theme-aware (different on light vs slate)."""
    sev_lc = severity.lower()
    return f'<span class="pg-sev pg-sev--{sev_lc}">{severity}</span>'


def _autofix_chip(rule_id: str) -> str:
    """A tiny "🔧 fix" badge for rules with a registered autofix.

    Renders as an empty cell when the rule has no fixer, keeps the
    table tidy without spelling out "no". Sortable-tables JS treats
    empty cells as "comes after populated", so sorting by Fix puts
    autofixable rules first.
    """
    if rule_id in _AUTOFIXABLE:
        return '<span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span>'
    return ""


def _render_rule(rule: Rule) -> str:
    """Render one rule as a card-style section with severity rail.

    Output shape (renders in MkDocs' ``md_in_html`` extension; the
    ``markdown`` attribute lets nested markdown inside the
    ``<div>`` cascades work as expected):

        <div class="pg-rule pg-rule--high" markdown>

        ## GHA-001, title { #gha-001 }

        <div class="pg-rule__tags">…severity chip + tag pills…</div>

        Body text (docs_note prose).

        <div class="pg-rule__rec" markdown>
        **Recommended action**
        …recommendation prose…
        </div>

        </div>

    The CSS picks up ``pg-rule--<severity>`` to color the left
    rail, the chip, and the recommendation block accent.
    """
    parts: list[str] = []
    anchor = _rule_anchor(rule.id)
    sev = rule.severity.value
    sev_lc = sev.lower()

    parts.append(f'<div class="pg-rule pg-rule--{sev_lc}" markdown>\n\n')
    parts.append(f"## {rule.id}: {rule.title} {{ #{anchor} }}\n\n")

    # ── Tag chip row: severity + autofix indicator + OWASP + ESF + CWE ──
    chips: list[str] = [_severity_chip(sev)]
    if rule.id in _AUTOFIXABLE:
        chips.append(
            '<span class="pg-fix pg-fix--rule" '
            'title="`--fix` will patch this rule">🔧 autofix</span>'
        )
    for tag in rule.owasp:
        chips.append(f'<span class="pg-tag pg-tag--owasp">{tag}</span>')
    for tag in rule.esf:
        chips.append(f'<span class="pg-tag pg-tag--esf">{tag}</span>')
    for tag in rule.cwe:
        chips.append(f'<span class="pg-tag pg-tag--cwe">{tag}</span>')
    parts.append('<div class="pg-rule__tags">\n')
    parts.append(" ".join(chips) + "\n")
    parts.append("</div>\n\n")

    # ── Body, the rule's ``docs_note`` is the "why this matters"
    # narrative; render as plain prose. ──
    if rule.docs_note:
        parts.append(rule.docs_note.strip() + "\n\n")

    # ── Known-FP modes: surface the same prose ``--explain`` shows so
    # readers see why a rule defaults to LOW / MEDIUM confidence and
    # what kind of legitimate code trips it. Rendered as a bullet list
    # so a multi-mode entry stays scannable. ──
    if rule.known_fp:
        parts.append("**Known false-positive modes**\n\n")
        for mode in rule.known_fp:
            parts.append(f"- {mode.strip()}\n")
        parts.append("\n")

    # ── Real-world incident citations. Anchors the rule to concrete
    # incidents (CVEs, breach postmortems) so the operator's manager
    # has heard of the cost. Rendered as a bullet list; the prose
    # itself carries any URLs that mkdocs will autolink. ──
    if rule.incident_refs:
        parts.append("**Seen in the wild**\n\n")
        for ref in rule.incident_refs:
            parts.append(f"- {ref.strip()}\n")
        parts.append("\n")

    # ── Recommendation: framed block so it stands out from the body
    # narrative. Marked with ``markdown`` so embedded code blocks /
    # bullet lists in the recommendation render. ──
    if rule.recommendation:
        parts.append('<div class="pg-rule__rec" markdown>\n\n')
        parts.append("**Recommended action**\n\n")
        parts.append(rule.recommendation.strip() + "\n\n")
        parts.append("</div>\n\n")

    parts.append("</div>\n\n")
    return "".join(parts)


def _providers_to_render(argv: Iterable[str]) -> list[str]:
    argv = list(argv)
    if not argv:
        return list(SUPPORTED_PROVIDERS.keys())
    for name in argv:
        if name not in SUPPORTED_PROVIDERS:
            raise SystemExit(
                f"Unknown provider {name!r}. "
                f"Supported: {', '.join(SUPPORTED_PROVIDERS.keys())}"
            )
    return argv


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if any provider doc would change. Useful in CI.",
    )
    parser.add_argument(
        "providers",
        nargs="*",
        help="Subset of providers to render (default: all).",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    targets = _providers_to_render(args.providers)
    stale: list[str] = []
    for slug in targets:
        title, rules_fqn, out_path, header = SUPPORTED_PROVIDERS[slug]
        body = _render_provider(title, header, rules_fqn, slug)
        rel = out_path.relative_to(_REPO_ROOT)
        if args.check:
            current = out_path.read_text(encoding="utf-8") if out_path.exists() else ""
            if current != body:
                stale.append(str(rel))
                print(f"[gen-docs] {rel}: out of sync", file=sys.stderr)
            else:
                print(f"[gen-docs] {rel}: in sync")
            continue
        out_path.write_text(body, encoding="utf-8")
        print(f"[gen-docs] wrote {rel} ({body.count(chr(10))} lines)")

    if args.check and stale:
        print(
            f"[gen-docs] {len(stale)} provider doc(s) out of sync. "
            f"Re-run scripts/gen_provider_docs.py to update.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
