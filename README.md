# Pipeline-Check

CI/CD Security Posture Scanner — analyses pipeline configurations and scores them against the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/).

Currently supports **AWS** (CodeBuild, CodePipeline, CodeDeploy, ECR, IAM, S3). Support for **GCP**, **GitHub Actions**, and **Azure Pipelines** is planned.

## Features

- Multi-provider architecture: select your pipeline environment with `--pipeline`
- Scans CodeBuild, CodePipeline, CodeDeploy, ECR, IAM, and S3 (AWS)
- Run targeted scans with `--checks` to focus on specific check IDs
- Scores findings on a 0–100 scale with letter grade (A–D)
- Cross-compatible: same core logic runs as a CLI tool or AWS Lambda function
- Rich terminal output and machine-readable JSON
- CI-gate friendly: exits with code `1` when grade is D

## Architecture

```
pipeline_check/
├── cli.py                      # click CLI entry point
├── lambda_handler.py           # AWS Lambda entry point
└── core/
    ├── scanner.py              # provider-agnostic orchestrator
    ├── scorer.py               # weighted scoring + grading
    ├── reporter.py             # terminal (rich) + JSON output
    └── checks/
        ├── base.py             # Finding dataclass, Severity enum, BaseCheck ABC (no cloud SDK imports)
        └── aws/                # AWS-specific checks
            ├── base.py         # AWSBaseCheck — wires boto3 Session into self.session
            ├── codebuild.py    # CB-001 … CB-005
            ├── codepipeline.py # CP-001 … CP-003
            ├── codedeploy.py   # CD-001 … CD-003
            ├── ecr.py          # ECR-001 … ECR-004
            ├── iam.py          # IAM-001 … IAM-003
            └── s3.py           # S3-001 … S3-004

tests/
├── test_scorer.py              # generic scoring tests
├── test_reporter.py            # generic reporter tests
└── aws/                        # AWS-specific tests
    ├── conftest.py             # make_session, make_paginator helpers
    ├── test_codebuild.py
    ├── test_codepipeline.py
    ├── test_codedeploy.py
    ├── test_ecr.py
    ├── test_iam.py
    ├── test_s3.py
    └── test_owasp_pipeline.py  # end-to-end integration test across all AWS services
```

## Installation

```bash
pip install pipeline_check
```

Or install from source:

```bash
git clone https://github.com/your-org/pipelineguard.git
cd pipeline_check
pip install -e .
```

## CLI Usage

```bash
# Scan the whole of AWS us-east-1 with default settings
pipeline_check

# Scan a specific CodePipeline pipeline (scopes CP and S3 checks to that pipeline)
pipeline_check --target my-production-pipeline

# Scan a specific pipeline and only show HIGH+ severity findings
pipeline_check --target my-production-pipeline --severity-threshold HIGH

# Scan a specific AWS region using a named profile
pipeline_check --pipeline aws --region eu-west-1 --profile my-profile

# Run only specific check IDs
pipeline_check --checks CB-001 --checks IAM-001

# Output JSON only (suitable for piping to jq or storing as an artifact)
pipeline_check --output json

# Show terminal report AND save JSON simultaneously
pipeline_check --output both
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--pipeline` | `aws` | Pipeline environment: `aws`, `gcp`, `github`, `azure` |
| `--target` | _(all)_ | Scope scan to a named resource (e.g. a CodePipeline name). Omit to scan the whole region. |
| `--checks` | _(all)_ | Check ID(s) to run — repeat for multiple (e.g. `--checks CB-001 --checks CB-003`) |
| `--region` | `us-east-1` | Region to scan (AWS only) |
| `--profile` | None | AWS CLI named profile (AWS only) |
| `--output` | `terminal` | `terminal`, `json`, or `both` |
| `--severity-threshold` | `INFO` | Minimum severity to display |

> **How `--target` works:** `CodePipelineChecks` fetches only the named pipeline rather than listing all pipelines in the region. `S3Checks` discovers the artifact bucket directly from that pipeline instead of enumerating all pipelines. Other checks (CodeBuild, CodeDeploy, ECR, IAM) still run over the full region — combine with `--checks` to narrow further.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan succeeded, grade A/B/C |
| `1` | Scan succeeded, grade D |
| `2` | Scan failed (AWS API error) |

## Lambda Usage

Deploy `pipeline_check.lambda_handler.handler` as the Lambda handler.

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `PIPELINEGUARD_RESULTS_BUCKET` | No | S3 bucket where JSON reports are stored under `reports/<timestamp>/` |
| `PIPELINEGUARD_SNS_TOPIC_ARN` | No | SNS topic ARN — receives an alert when CRITICAL findings are detected |

### Event payload (optional)

```json
{ "region": "eu-west-1" }
```

If omitted, `AWS_REGION` is used.

### Return value

```json
{
  "statusCode": 200,
  "grade": "B",
  "score": 78,
  "total_findings": 22,
  "critical_failures": 0,
  "report_s3_key": "reports/20240501T120000Z/pipeline_check-report.json"
}
```

### Required IAM permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codebuild:ListProjects",
        "codebuild:BatchGetProjects",
        "codepipeline:ListPipelines",
        "codepipeline:GetPipeline",
        "codedeploy:ListApplications",
        "codedeploy:ListDeploymentGroups",
        "codedeploy:BatchGetDeploymentGroups",
        "ecr:DescribeRepositories",
        "ecr:GetRepositoryPolicy",
        "ecr:GetLifecyclePolicy",
        "iam:ListRoles",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "s3:GetPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging"
      ],
      "Resource": "*"
    }
  ]
}
```

## Checks Reference

### CodeBuild

| ID | Title | Severity | OWASP CI/CD |
|---|---|---|---|
| CB-001 | Secrets in plaintext environment variables | CRITICAL | CICD-SEC-6 |
| CB-002 | Privileged mode enabled | HIGH | CICD-SEC-7 |
| CB-003 | Build logging not enabled | MEDIUM | CICD-SEC-10 |
| CB-004 | No build timeout configured | LOW | CICD-SEC-7 |
| CB-005 | Outdated managed build image | MEDIUM | CICD-SEC-7 |

### CodePipeline

| ID | Title | Severity | OWASP CI/CD |
|---|---|---|---|
| CP-001 | No approval action before deploy stages | HIGH | CICD-SEC-1 |
| CP-002 | Artifact store not encrypted with customer KMS key | MEDIUM | CICD-SEC-9 |
| CP-003 | Source stage using polling instead of event-driven trigger | LOW | CICD-SEC-4 |

### CodeDeploy

| ID | Title | Severity | OWASP CI/CD |
|---|---|---|---|
| CD-001 | Automatic rollback on failure not enabled | MEDIUM | CICD-SEC-1 |
| CD-002 | AllAtOnce deployment config — no canary/rolling strategy | HIGH | CICD-SEC-1 |
| CD-003 | No CloudWatch alarm monitoring on deployment group | MEDIUM | CICD-SEC-10 |

### ECR

| ID | Title | Severity | OWASP CI/CD |
|---|---|---|---|
| ECR-001 | Image scanning on push not enabled | HIGH | CICD-SEC-3 |
| ECR-002 | Image tags are mutable | HIGH | CICD-SEC-9 |
| ECR-003 | Repository policy allows public access | CRITICAL | CICD-SEC-8 |
| ECR-004 | No lifecycle policy configured | LOW | CICD-SEC-7 |

### IAM (CI/CD service roles only)

| ID | Title | Severity | OWASP CI/CD |
|---|---|---|---|
| IAM-001 | CI/CD role has AdministratorAccess policy attached | CRITICAL | CICD-SEC-2 |
| IAM-002 | CI/CD role has wildcard Action in inline policy | HIGH | CICD-SEC-2 |
| IAM-003 | CI/CD role has no permission boundary | MEDIUM | CICD-SEC-2 |

### S3 (CodePipeline artifact buckets only)

| ID | Title | Severity | OWASP CI/CD |
|---|---|---|---|
| S3-001 | Artifact bucket public access block not fully enabled | CRITICAL | CICD-SEC-9 |
| S3-002 | Artifact bucket server-side encryption not configured | HIGH | CICD-SEC-9 |
| S3-003 | Artifact bucket versioning not enabled | MEDIUM | CICD-SEC-9 |
| S3-004 | Artifact bucket access logging not enabled | LOW | CICD-SEC-10 |

## Scoring Model

| Severity | Weight |
|---|---|
| CRITICAL | 20 |
| HIGH | 10 |
| MEDIUM | 5 |
| LOW | 2 |
| INFO | 0 |

**Base score** = `(sum of weights for passing checks) / (total weights) × 100`

An additional **−5 points** is deducted per CRITICAL failure to prevent critical issues being masked by many low-severity passes.

| Grade | Score |
|---|---|
| A | ≥ 90 |
| B | ≥ 75 |
| C | ≥ 60 |
| D | < 60 |

## Adding a New AWS Check Module

1. Create `pipeline_check/core/checks/aws/<service>.py`:

```python
from .base import AWSBaseCheck, Finding, Severity

class MyServiceChecks(AWSBaseCheck):
    def run(self) -> list[Finding]:
        client = self.session.client("myservice")
        # ... collect resources, run checks ...
        return findings
```

2. Register it in `pipeline_check/core/scanner.py`:

```python
from .checks.aws.myservice import MyServiceChecks

_CHECK_CLASSES = [
    ...
    MyServiceChecks,
]
```

3. Add tests in `tests/aws/test_myservice.py`.

Check IDs follow the convention `<PREFIX>-<NNN>` where `NNN` is zero-padded to three digits.

## Adding a New Provider (GCP, GitHub, Azure, …)

1. Create a `pipeline_check/core/checks/<provider>/` sub-package with its own `base.py` that subclasses `BaseCheck`, sets `PROVIDER = "<provider>"`, and accepts whatever credentials object the provider SDK uses.

2. Add a context-building branch in `Scanner.__init__`:

```python
elif self.pipeline == "github":
    self._context = GitHubClient(token=os.environ["GITHUB_TOKEN"])
```

3. Create check modules in the sub-package:

```python
from .base import GitHubBaseCheck, Finding, Severity

class GitHubActionsChecks(GitHubBaseCheck):
    def run(self) -> list[Finding]:
        ...
```

4. Register the classes in `_CHECK_CLASSES` and add tests under `tests/<provider>/`.

They will only run when `--pipeline <provider>` is passed.

## Development

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov=pipeline_check --cov-report=term-missing
```

## Lambda Packaging

```bash
bash scripts/build_lambda.sh
# Output: dist/pipeline_check-lambda.zip
```

## License

MIT
