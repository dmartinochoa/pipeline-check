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
pipelineguard/
├── cli.py                      # click CLI entry point
├── lambda_handler.py           # Lambda entry point
└── core/
    ├── scanner.py              # orchestrates check modules
    ├── scorer.py               # weighted scoring + grading
    ├── reporter.py             # terminal (rich) + JSON output
    └── checks/
        ├── base.py             # Finding dataclass, Severity enum, BaseCheck ABC
        ├── codebuild.py        # CB-001 … CB-005
        ├── codepipeline.py     # CP-001 … CP-003
        ├── codedeploy.py       # CD-001 … CD-003
        ├── ecr.py              # ECR-001 … ECR-004
        ├── iam.py              # IAM-001 … IAM-003
        └── s3.py               # S3-001 … S3-004
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
# Scan AWS us-east-1 with default settings
pipeline_check

# Scan a specific AWS region using a named profile
pipeline_check --pipeline aws --region eu-west-1 --profile my-profile

# Run only specific checks
pipeline_check --checks CB-001 --checks IAM-001

# Output JSON only (suitable for piping to jq or storing as an artifact)
pipeline_check --output json

# Show terminal report AND save JSON simultaneously
pipeline_check --output both

# Only show HIGH and CRITICAL findings
pipeline_check --severity-threshold HIGH
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--pipeline` | `aws` | Pipeline environment: `aws`, `gcp`, `github`, `azure` |
| `--checks` | _(all)_ | Check ID(s) to run — repeat for multiple (e.g. `--checks CB-001 --checks CB-003`) |
| `--region` | `us-east-1` | Region to scan (AWS only) |
| `--profile` | None | AWS CLI named profile (AWS only) |
| `--output` | `terminal` | `terminal`, `json`, or `both` |
| `--severity-threshold` | `INFO` | Minimum severity to display |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan succeeded, grade A/B/C |
| `1` | Scan succeeded, grade D |
| `2` | Scan failed (AWS API error) |

## Lambda Usage

Deploy `pipelineguard.lambda_handler.handler` as the Lambda handler.

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

## Adding a New Check Module (AWS)

1. Create `pipelineguard/core/checks/<service>.py`:

```python
from .base import BaseCheck, Finding, Severity

class MyServiceChecks(BaseCheck):
    PROVIDER = "aws"  # inherited default — can omit for AWS checks

    def run(self) -> list[Finding]:
        client = self.session.client("myservice")
        # ... collect resources, run checks ...
        return findings
```

2. Register it in `pipelineguard/core/scanner.py`:

```python
from .checks.myservice import MyServiceChecks

_CHECK_CLASSES = [
    ...
    MyServiceChecks,
]
```

3. Add tests in `tests/test_myservice.py`.

Check IDs follow the convention `<PREFIX>-<NNN>` where `NNN` is zero-padded to three digits.

## Adding a New Provider (GCP, GitHub, Azure, …)

1. Add a branch in `Scanner.__init__` (`scanner.py`) that builds the appropriate client/credentials object for the provider and stores it as `self._context`.

2. Create check modules with `PROVIDER = "<provider>"` and override `__init__` to accept the context type your provider uses:

```python
from .base import BaseCheck, Finding, Severity

class GitHubActionsChecks(BaseCheck):
    PROVIDER = "github"

    def __init__(self, context) -> None:
        self.client = context  # e.g. a PyGithub client

    def run(self) -> list[Finding]:
        # ...
        return findings
```

3. Register the class in `_CHECK_CLASSES`. It will only run when `--pipeline github` is passed.

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
