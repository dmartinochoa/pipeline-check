# Pipeline-Check

AWS CI/CD Security Posture Scanner — currenty analyses AWS-native pipeline configurations and scores them against the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/).

## Features

- Scans CodeBuild, CodePipeline, CodeDeploy, ECR, IAM, and S3
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
pip install pipelineguard
```

Or install from source:

```bash
git clone https://github.com/your-org/pipelineguard.git
cd pipelineguard
pip install -e .
```

## CLI Usage

```bash
# Scan us-east-1 with default settings
pipelineguard

# Scan a different region using a named AWS profile
pipelineguard --region eu-west-1 --profile my-profile

# Output JSON only (suitable for piping to jq or storing as an artifact)
pipelineguard --output json

# Show terminal report AND save JSON simultaneously
pipelineguard --output both

# Only show HIGH and CRITICAL findings
pipelineguard --severity-threshold HIGH
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--region` | `us-east-1` | AWS region to scan |
| `--profile` | None | AWS CLI named profile |
| `--output` | `terminal` | `terminal`, `json`, or `both` |
| `--severity-threshold` | `LOW` | Minimum severity to display |

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
  "report_s3_key": "reports/20240501T120000Z/pipelineguard-report.json"
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

## Adding a New Check Module

1. Create `pipelineguard/core/checks/<service>.py`:

```python
from .base import BaseCheck, Finding, Severity

class MyServiceChecks(BaseCheck):
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

## Development

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov=pipelineguard --cov-report=term-missing
```

## Lambda Packaging

```bash
bash scripts/build_lambda.sh
# Output: dist/pipelineguard-lambda.zip
```

## License

MIT
