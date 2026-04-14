# Pipeline-Check

CI/CD Security Posture Scanner — analyses pipeline configurations and scores.

Currently supports **AWS** [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) through aws cli (CodeBuild, CodePipeline, CodeDeploy, ECR, IAM, S3). Support for **GCP**, **GitHub Actions**, and **Azure Pipelines** is planned.

## Features

- Multi-provider architecture: select your pipeline environment with `--pipeline`
- Scans CodeBuild, CodePipeline, CodeDeploy, ECR, IAM, and S3 (AWS)
- Run targeted scans with `--checks` to focus on specific check IDs
- Scores findings on a 0–100 scale with letter grade (A–D)
- Cross-compatible: same core logic runs as a CLI tool or AWS Lambda function
- Rich terminal output, machine-readable JSON, and self-contained HTML reports
- Per-check YAML rule files with description, severity, and recommended actions
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
    ├── html_reporter.py        # self-contained HTML report
    └── checks/
        ├── base.py             # Finding dataclass, Severity enum, BaseCheck ABC (no cloud SDK imports)
        └── aws/                # AWS-specific checks
            ├── base.py         # AWSBaseCheck — wires boto3 Session into self.session
            ├── codebuild.py    # CB-001 … CB-005
            ├── codepipeline.py # CP-001 … CP-003
            ├── codedeploy.py   # CD-001 … CD-003
            ├── ecr.py          # ECR-001 … ECR-004
            ├── iam.py          # IAM-001 … IAM-003
            ├── s3.py           # S3-001 … S3-004
            └── rules/          # YAML check metadata (id, severity, description, recommended_actions)
                ├── codebuild.yml
                ├── codepipeline.yml
                ├── codedeploy.yml
                ├── ecr.yml
                ├── iam.yml
                └── s3.yml

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

# Generate an HTML report (written to pipelineguard-report.html by default)
pipeline_check --output html

# Write the HTML report to a specific path
pipeline_check --output html --output-file /tmp/report.html

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
| `--output` | `terminal` | `terminal`, `json`, `html`, or `both` |
| `--output-file` | `pipelineguard-report.html` | File path for HTML report (used with `--output html`) |
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

## Check Rule Files

Each AWS service has a YAML file in `pipeline_check/core/checks/aws/rules/` that defines the static metadata for its checks. These are used to enrich the HTML report with structured descriptions and recommended actions.

```yaml
- id: CB-001
  title: Secrets in plaintext environment variables
  severity: CRITICAL
  description: >
    Checks for environment variables whose names match common secret patterns
    that are stored with type PLAINTEXT...
  recommended_actions:
    - Move secrets to AWS Secrets Manager or SSM Parameter Store.
    - Update the CodeBuild environment variable type to SECRETS_MANAGER or PARAMETER_STORE.
    - Rotate any credentials that may have been exposed in plaintext.
  owasp_cicd: "CICD-SEC-6: Insufficient Credential Hygiene"
```

The HTML reporter loads these files automatically when `pyyaml` is installed. Without it the report still renders fully — it uses the dynamic descriptions embedded in each `Finding`.

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

3. Add a rule file at `pipeline_check/core/checks/aws/rules/<service>.yml` with an entry for each check ID (see [Check Rule Files](#check-rule-files) above).

4. Add tests in `tests/aws/test_myservice.py`.

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
