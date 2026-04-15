# Pipeline-Check

A CLI tool that scans your AWS CI/CD pipeline against the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) and gives it a score. Currently covers CodeBuild, CodePipeline, CodeDeploy, ECR, IAM, and S3. GCP, GitHub Actions, and Azure Pipelines support is planned.

- [What it checks](#what-it-checks)
- [Installation](#installation)
- [Usage](#usage)
- [Adding a new check](#adding-a-new-aws-check)
- [Adding a new provider](#adding-a-new-provider-gcp-github-azure-)
- [CI / LocalStack integration test](#ci--localstack-integration-test)


![HTML report showing per-check results, severity breakdown, and an overall grade](docs/localstack-report.png)
*HTML report sample generated with `--output html`.*

---

## What it checks

- **CodeBuild** — plaintext secrets, privileged mode, logging, timeouts, image freshness (CB-001–005)
- **CodePipeline** — manual approval gates, KMS encryption, event-driven vs polling triggers (CP-001–003)
- **CodeDeploy** — auto rollback, deployment strategy, CloudWatch alarm monitoring (CD-001–003)
- **ECR** — scan on push, tag immutability, public access, lifecycle policies (ECR-001–004)
- **IAM** — AdministratorAccess, wildcard inline policies, permission boundaries (IAM-001–003)
- **S3** — public access block, encryption, versioning, access logging (S3-001–004)

Findings are scored 0–100 and graded A–D. Exit code `1` when grade is D, so it works as a CI gate.

---

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
        ├── base.py             # Finding dataclass, Severity enum, BaseCheck ABC
        └── aws/
            ├── base.py         # AWSBaseCheck — wires boto3 Session into self.session
            ├── codebuild.py    # CB-001 … CB-005
            ├── codepipeline.py # CP-001 … CP-003
            ├── codedeploy.py   # CD-001 … CD-003
            ├── ecr.py          # ECR-001 … ECR-004
            ├── iam.py          # IAM-001 … IAM-003
            ├── s3.py           # S3-001 … S3-004
            └── rules/          # per-check YAML metadata
                ├── codebuild.yml
                ├── codepipeline.yml
                ├── codedeploy.yml
                ├── ecr.yml
                ├── iam.yml
                └── s3.yml

tests/
├── conftest.py
├── test_cli.py
├── test_json_schema.py
├── test_reporter.py
├── test_scorer.py
└── aws/
    ├── conftest.py
    ├── test_codebuild.py
    ├── test_codepipeline.py
    ├── test_codedeploy.py
    ├── test_ecr.py
    ├── test_iam.py
    ├── test_s3.py
    └── test_owasp_pipeline.py  # end-to-end OWASP coverage test
```
---

## Installation

```bash
git clone https://github.com/your-org/pipeline-check.git
cd pipeline-check
pip install -e .
```
---
## Usage

```bash
# Scan everything in us-east-1
pipeline_check

# Scope to a specific pipeline
pipeline_check --target my-production-pipeline

# Only show HIGH and above
pipeline_check --target my-production-pipeline --severity-threshold HIGH

# Different region, named profile
pipeline_check --pipeline aws --region eu-west-1 --profile my-profile

# Run specific checks only
pipeline_check --checks CB-001 --checks IAM-001

# JSON output (pipe to jq, save as artifact, etc.)
pipeline_check --output json

# HTML report
pipeline_check --output html
pipeline_check --output html --output-file /tmp/report.html

# Terminal + JSON at the same time
pipeline_check --output both
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--pipeline` | `aws` | Pipeline environment: `aws`, `gcp`\*, `github`\*, `azure`\* |
| `--target` | _(all)_ | Scope to a named resource (e.g. a CodePipeline name) |
| `--checks` | _(all)_ | Check ID(s) to run — repeat for multiple |
| `--region` | `us-east-1` | AWS region |
| `--profile` | None | AWS CLI named profile |
| `--output` | `terminal` | `terminal`, `json`, `html`, or `both` |
| `--output-file` | `pipeline-check-report.html` | Output path — only used with `--output html` |
| `--severity-threshold` | `INFO` | Minimum severity to include |

\* GCP, GitHub Actions, and Azure Pipelines support is planned but not yet implemented.

> **`--target` scoping:** CodePipeline fetches only the named pipeline; S3 checks discover the artifact bucket from it. CodeBuild, CodeDeploy, ECR, and IAM still scan the full region — use `--checks` to narrow those further.

> **`--output both`:** The human-readable terminal report is written to **stderr** and the JSON to **stdout**, so you can pipe or redirect them independently:
> ```bash
> pipeline_check --output both 2>report.txt | jq '.score'
> ```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Grade A/B/C |
| `1` | Grade D |
| `2` | AWS API error |
---
## Lambda packaging

```bash
bash scripts/build_lambda.sh
# Output: dist/pipeline_check-lambda.zip
```

Deploy `pipeline_check.lambda_handler.handler` as the handler.

### Environment variables

| Variable | Description |
|---|---|
| `PIPELINE_CHECK_RESULTS_BUCKET` | S3 bucket for JSON reports (stored under `reports/<timestamp>/`) |
| `PIPELINE_CHECK_SNS_TOPIC_ARN` | SNS topic to alert when CRITICAL findings are found |

### Event payload

```json
{ "region": "eu-west-1" }
```

Omit to fall back to `AWS_REGION`.

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
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "codebuild:ListProjects", "codebuild:BatchGetProjects",
      "codepipeline:ListPipelines", "codepipeline:GetPipeline",
      "codedeploy:ListApplications", "codedeploy:ListDeploymentGroups",
      "codedeploy:BatchGetDeploymentGroups",
      "ecr:DescribeRepositories", "ecr:GetRepositoryPolicy", "ecr:GetLifecyclePolicy",
      "iam:ListRoles", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:GetRolePolicy",
      "s3:GetPublicAccessBlock", "s3:GetEncryptionConfiguration",
      "s3:GetBucketVersioning", "s3:GetBucketLogging"
    ],
    "Resource": "*"
  }]
}
```

---
## Check rule files

Each service has a YAML file under `pipeline_check/core/checks/aws/rules/` with metadata for every check it defines:

```yaml
- id: CB-001
  title: Secrets in plaintext environment variables
  severity: CRITICAL
  description: >
    Checks for environment variables whose names match common secret patterns
    stored with type PLAINTEXT...
  recommended_actions:
    - Move secrets to AWS Secrets Manager or SSM Parameter Store.
    - Update the CodeBuild environment variable type to SECRETS_MANAGER or PARAMETER_STORE.
    - Rotate any credentials that may have been exposed in plaintext.
  owasp_cicd: "CICD-SEC-6: Insufficient Credential Hygiene"
```

The HTML reporter picks these up automatically if `pyyaml` is installed. Without it the report still works — it falls back to the descriptions embedded in each `Finding`.

---

## Adding a new AWS check

Only **one file** needs to change after the check module itself is written.

1. Create `pipeline_check/core/checks/aws/<service>.py`:

```python
from .base import AWSBaseCheck, Finding, Severity

class MyServiceChecks(AWSBaseCheck):
    def run(self) -> list[Finding]:
        client = self.session.client("myservice")
        # ...
        return findings
```

2. Register it in **`pipeline_check/core/providers/aws.py`** — the only file that needs to change:

```python
from ..checks.aws.myservice import MyServiceChecks

class AWSProvider(BaseProvider):
    @property
    def check_classes(self):
        return [
            ...,
            MyServiceChecks,   # ← add here
        ]
```

3. Add a rule file at `pipeline_check/core/checks/aws/rules/<service>.yml` (optional — enriches the HTML report).

4. Add tests in `tests/aws/test_myservice.py`.

Check IDs use the format `<PREFIX>-<NNN>` (e.g. `CB-001`). The Scanner and CLI pick up the new check automatically.

---
## Adding a new provider (GCP, GitHub, Azure, …)

Three steps — `scanner.py` and `cli.py` never need to change.

1. Create `pipeline_check/core/providers/<provider>.py` subclassing `BaseProvider`:

```python
from .base import BaseProvider
from ..checks.<provider>.mycheck import MyChecks

class GitHubProvider(BaseProvider):
    NAME = "github"

    def build_context(self, token: str | None = None, **_):
        # Return whatever context your check classes need.
        return {"token": token}

    @property
    def check_classes(self):
        return [MyChecks]
```

2. Register it in `pipeline_check/core/providers/__init__.py`:

```python
from .github import GitHubProvider
register(GitHubProvider())
```

3. Write check modules under `pipeline_check/core/checks/<provider>/` and tests under `tests/<provider>/`.

The new provider is immediately available via `--pipeline github` — the Scanner and CLI derive their choices from the registry.


---

## CI / LocalStack integration test

The `LocalStack Integration Test` workflow (`.github/workflows/localstack-test.yml`) is triggered manually from **Actions → LocalStack Integration Test → Run workflow**. It spins up a LocalStack Pro container, applies the Terraform fixture in `infra/`, runs a full scan against a known-good config and a deliberately bad config, and fails if either assertion fails.

### Required secret

| Secret | Where to get it |
|---|---|
| `LOCALSTACK_AUTH_TOKEN` | [app.localstack.cloud](https://app.localstack.cloud) → CI Auth Tokens |

Add it under **Settings → Secrets and variables → Actions → New repository secret**.

---