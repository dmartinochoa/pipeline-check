<div align="center">

# Pipeline-Check

**A CI/CD security posture scanner.**

Pipeline-Check audits your CI/CD build, deploy, and artifact infrastructure
against well-known compliance standards and scores it A–D, so you can gate
pipelines on the result. It can scan a **live AWS account** via boto3, a
**Terraform plan** (`terraform show -json`) before any resource is
provisioned, or CI definition YAML for **GitHub Actions**, **GitLab CI**,
and **Bitbucket Pipelines** — all without an API token.

[What it checks](#what-it-checks) ·
[Installation](#installation) ·
[Usage](#usage) ·
[Compliance standards](#compliance-standards) ·
[Extending](#extending) ·
[CI / LocalStack](#ci--localstack-integration-test)

![HTML report showing per-check results, severity breakdown, and an overall grade](resources/img/localstack-report.png)

<sub><em>HTML report sample — generated with <code>--output html</code>.</em></sub>

</div>

---

## What it checks

Covered surfaces (**47 checks** total: 32 AWS + 5 GitHub Actions + 5 GitLab CI + 5 Bitbucket Pipelines, severity-weighted):

| Service             | Focus                                                                                              | IDs              |
|---------------------|----------------------------------------------------------------------------------------------------|------------------|
| CodeBuild           | Plaintext secrets, privileged mode, logging, timeouts, image freshness, long-lived source tokens, webhook filter groups | `CB-001…007`     |
| CodePipeline        | Manual approval gates, KMS encryption, event-driven triggers, legacy ThirdParty/GitHub OAuth       | `CP-001…004`     |
| CodeDeploy          | Auto rollback, deployment strategy, CloudWatch alarm monitoring                                    | `CD-001…003`     |
| ECR                 | Scan-on-push, tag immutability, public access, lifecycle policies, KMS CMK encryption              | `ECR-001…005`    |
| IAM                 | `AdministratorAccess`, wildcard actions, permission boundaries, `iam:PassRole *`, external trust without `sts:ExternalId`, sensitive actions with `Resource:*` | `IAM-001…006`    |
| PBAC                | Build project VPC isolation, service-role sharing                                                  | `PBAC-001…002`   |
| S3                  | Public access block, encryption, versioning, access logging, `aws:SecureTransport` deny            | `S3-001…005`     |
| GitHub Actions      | Unpinned actions, `pull_request_target` head-checkout, script injection, missing permissions blocks, long-lived AWS keys | `GHA-001…005`    |
| GitLab CI           | Image pinning, script injection via `$CI_COMMIT_*`, literal secrets in `variables:`, deploy gating, `include:` pinning | `GL-001…005`     |
| Bitbucket Pipelines | `pipe:` pinning, injection via `$BITBUCKET_*`, literal secrets, `deployment:` gating, unbounded `max-time` | `BB-001…005`     |

Every finding is tagged with the compliance controls it evidences — seven
frameworks are shipped: OWASP Top 10 CI/CD, CIS AWS Foundations, CIS
Software Supply Chain, NIST SSDF (SP 800-218), NIST SP 800-53, SLSA Build
Track, and PCI DSS v4.0 (see [Compliance standards](#compliance-standards)).
Findings are scored 0–100 and graded A–D. Exit code is `1` when the grade
is D, so `pipeline_check` works as a CI gate.

Supported providers: **AWS** (live, via boto3), **Terraform** (plan JSON),
**GitHub Actions**, **GitLab CI**, and **Bitbucket Pipelines** (all YAML
— no API token required). Planned: **Azure Pipelines**, **Jenkins**.

---

## Installation

```bash
git clone https://github.com/your-org/pipeline-check.git
cd pipeline-check
pip install -e .
```

Python ≥ 3.10 is required. Credentials are picked up from the standard AWS
chain (`~/.aws/credentials`, env vars, instance profile, SSO).

---

## Usage

```bash
# Scan a Terraform plan before provisioning (no AWS creds needed)
terraform plan -out=tfplan && terraform show -json tfplan > plan.json
pipeline_check --pipeline terraform --tf-plan plan.json

# Scan GitHub Actions workflows (no network calls, no API token needed)
pipeline_check --pipeline github --gha-path .github/workflows

# Scan a GitLab CI config
pipeline_check --pipeline gitlab --gitlab-path .gitlab-ci.yml

# Scan a Bitbucket Pipelines config
pipeline_check --pipeline bitbucket --bitbucket-path bitbucket-pipelines.yml

# Scan everything in us-east-1 (live AWS account)
pipeline_check

# Scope to a specific pipeline
pipeline_check --target my-production-pipeline

# Only show HIGH and above
pipeline_check --target my-production-pipeline --severity-threshold HIGH

# Different region, named profile
pipeline_check --pipeline aws --region eu-west-1 --profile my-profile

# Run specific checks only
pipeline_check --checks CB-001 --checks IAM-001

# Restrict to a single compliance standard
pipeline_check --standard owasp_cicd_top_10

# List every registered standard
pipeline_check --list-standards

# JSON output (pipe to jq, save as artifact, etc.)
pipeline_check --output json

# HTML report
pipeline_check --output html --output-file /tmp/report.html

# SARIF 2.1.0 — upload directly to GitHub code-scanning
pipeline_check --pipeline github --gha-path .github/workflows \
    --output sarif --output-file pipeline-check.sarif

# Terminal + JSON at the same time
pipeline_check --output both
```

### Options

| Flag                    | Default                       | Description                                                   |
|-------------------------|-------------------------------|---------------------------------------------------------------|
| `--pipeline`            | `aws`                         | Provider: `aws`, `terraform`, `github`, `gitlab`, `bitbucket` |
| `--tf-plan`             | _(none)_                      | Path to `terraform show -json` output (required with `--pipeline terraform`) |
| `--gha-path`            | _(none)_                      | Path to workflows dir (required with `--pipeline github`)      |
| `--gitlab-path`         | _(none)_                      | Path to `.gitlab-ci.yml` (required with `--pipeline gitlab`)   |
| `--bitbucket-path`      | _(none)_                      | Path to `bitbucket-pipelines.yml` (required with `--pipeline bitbucket`) |
| `--target`              | _(all)_                       | Scope to a named resource (e.g. a CodePipeline name)          |
| `--checks`              | _(all)_                       | Check ID(s) to run — repeat for multiple                      |
| `--standard`            | _(all registered)_            | Compliance standard(s) to annotate findings with              |
| `--list-standards`      | _(flag)_                      | Print every registered standard and exit                      |
| `--region`              | `us-east-1`                   | AWS region                                                    |
| `--profile`             | _(env)_                       | AWS CLI named profile                                         |
| `--output`              | `terminal`                    | `terminal`, `json`, `html`, `sarif`, or `both`                |
| `--output-file`         | _(provider-specific default)_ | Output path — used with `--output html` or `--output sarif`   |
| `--severity-threshold`  | `INFO`                        | Minimum severity to include                                   |
| `--version`             | _(flag)_                      | Print version and exit                                        |

`--tf-plan`, `--gha-path`, `--gitlab-path`, and `--bitbucket-path` are
validated eagerly: the CLI exits with `UsageError` if the flag is missing
for its provider or if the path does not exist on disk.

> **`--target` scoping:** CodePipeline fetches only the named pipeline;
> S3 checks discover the artifact bucket from it. CodeBuild, CodeDeploy,
> ECR, and IAM still scan the full region — use `--checks` to narrow those.

> **`--output both`:** the terminal report is written to **stderr** and the
> JSON to **stdout**, so you can pipe or redirect them independently:
> ```bash
> pipeline_check --output both 2>report.txt | jq '.score'
> ```

### Exit codes

| Code | Meaning        |
|------|----------------|
| `0`  | Grade A/B/C    |
| `1`  | Grade D        |
| `2`  | AWS API error  |

See [docs/scoring_model.md](docs/scoring_model.md) for the full severity
weights and grade bands.

---

## Compliance standards

Every finding is enriched post-scan with a list of `ControlRef` objects —
references to controls in registered compliance standards. A single check
can evidence controls in multiple standards at once, so one scan satisfies
multiple frameworks.

| Name                  | Title                                   | Version         | Docs                                                                           |
|-----------------------|-----------------------------------------|-----------------|--------------------------------------------------------------------------------|
| `owasp_cicd_top_10`   | OWASP Top 10 CI/CD Security Risks       | 2022            | [docs/standards/owasp_cicd_top_10.md](docs/standards/owasp_cicd_top_10.md)     |
| `cis_aws_foundations` | CIS AWS Foundations Benchmark (subset)  | 3.0.0           | [docs/standards/cis_aws_foundations.md](docs/standards/cis_aws_foundations.md) |
| `cis_supply_chain`    | CIS Software Supply Chain Security Guide| 1.0             | [docs/standards/cis_supply_chain.md](docs/standards/cis_supply_chain.md)       |
| `nist_ssdf`           | NIST Secure Software Development Framework | SP 800-218 v1.1 | [docs/standards/nist_ssdf.md](docs/standards/nist_ssdf.md)                  |
| `nist_800_53`         | NIST SP 800-53 Rev. 5 (CI/CD subset)    | Rev. 5          | [docs/standards/nist_800_53.md](docs/standards/nist_800_53.md)                 |
| `slsa`                | SLSA Build Track                        | 1.0             | [docs/standards/slsa.md](docs/standards/slsa.md)                               |
| `pci_dss_v4`          | PCI DSS v4.0 (CI/CD subset)             | 4.0             | [docs/standards/pci_dss_v4.md](docs/standards/pci_dss_v4.md)                   |

Standards are pure data — each one is a Python module under
`pipeline_check/core/standards/data/` that declares its controls and a
`check_id → [control_id, …]` mapping. Adding SOC 2 or a bespoke internal
policy is one new module; see
[docs/standards/README.md](docs/standards/README.md) for the full contract.

---

## Architecture

```
pipeline_check/
├── cli.py                         # click CLI entry point
├── lambda_handler.py              # AWS Lambda entry point
└── core/
    ├── scanner.py                 # provider-agnostic orchestrator
    ├── scorer.py                  # weighted scoring + grading
    ├── reporter.py                # terminal (rich) + JSON output
    ├── html_reporter.py           # self-contained HTML report
    ├── sarif_reporter.py          # SARIF 2.1.0 output
    ├── providers/                 # provider registry
    │   ├── base.py                # BaseProvider ABC
    │   ├── aws.py                 # boto3-backed provider
    │   ├── terraform.py           # plan-JSON provider
    │   ├── github.py              # GitHub Actions workflow-YAML provider
    │   ├── gitlab.py              # GitLab CI YAML provider
    │   └── bitbucket.py           # Bitbucket Pipelines YAML provider
    ├── standards/                 # compliance standards (data-driven)
    │   ├── base.py                # ControlRef + Standard dataclasses
    │   ├── registry.py            # register / get / resolve
    │   └── data/
    │       ├── owasp_cicd_top_10.py
    │       ├── cis_aws_foundations.py
    │       ├── cis_supply_chain.py
    │       ├── nist_ssdf.py
    │       ├── nist_800_53.py
    │       ├── slsa.py
    │       └── pci_dss_v4.py
    └── checks/
        ├── base.py                # Finding dataclass, Severity enum, BaseCheck ABC
        ├── aws/                   # live-account provider (boto3)
        │   ├── base.py            # AWSBaseCheck — wires boto3 Session
        │   ├── codebuild.py       # CB-001 … CB-007
        │   ├── codepipeline.py    # CP-001 … CP-004
        │   ├── codedeploy.py      # CD-001 … CD-003
        │   ├── ecr.py             # ECR-001 … ECR-005
        │   ├── iam.py             # IAM-001 … IAM-006
        │   ├── pbac.py            # PBAC-001 … PBAC-002
        │   ├── s3.py              # S3-001 … S3-005
        │   └── rules/             # per-check YAML metadata for HTML report
        ├── terraform/             # plan-JSON provider (same check IDs)
        │   ├── base.py            # TerraformContext + TerraformBaseCheck
        │   ├── codebuild.py
        │   ├── codepipeline.py
        │   ├── codedeploy.py
        │   ├── ecr.py
        │   ├── iam.py
        │   ├── pbac.py
        │   └── s3.py
        ├── github/                # GitHub Actions workflow-YAML provider
        │   ├── base.py            # GitHubContext + Workflow loader
        │   └── workflows.py       # GHA-001 … GHA-005
        ├── gitlab/                # GitLab CI YAML provider
        │   ├── base.py            # GitLabContext + Pipeline loader
        │   └── pipelines.py       # GL-001 … GL-005
        └── bitbucket/             # Bitbucket Pipelines YAML provider
            ├── base.py            # BitbucketContext + step walker
            └── pipelines.py       # BB-001 … BB-005
```

See [docs/providers/](docs/providers/) for the provider catalogue and
[docs/standards/](docs/standards/) for the compliance matrices.

---

## Lambda packaging

```bash
bash scripts/build_lambda.sh
# Output: dist/pipeline_check-lambda.zip
```

Deploy `pipeline_check.lambda_handler.handler` as the handler.

### Environment variables

| Variable                         | Description                                                         |
|----------------------------------|---------------------------------------------------------------------|
| `PIPELINE_CHECK_RESULTS_BUCKET`  | S3 bucket for JSON reports (stored under `reports/<timestamp>/`)    |
| `PIPELINE_CHECK_SNS_TOPIC_ARN`   | SNS topic alerted when CRITICAL findings are detected               |

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
      "codebuild:ListSourceCredentials",
      "codepipeline:ListPipelines", "codepipeline:GetPipeline",
      "codedeploy:ListApplications", "codedeploy:ListDeploymentGroups",
      "codedeploy:BatchGetDeploymentGroups",
      "ecr:DescribeRepositories", "ecr:GetRepositoryPolicy", "ecr:GetLifecyclePolicy",
      "iam:ListRoles", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:GetRolePolicy",
      "s3:GetPublicAccessBlock", "s3:GetEncryptionConfiguration",
      "s3:GetBucketVersioning", "s3:GetBucketLogging", "s3:GetBucketPolicy"
    ],
    "Resource": "*"
  }]
}
```

---

## Extending

### Adding a new AWS check

1. Create `pipeline_check/core/checks/aws/<service>.py`:

    ```python
    from .base import AWSBaseCheck, Finding, Severity

    class MyServiceChecks(AWSBaseCheck):
        def run(self) -> list[Finding]:
            # self.client() caches clients on the shared session so
            # repeat lookups across modules are free.
            client = self.client("myservice")
            ...
            return findings
    ```

2. Register it in `pipeline_check/core/providers/aws.py` by appending the
   class to `check_classes`.
3. (Optional) Add rule metadata at
   `pipeline_check/core/checks/aws/rules/<service>.yml` to enrich the HTML
   report.
4. Add unit tests in `tests/aws/test_<service>.py`.
5. Add mappings for the new check IDs in the relevant standard file under
   `pipeline_check/core/standards/data/`.

Check IDs use the format `<PREFIX>-<NNN>` (e.g. `CB-001`). The Scanner,
CLI, and reporters pick up the new check automatically.

### Adding a new provider (GCP, GitHub, Azure, …)

1. Create `pipeline_check/core/providers/<provider>.py` subclassing
   `BaseProvider`, set `NAME`, and implement `build_context()` and
   `check_classes`.
2. Register it in `pipeline_check/core/providers/__init__.py`.
3. Add check modules under `pipeline_check/core/checks/<provider>/` and
   tests under `tests/<provider>/`.

The new provider becomes available via `--pipeline <name>` without
touching `scanner.py` or `cli.py`. See [docs/providers/README.md](docs/providers/README.md).

### Adding a new compliance standard

Create one Python module under `pipeline_check/core/standards/data/`:

```python
from ..base import Standard

STANDARD = Standard(
    name="soc2_trust_services",
    title="SOC 2 Trust Services Criteria",
    version="2017",
    url="https://www.aicpa-cima.com/...",
    controls={"CC6.1": "Logical access controls", ...},
    mappings={
        "IAM-001": ["CC6.1"],
        "S3-001":  ["CC6.1"],
        ...
    },
)
```

Register it in `pipeline_check/core/standards/__init__.py`. The CLI
(`--standard`, `--list-standards`) and reporters pick it up automatically.

---

## CI / LocalStack integration test

The `LocalStack Integration Test` workflow
(`.github/workflows/localstack-test.yml`) runs manually from
**Actions → LocalStack Integration Test → Run workflow**. It consists of
two independent jobs:

1. **`pytest-integration`** — boots its own LocalStack, creates resources
   directly via `boto3`, runs the pytest suite under `tests/integration/`,
   and tears everything down.
2. **`terraform-fixture`** — boots a separate LocalStack, applies the
   Terraform fixtures in `infra/` (good and bad), runs the CLI against
   both, and asserts the expected grades and check failures.

### Required secret

| Secret                     | Where to get it                                                              |
|----------------------------|------------------------------------------------------------------------------|
| `LOCALSTACK_AUTH_TOKEN`    | [app.localstack.cloud](https://app.localstack.cloud) → CI Auth Tokens        |

Add it under **Settings → Secrets and variables → Actions → New repository secret**.

---

## License

MIT — see [LICENSE](LICENSE).
