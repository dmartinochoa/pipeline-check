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

Covered surfaces (**79 checks** total: 32 AWS + 8 GitHub Actions + 9 GitLab CI + 9 Bitbucket Pipelines + 9 Azure DevOps Pipelines + 12 Jenkins, severity-weighted):

| Service             | Focus                                                                                              | IDs              |
|---------------------|----------------------------------------------------------------------------------------------------|------------------|
| CodeBuild           | Plaintext secrets, privileged mode, logging, timeouts, image freshness, long-lived source tokens, webhook filter groups | `CB-001…007`     |
| CodePipeline        | Manual approval gates, KMS encryption, event-driven triggers, legacy ThirdParty/GitHub OAuth       | `CP-001…004`     |
| CodeDeploy          | Auto rollback, deployment strategy, CloudWatch alarm monitoring                                    | `CD-001…003`     |
| ECR                 | Scan-on-push, tag immutability, public access, lifecycle policies, KMS CMK encryption              | `ECR-001…005`    |
| IAM                 | `AdministratorAccess`, wildcard actions, permission boundaries, `iam:PassRole *`, external trust without `sts:ExternalId`, sensitive actions with `Resource:*` | `IAM-001…006`    |
| PBAC                | Build project VPC isolation, service-role sharing                                                  | `PBAC-001…002`   |
| S3                  | Public access block, encryption, versioning, access logging, `aws:SecureTransport` deny            | `S3-001…005`     |
| GitHub Actions      | Unpinned actions, `pull_request_target` head-checkout, script injection, missing permissions blocks, long-lived AWS keys, artifact signing, SBOM generation, credential-shaped literals | `GHA-001…008`    |
| GitLab CI           | Image pinning, script injection via `$CI_COMMIT_*`, literal secrets in `variables:`, deploy gating, `include:` pinning, artifact signing, SBOM generation, credential-shaped literals, sha256-digest image pinning | `GL-001…009`     |
| Bitbucket Pipelines | `pipe:` pinning, injection via `$BITBUCKET_*`, literal secrets, `deployment:` gating, unbounded `max-time`, artifact signing, SBOM generation, credential-shaped literals, sha256-digest pipe pinning | `BB-001…009`     |
| Azure DevOps Pipelines | `task:` pinning, injection via `$(Build.SourceBranch*)` / PR vars, literal secrets, `environment:` binding, container image pinning, artifact signing, SBOM generation, credential-shaped literals, sha256-digest container pinning | `ADO-001…009`    |
| Jenkins             | `@Library` pinning, injection via `$BRANCH_NAME` / `$CHANGE_*`, `agent any` blast radius, long-lived AWS keys via `withCredentials` and `environment {}`, deploy `input` gate, artifact signing, SBOM generation, credential-shaped literals, docker-agent digest pinning, `buildDiscarder` retention, dynamic `load` of Groovy from disk | `JF-001…012`     |

Cross-cutting capabilities layered on top:

- **Autofix** — `--fix` emits a unified-diff patch (pipe to `git apply`)
  or `--fix --apply` writes in place. Ships fixers for GHA-002
  (`persist-credentials`), GHA-004 (permissions block), and GHA-008
  (redact + TODO marker for literal secrets).
- **Diff-mode scanning** — `--diff-base REF` scans only workflow /
  terraform resources touched by the branch, keyed off `git diff`.
- **Baselines from git** — `--baseline-from-git REF:PATH` resolves a
  prior scan's JSON via `git show`, so you don't need to carry it as
  a CI artifact.
- **Custom secret detectors** — `--secret-pattern '^acme_...$'` extends
  the `*-008` secret scanner with org-specific token shapes.
- **Glob check selection** — `--checks 'GHA-*'`, `--checks '*-008'`.
- **Standard audit** — `--standard-report NAME` prints the
  control → check matrix plus any unmapped gaps, turning the tool
  into a compliance-coverage explorer.
- **Config validation** — `--config-check` parses `.pipeline-check.yml` /
  `pyproject.toml` and exits non-zero on any unknown key so CI catches
  typos in repo policy.

Every finding is tagged with the compliance controls it evidences — eight
frameworks are shipped: OWASP Top 10 CI/CD, CIS AWS Foundations, CIS
Software Supply Chain, NIST SSDF (SP 800-218), NIST SP 800-53, SLSA Build
Track, PCI DSS v4.0, and NSA/CISA ESF Software Supply Chain (see
[Compliance standards](#compliance-standards)).
Findings are scored 0–100 and graded A–D. Exit code is `1` when the grade
is D, so `pipeline_check` works as a CI gate.

Supported providers: **AWS** (live, via boto3), **Terraform** (plan
JSON), **GitHub Actions**, **GitLab CI**, **Bitbucket Pipelines**,
**Azure DevOps Pipelines** (all YAML), and **Jenkins** (Declarative
or Scripted Pipeline text — no Groovy interpreter, no controller
access). All providers run without an API token.

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

# Scan a GitLab CI config (--gitlab-path auto-detected if .gitlab-ci.yml is at cwd)
pipeline_check --pipeline gitlab

# Scan a Bitbucket Pipelines config (--bitbucket-path auto-detected)
pipeline_check --pipeline bitbucket

# Scan an Azure DevOps pipeline (--azure-path auto-detected)
pipeline_check --pipeline azure

# Scan a Jenkinsfile (--jenkinsfile-path auto-detected if ./Jenkinsfile exists)
pipeline_check --pipeline jenkins

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

# HTML report — --output-file is required, includes client-side filters
pipeline_check --output html --output-file /tmp/report.html

# SARIF 2.1.0 — upload directly to GitHub code-scanning
pipeline_check --pipeline github --gha-path .github/workflows \
    --output sarif --output-file pipeline-check.sarif

# Terminal + JSON at the same time
pipeline_check --output both

# Scope to workflows the branch actually touches
pipeline_check --pipeline github --diff-base origin/main

# Glob check selection
pipeline_check --pipeline github --checks 'GHA-*'   # every GitHub check
pipeline_check --pipeline github --checks '*-008'   # every secret-scan check

# Emit fix patches, or apply them in place
pipeline_check --pipeline github --fix | git apply
pipeline_check --pipeline github --fix --apply

# Extend the secret-scanning detectors with an org-specific pattern
pipeline_check --pipeline github --secret-pattern '^acme_[a-f0-9]{32}$'

# Audit a standard: print its control→check matrix + any unmapped gaps
pipeline_check --standard-report nist_ssdf

# Validate the repo's pipeline_check config (exits non-zero on unknown keys)
pipeline_check --config-check
```

### Config file

Every flag can be set in `pyproject.toml` so CI stays short and repo
policy lives with the code:

```toml
[tool.pipeline_check]
pipeline = "aws"
standards = ["owasp_cicd_top_10", "nist_ssdf"]
output = "sarif"
output_file = "pipeline-check.sarif"

[tool.pipeline_check.gate]
fail_on = "HIGH"
baseline = "artifacts/baseline.json"
ignore_file = ".pipelinecheckignore"
```

Also supports `.pipeline-check.yml` and `PIPELINE_CHECK_*` env vars.
Precedence: CLI > env > file > defaults. Full reference:
[docs/config.md](docs/config.md).

### Options

| Flag                    | Default                       | Description                                                   |
|-------------------------|-------------------------------|---------------------------------------------------------------|
| `--config`              | _(auto)_                      | Config file (TOML or YAML); auto-discovers `.pipeline-check.yml` or `[tool.pipeline_check]` in `pyproject.toml` |
| `--pipeline`            | `aws`                         | Provider: `aws`, `terraform`, `github`, `gitlab`, `bitbucket`, `azure`, `jenkins` |
| `--tf-plan`             | _(none)_                      | Path to `terraform show -json` output (required with `--pipeline terraform`) |
| `--gha-path`            | _(auto: `.github/workflows`)_ | Path to workflows dir; auto-detected from cwd when omitted     |
| `--gitlab-path`         | _(auto: `.gitlab-ci.yml`)_    | Path to `.gitlab-ci.yml`; auto-detected from cwd when omitted  |
| `--bitbucket-path`      | _(auto: `bitbucket-pipelines.yml`)_ | Path to `bitbucket-pipelines.yml`; auto-detected from cwd |
| `--azure-path`          | _(auto: `azure-pipelines.yml`)_ | Path to `azure-pipelines.yml`; auto-detected from cwd       |
| `--jenkinsfile-path`    | _(auto: `Jenkinsfile`)_       | Path to a Jenkinsfile (or directory); auto-detected from cwd  |
| `--target`              | _(all)_                       | Scope to a named resource (e.g. a CodePipeline name)          |
| `--checks`              | _(all)_                       | Check ID(s) to run — repeat for multiple                      |
| `--standard`            | _(all registered)_            | Compliance standard(s) to annotate findings with              |
| `--list-standards`      | _(flag)_                      | Print every registered standard and exit                      |
| `--man`                 | _(flag, optional TOPIC)_      | Print extended documentation for TOPIC and exit. `--man` alone lists topics. Topics: `gate`, `autofix`, `diff`, `secrets`, `standards`, `config`, `output`, `lambda`, `recipes`. |
| `--region`              | `us-east-1`                   | AWS region                                                    |
| `--profile`             | _(env)_                       | AWS CLI named profile                                         |
| `--output`              | `terminal`                    | `terminal`, `json`, `html`, `sarif`, or `both`                |
| `--output-file`         | _(none)_                      | Output path — **required** with `--output html`; optional with `--output sarif` |
| `--severity-threshold`  | `INFO`                        | Minimum severity to include in the report                     |
| `--fail-on`             | _(unset)_                     | Gate: fail if any finding ≥ this severity                     |
| `--min-grade`           | _(unset)_                     | Gate: fail if grade is worse than this (A/B/C/D)              |
| `--max-failures`        | _(unset)_                     | Gate: fail if more than N effective failing findings          |
| `--fail-on-check`       | _(unset)_                     | Gate: fail if named check fails (repeat for multiple)         |
| `--baseline`            | _(none)_                      | Prior JSON report — findings already there don't gate         |
| `--baseline-from-git`   | _(none)_                      | Resolve the baseline via `git show REF:PATH` instead of a file |
| `--ignore-file`         | `.pipelinecheckignore`        | Curated suppressions (flat format or YAML with `expires`)     |
| `--diff-base`           | _(none)_                      | Scan only workflow / terraform resources changed vs this git ref; AWS errors out |
| `--fix`                 | _(flag)_                      | Emit autofix patches to stdout (pipe to `git apply`)          |
| `--apply`               | _(flag)_                      | With `--fix`, write patches in place instead of printing them |
| `--secret-pattern`      | _(none, repeat)_              | Extra regex for the `*-008` secret-scan checks                |
| `--standard-report`     | _(none)_                      | Print the control→check matrix for a standard and exit        |
| `--config-check`        | _(flag)_                      | Parse the config, report unknown keys, exit non-zero on any   |
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

### CI gate

By default, `pipeline_check` exits `1` if any **CRITICAL** finding is
present after baseline + ignore-file filtering (equivalent to `--fail-on
CRITICAL`). For finer control, set explicit gate conditions — any
tripped condition fails the gate:

```bash
# Block CRITICAL only
pipeline_check --pipeline aws --fail-on CRITICAL

# Require a B-or-better grade
pipeline_check --pipeline aws --min-grade B

# Zero-tolerance on specific checks
pipeline_check --pipeline github --gha-path .github/workflows \
    --fail-on-check GHA-002 --fail-on-check GHA-005

# Only block on NEW findings (baseline diff)
pipeline_check --pipeline aws --output json > baseline.json      # once
pipeline_check --pipeline aws --fail-on HIGH --baseline baseline.json  # per-PR

# Curated suppressions — `.pipelinecheckignore` picked up automatically
echo "CB-001:my-legacy-project" >> .pipelinecheckignore
pipeline_check --pipeline aws --fail-on HIGH
```

A short `[gate] PASS/FAIL` summary is emitted to stderr on every run.
Full reference: [docs/ci_gate.md](docs/ci_gate.md).

### Exit codes

| Code | Meaning                                                 |
|------|---------------------------------------------------------|
| `0`  | Gate passed                                             |
| `1`  | Gate failed                                             |
| `2`  | Scanner error (stack trace printed to stderr)           |
| `3`  | `--config-check` found unknown config keys              |

See [docs/scoring_model.md](docs/scoring_model.md) for the severity
weights and grade bands feeding `--min-grade`.

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
| `esf_supply_chain`    | NSA/CISA ESF — Securing the Software Supply Chain | 2022  | [docs/standards/esf_supply_chain.md](docs/standards/esf_supply_chain.md)       |

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
    │       ├── pci_dss_v4.py
    │       └── esf_supply_chain.py
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

Single-region, single-provider (legacy shape):

```json
{ "region": "eu-west-1" }
```

Multi-region / multi-provider fan-out (one invocation, one aggregated
result):

```json
{
  "regions":   ["us-east-1", "eu-west-1"],
  "providers": ["aws"]
}
```

Omit both to fall back to `AWS_REGION`. The handler accepts per-
provider kwargs (`tf_plan`, `gha_path`, `gitlab_path`, `bitbucket_path`,
`azure_path`, `target`, `profile`) alongside `region` / `provider` for
non-AWS providers.

### Return value

Single-scan shape:

```json
{
  "statusCode": 200,
  "grade": "B",
  "score": 78,
  "total_findings": 22,
  "critical_failures": 0,
  "report_s3_key": "reports/20240501T120000Z/pipeline_check-report.json",
  "report_s3_status": "ok"
}
```

`report_s3_status` is one of `"ok"`, `"unconfigured"`
(`PIPELINE_CHECK_RESULTS_BUCKET` unset), or `"error"` (put_object
failed — see CloudWatch logs).

Fan-out shape:

```json
{
  "statusCode": 200,
  "scans": [
    {"region": "us-east-1", "provider": "aws", "grade": "A", "score": 92, ...},
    {"region": "eu-west-1", "provider": "aws", "error": "ClientError: ..."}
  ],
  "worst_grade": "D",
  "total_critical_failures": 3
}
```

A per-scan exception produces an error entry instead of aborting the
whole invocation; `worst_grade` is forced to `D` when any scan fails.

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

### Adding a new provider (Jenkins, Azure Pipelines, …)

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
