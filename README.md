<div align="center">

# Pipeline-Check

**Find security risks in your CI/CD pipelines before attackers do.**

Scans CI/CD configurations against the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) and twelve other compliance frameworks. Scores findings A--D so you can gate merges on the result.

**283 checks** across **10 providers** -- mapped to **13 compliance standards** -- with **68 autofixers** -- plus **8 attack chains** correlating findings into MITRE ATT&CK-mapped kill chains

[Quick start](#quick-start) |
[Providers](#supported-providers) |
[How it works](#how-it-works) |
[CI integration](#ci-integration) |
[Compliance](#compliance-standards) |
[Docs](docs/)

</div>

---

## Quick start

```bash
pip install pipeline-check          # Python >= 3.10

pipeline_check                      # auto-detects the provider from cwd
pipeline_check init                 # scaffold .pipeline-check.yml
pipeline_check -p github -o json    # short flags work too
pipeline_check --pipeline aws       # force the live-AWS scan
```

Run `pipeline_check` with no flags in any supported repo — it inspects
the working directory (`.github/workflows/`, `.gitlab-ci.yml`,
`Jenkinsfile`, `cloudbuild.yaml`, `template.yml`, …), picks the matching
provider, and falls back to `aws` when nothing recognisable is found.

No API tokens required. CI configs are parsed from disk; AWS uses the
standard boto3 credential chain.

---

## Supported providers

| Provider | Input | Auto-detect | Checks |
|----------|-------|-------------|--------|
| **AWS** | Live account via boto3 | `--region` | 72 checks (CodeBuild, CodePipeline, CodeDeploy, ECR, IAM, PBAC, S3, CloudTrail, CloudWatch Logs, Secrets Manager, CodeArtifact, CodeCommit, Lambda, KMS, SSM, EventBridge, Signer) |
| **Terraform** | `terraform show -json` plan | `--tf-plan` | AWS-parity shift-left checks, pre-provisioning |
| **CloudFormation** | YAML or JSON template | `--cfn-template` | ~63 AWS-parity shift-left checks; handles `!Ref`/`!Sub`/`!GetAtt` intrinsics (treats unresolved values as strict) |
| **GitHub Actions** | `.github/workflows/*.yml` | `--gha-path` | 29 checks (`GHA-001`--`029`) |
| **GitLab CI** | `.gitlab-ci.yml` | `--gitlab-path` | 30 checks (`GL-001`--`030`) |
| **Bitbucket Pipelines** | `bitbucket-pipelines.yml` | `--bitbucket-path` | 27 checks (`BB-001`--`027`) |
| **Azure DevOps** | `azure-pipelines.yml` | `--azure-path` | 28 checks (`ADO-001`--`028`) |
| **Jenkins** | `Jenkinsfile` (Declarative/Scripted) | `--jenkinsfile-path` | 31 checks (`JF-001`--`031`) |
| **CircleCI** | `.circleci/config.yml` | `--circleci-path` | 30 checks (`CC-001`--`030`) |
| **Google Cloud Build** | `cloudbuild.yaml` | `--cloudbuild-path` | 15 checks (`GCB-001`--`015`) |

Each CI provider checks for: dependency pinning, script injection, credential
leaks, deploy approval gates, artifact signing, SBOM generation, Docker
security, package integrity, timeout enforcement, vulnerability scanning, TLS
verification, and more. See [docs/providers/](docs/providers/) for the full
per-check reference.

---

## How it works

```
                 +-----------+
  Config files   |  Scanner  |   283 checks across 10 providers
  or live APIs ---->         +---> Findings (check_id, severity, resource)
                 +-----------+
                       |
                 +-----------+
                 |  Scorer   |   Severity-weighted: CRITICAL=20, HIGH=10, MED=5, LOW=2
                 |           +---> Score 0-100, Grade A/B/C/D
                 +-----------+
                       |
                 +-----------+
                 |   Gate    |   --fail-on, --min-grade, --max-failures, --baseline
                 |           +---> Exit 0 (pass) or 1 (fail)
                 +-----------+
                       |
                 +-----------+
                 | Reporter  |   Terminal, JSON, HTML, SARIF 2.1.0
                 +-----------+
```

Every finding is annotated with compliance controls from all enabled
standards, so a single scan satisfies multiple audit frameworks.

---

## Key features

| Feature | Description |
|---------|-------------|
| **Autofix** | `--fix` emits unified-diff patches; `--fix --apply` writes in place. 67 fixers cover script injection, secrets, timeouts, pinning, Docker flags, TLS, and more. |
| **CI gate** | `--fail-on HIGH`, `--min-grade B`, `--max-failures 5`, `--fail-on-check GHA-002`. Any condition trips exit 1. |
| **Baselines** | `--baseline prior.json` or `--baseline-from-git origin/main:report.json` -- only gate on *new* findings. |
| **Diff-mode** | `--diff-base origin/main` scans only files changed by the branch. |
| **Suppressions** | `.pipelinecheckignore` (flat or YAML with `expires:` dates). |
| **Custom secrets** | `--secret-pattern '^acme_[a-f0-9]{32}$'` extends the credential scanner. |
| **Glob selection** | `--checks 'GHA-*'` or `--checks '*-008'` to scope checks. |
| **Standard audit** | `--standard-report nist_ssdf` prints the control-to-check matrix and coverage gaps. |
| **Component inventory** | `--inventory` emits the list of resources / workflows / templates the scanner discovered, with per-type metadata (encryption, runtime, tags, lifecycle policies). Filter with `--inventory-type 'AWS::IAM::*'`; skip checks entirely with `--inventory-only`. Feeds asset-register dashboards and drift detectors. |

---

## Output formats

```bash
pipeline_check --output terminal            # rich table to stdout (default)
pipeline_check --output json                # machine-readable JSON
pipeline_check --output html --output-file report.html  # self-contained HTML
pipeline_check --output sarif --output-file scan.sarif  # SARIF 2.1.0 for GitHub/GitLab
pipeline_check --output both                # terminal on stderr + JSON on stdout
```

---

## CI integration

### GitHub Actions

```yaml
- name: Scan CI/CD security posture
  run: |
    pip install pipeline-check
    pipeline_check --pipeline github \
      --output sarif --output-file pipeline-check.sarif \
      --fail-on HIGH

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pipeline-check.sarif
```

### GitLab CI

```yaml
security-scan:
  script:
    - pip install pipeline-check
    - pipeline_check --pipeline gitlab --fail-on HIGH --output json > report.json
  artifacts:
    reports:
      sast: report.json
```

### Any CI system

```bash
# Gate on grade
pipeline_check --pipeline github --min-grade B

# Gate on new findings only (baseline diff)
pipeline_check --pipeline github --fail-on HIGH \
  --baseline-from-git origin/main:baseline.json
```

Exit codes: `0` = pass, `1` = gate failed, `2` = scanner error, `3` = config error.

---

## Configuration

Every CLI flag can be set in `pyproject.toml`, `.pipeline-check.yml`, or
environment variables. Precedence: CLI > env > file > defaults.

```toml
# pyproject.toml
[tool.pipeline_check]
pipeline = "github"
severity_threshold = "MEDIUM"

[tool.pipeline_check.gate]
fail_on = "HIGH"
baseline = "artifacts/baseline.json"
ignore_file = ".pipelinecheckignore"
```

Full reference: [docs/config.md](docs/config.md).

---

## Compliance standards

Each finding is tagged with controls from all enabled frameworks. One scan
covers multiple audits.

| Standard | Version | Coverage |
|----------|---------|----------|
| [OWASP Top 10 CI/CD Security Risks](docs/standards/owasp_cicd_top_10.md) | 2022 | 10/10 risks |
| [SLSA Build Track](docs/standards/slsa.md) | 1.0 | 6/7 levels (110 check mappings) |
| [NIST SSDF (SP 800-218)](docs/standards/nist_ssdf.md) | v1.1 | CI/CD subset |
| [NIST SP 800-53](docs/standards/nist_800_53.md) | Rev. 5 | CI/CD subset |
| [CIS Software Supply Chain](docs/standards/cis_supply_chain.md) | 1.0 | CI/CD subset |
| [CIS AWS Foundations](docs/standards/cis_aws_foundations.md) | 3.0.0 | CI/CD subset |
| [PCI DSS v4.0](docs/standards/pci_dss_v4.md) | 4.0 | CI/CD subset |
| [NSA/CISA ESF Supply Chain](docs/standards/esf_supply_chain.md) | 2022 | CI/CD subset |

```bash
# Explore a standard's control-to-check matrix
pipeline_check --standard-report slsa

# Restrict a scan to specific standards
pipeline_check --standard owasp_cicd_top_10 --standard nist_ssdf
```

Standards are pure data. Adding SOC 2 or an internal policy is one Python module.
See [docs/standards/](docs/standards/).

---

## CLI reference

| Flag | Default | Description |
|------|---------|-------------|
| `--pipeline` / `-p` | `auto` | `auto` (detect from cwd), `aws`, `terraform`, `cloudformation`, `github`, `gitlab`, `bitbucket`, `azure`, `jenkins`, `circleci`, `cloudbuild` |
| `--output` / `-o` | `terminal` | `terminal`, `json`, `html`, `sarif`, `junit`, `markdown`, `both` |
| `--output-file` / `-O` | | Required with `html`; optional with `sarif` |
| `--fail-on` / `-f` | | Fail if any finding >= severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `--min-grade` | | Fail if grade worse than `A`/`B`/`C`/`D` |
| `--max-failures` | | Fail if > N effective findings |
| `--fail-on-check` | | Fail if named check fails (repeat for multiple) |
| `--baseline` | | Prior JSON report; existing findings don't gate |
| `--baseline-from-git` | | `REF:PATH` -- resolve baseline via `git show` |
| `--ignore-file` | `.pipelinecheckignore` | Suppressions (flat or YAML with `expires:`) |
| `--diff-base` | | Only scan files changed vs this git ref |
| `--fix` | | Emit unified-diff patches to stdout |
| `--apply` | | With `--fix`, write patches in place |
| `--checks` / `-c` | all | Check ID(s) or globs (`GHA-*`, `*-008`) |
| `--severity-threshold` | `INFO` | Minimum severity to display |
| `--secret-pattern` | | Extra regex for credential scanning (repeat) |
| `--standard` | all | Standard(s) to annotate findings with |
| `--standard-report` | | Print control-to-check matrix and exit |
| `--inventory` | | Emit scanned-component inventory alongside findings |
| `--inventory-type` | | Glob pattern to scope inventory by type (repeatable, implies `--inventory`) |
| `--inventory-only` | | Skip checks; emit inventory only (implies `--inventory`) |
| `--config` | auto | Config file path (TOML or YAML) |
| `--config-check` | | Validate config, exit non-zero on unknown keys |
| `--man [TOPIC]` | | Extended docs (`gate`, `autofix`, `diff`, `secrets`, `standards`, `config`, `output`, `lambda`, `recipes`) |
| `--region` / `-r` | `us-east-1` | AWS region |
| `--profile` | | AWS CLI named profile |
| `--verbose` / `-v` | | Debug output to stderr |
| `--quiet` / `-q` | | Suppress all output; exit code only |
| `--version` | | Print version |

Provider-specific path flags (`--gha-path`, `--gitlab-path`, `--bitbucket-path`, `--cfn-template`,
`--azure-path`, `--jenkinsfile-path`, `--circleci-path`, `--tf-plan`) are
auto-detected from the working directory when omitted.

Subcommand: **`pipeline_check init`** writes a starter `.pipeline-check.yml`
to the current directory, pre-filling the `pipeline:` key based on what it
finds in cwd. Pass `--path PATH` to redirect the output, or `--force` to
overwrite an existing file.

---

## Architecture

```
pipeline_check/
├── cli.py                     # Click CLI
├── lambda_handler.py          # AWS Lambda entry point
└── core/
    ├── scanner.py             # Provider-agnostic orchestrator
    ├── scorer.py              # Severity-weighted scoring (A/B/C/D)
    ├── gate.py                # CI gate (pass/fail thresholds + baselines)
    ├── autofix.py             # 67 fixers (text-based, comment-preserving)
    ├── reporter.py            # Terminal + JSON
    ├── html_reporter.py       # Self-contained HTML
    ├── sarif_reporter.py      # SARIF 2.1.0
    ├── config.py              # TOML/YAML/env config loader
    ├── providers/             # One module per provider (register + go)
    ├── standards/data/        # One module per compliance standard
    └── checks/
        ├── base.py            # Finding, Severity, shared detection patterns
        ├── aws/               # 32 class-based checks (CB, CP, CD, ECR, IAM, PBAC, S3)
        │   └── rules/         # 38 rule-based checks (CT, CWL, SM, CA, CCM, LMB, KMS, SSM, EB, SIGN, CW, plus CB-008+/IAM-007+/PBAC-003+/CP-005+/ECR-006+)
        ├── terraform/         # AWS-parity checks against plan JSON
        ├── cloudformation/    # AWS-parity checks against CFN templates (YAML/JSON)
        ├── github/rules/      # GHA-001 .. GHA-023
        ├── gitlab/rules/      # GL-001 .. GL-023
        ├── bitbucket/rules/   # BB-001 .. BB-023
        ├── azure/rules/       # ADO-001 .. ADO-023
        ├── jenkins/rules/     # JF-001 .. JF-027
        └── circleci/rules/    # CC-001 .. CC-023
```

Adding a new check is a one-file change. Adding a new provider is three files.
See [docs/providers/](docs/providers/) for the full pattern.

---

## Lambda deployment

Pipeline-Check can run as an AWS Lambda for scheduled scans.
See [docs/lambda.md](docs/) for packaging, IAM permissions, event payload
shapes, and SNS alerting.

---

## Extending

**New check:** Drop a module in `checks/<provider>/rules/` exporting `RULE`
and `check()`. The orchestrator auto-discovers it.

**New provider:** Subclass `BaseProvider`, register in `providers/__init__.py`.
Available via `--pipeline <name>` immediately.

**New standard:** Add a Python module under `standards/data/` with a
`STANDARD` object. The CLI and reporters pick it up automatically.

See [docs/providers/README.md](docs/providers/README.md) for the full contract.

---

## License

MIT -- see [LICENSE](LICENSE).
