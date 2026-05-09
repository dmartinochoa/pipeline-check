<div align="center">

<img src="https://raw.githubusercontent.com/dmartinochoa/pipeline-check/master/docs/logo.svg" alt="Pipeline-Check logo" width="160">

# [Pipeline-Check](https://dmartinochoa.github.io/pipeline-check/)

[![CI](https://github.com/dmartinochoa/pipeline-check/actions/workflows/python-app.yml/badge.svg)](https://github.com/dmartinochoa/pipeline-check/actions/workflows/python-app.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) ![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/dmartinochoa/pipeline-check?utm_source=oss&utm_medium=github&utm_campaign=dmartinochoa%2Fpipeline-check&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

**Find security risks in your CI/CD pipelines before attackers do.**

Pipeline-Check is a security scanner for GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure DevOps, Bitbucket Pipelines, Buildkite, Drone, Tekton, Argo Workflows, and Google Cloud Build, plus Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, OCI image manifests, and live AWS accounts. It maps every finding to the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/), SLSA, NIST SSDF, PCI DSS, SOC 2, and nine other frameworks, and scores each scan A through D so you can gate merges on the result.

**550+ checks** across **18 providers**, mapped to **14 compliance standards**, with **111 autofixers**, plus **30 attack chains** correlating findings into MITRE ATT&CK-mapped kill chains. A dataflow taint engine catches multi-step and cross-job propagation that single-rule scanners miss.

[Quick start](#quick-start) |
[Usage guide](docs/usage.md) |
[Providers](#supported-providers) |
[How it works](#how-it-works) |
[CI integration](#ci-integration) |
[Compliance](#compliance-standards) |
[vs. Checkov / KICS / Semgrep](docs/comparison.md) |
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

Run `pipeline_check` with no flags in any supported repo. It inspects
the working directory (`.github/workflows/`, `.gitlab-ci.yml`,
`Jenkinsfile`, `cloudbuild.yaml`, `Chart.yaml`, `template.yml`, …),
picks the matching provider, and falls back to `aws` when nothing
recognizable is found.

No API tokens required. CI configs are parsed from disk; AWS uses the
standard boto3 credential chain. The GitHub Actions provider can
*optionally* follow remote reusable-workflow refs over HTTPS via
`--resolve-remote` (off by default; see [docs/providers/github.md](docs/providers/github.md)
for the full opt-in surface).

### PR review comments

Pipe findings into pull-request review comments on the changed lines
via the bundled composite action:

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dmartinochoa/pipeline-check/.github/actions/pipeline-check-pr@v1
        with:
          severity-threshold: MEDIUM
```

Each finding lands as a review comment on its precise line (when the
rule emits a `Location`); everything else goes into a single PR-level
summary comment. See [.github/actions/pipeline-check-pr/README.md](.github/actions/pipeline-check-pr/README.md)
for inputs, idempotency, and fork-PR fallback behavior.

---

## Supported providers

| Provider | Input | Auto-detect | Checks |
|----------|-------|-------------|--------|
| **AWS** | Live account via boto3 | `--region` | 71 checks (CodeBuild, CodePipeline, CodeDeploy, ECR, IAM, PBAC, S3, CloudTrail, CloudWatch Logs, Secrets Manager, CodeArtifact, CodeCommit, Lambda, KMS, SSM, EventBridge, Signer) |
| **Terraform** | `terraform show -json` plan | `--tf-plan` | AWS-parity shift-left checks, pre-provisioning |
| **CloudFormation** | YAML or JSON template | `--cfn-template` | ~63 AWS-parity shift-left checks; handles `!Ref`/`!Sub`/`!GetAtt` intrinsics (treats unresolved values as strict) |
| **GitHub Actions** | `.github/workflows/*.yml` | `--gha-path` | 39 checks (`GHA-001`--`039`) |
| **GitLab CI** | `.gitlab-ci.yml` | `--gitlab-path` | 33 checks (`GL-001`--`033`) |
| **Bitbucket Pipelines** | `bitbucket-pipelines.yml` | `--bitbucket-path` | 29 checks (`BB-001`--`029`) |
| **Azure DevOps** | `azure-pipelines.yml` | `--azure-path` | 30 checks (`ADO-001`--`030`) |
| **Jenkins** | `Jenkinsfile` (Declarative/Scripted) | `--jenkinsfile-path` | 32 checks (`JF-001`--`032`) |
| **CircleCI** | `.circleci/config.yml` | `--circleci-path` | 31 checks (`CC-001`--`031`) |
| **Google Cloud Build** | `cloudbuild.yaml` | `--cloudbuild-path` | 26 checks (`GCB-001`--`026`) |
| **Buildkite** | `.buildkite/pipeline.yml` | `--buildkite-path` | 15 checks (`BK-001`--`015`) |
| **Drone CI** | `.drone.yml` / `.drone.yaml` | `--drone-path` | 11 checks (`DR-001`--`011`): image / plugin pinning, privileged steps, ${DRONE_*} injection, literal secrets, TLS bypass, sensitive host-path mount, `pull: never` policy, tainted cache key, unpinned package install, runner-targeting node map |
| **Tekton** | `Task` / `Pipeline` / `*Run` YAML | `--tekton-path` | 15 checks (`TKN-001`--`015`) |
| **Argo Workflows** | `Workflow` / `WorkflowTemplate` YAML | `--argo-path` | 15 checks (`ARGO-001`--`015`) |
| **Dockerfile** | `Dockerfile` / `Containerfile` | `--dockerfile-path` | 20 checks (`DF-001`--`020`) |
| **Kubernetes** | Manifest YAML (`Deployment`, `Pod`, …) | `--k8s-path` | 40 checks (`K8S-001`--`040`) |
| **Helm** | Chart directory (`Chart.yaml`) or `.tgz` | `--helm-path` | Renders via `helm template`, runs the 40 K8S-* rules on the result, plus 10 chart-supply-chain rules (`HELM-001`--`010`) read straight off `Chart.yaml` / `Chart.lock`. Requires `helm` (Helm 3) on PATH. |
| **OCI image manifest** | `docker buildx imagetools inspect --raw <ref>` JSON | `--oci-manifest` | 8 checks (`OCI-001`--`008`): provenance annotations, build attestations (SLSA / SBOM), `image.created` timestamp, foreign-layer URL refs, license annotation, layer-count hygiene, legacy schemaVersion 1, weak (non-sha256) digest |

Each CI provider checks for: dependency pinning, script injection, credential
leaks, deploy approval gates, artifact signing, SBOM generation, Docker
security, package integrity, timeout enforcement, vulnerability scanning, TLS
verification, and more. The Kubernetes provider focuses on workload posture
(image digest pinning, securityContext, hostPath / host-namespace exposure,
RBAC blast radius, Secret hygiene). The Helm provider renders charts via
`helm template` and runs the Kubernetes rule pack on the result, plus ten
chart-supply-chain rules (`HELM-001`--`010`: legacy `apiVersion: v1`,
missing `Chart.lock` digests, non-HTTPS dependency / home / sources URLs,
non-pinned dependency versions, missing maintainers / description /
appVersion, missing `kubeVersion` range, stale `Chart.lock` > 90 days)
read straight off the on-disk chart files. See [docs/providers/](docs/providers/)
for the full per-check reference.

---

## How it works

```
                 +-----------+
  Config files   |  Scanner  |   550+ checks across 18 providers
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
| **Autofix** | `--fix` emits unified-diff patches; `--fix --apply` writes in place. 111 fixers cover script injection, secrets, timeouts, pinning, Docker flags, TLS, Kubernetes securityContext, Cloud Build options, Helm chart-supply-chain TODOs, and more. |
| **CI gate** | `--fail-on HIGH`, `--min-grade B`, `--max-failures 5`, `--fail-on-check GHA-002`. Any condition trips exit 1. |
| **Baselines** | `--baseline prior.json` or `--baseline-from-git origin/main:report.json`. Only gate on *new* findings. |
| **Diff-mode** | `--diff-base origin/main` scans only files changed by the branch. |
| **Suppressions** | `.pipelinecheckignore` (flat or YAML with `expires:` dates). |
| **Custom secrets** | `--secret-pattern '^acme_[a-f0-9]{32}$'` extends the credential scanner. |
| **Glob selection** | `--checks 'GHA-*'` or `--checks '*-008'` to scope checks. |
| **Standard audit** | `--standard-report nist_ssdf` prints the control-to-check matrix and coverage gaps. |
| **Custom rule DSL** | `--custom-rules PATH` loads YAML-defined rules that run alongside the built-in catalog. Supports GHA, GitLab, Bitbucket, Azure, CircleCI, Cloud Build, Kubernetes, and Helm. Rule shape: `for_each:` jsonpath + `assert:` predicate (`eq` / `regex` / `exists` / `len_gt` / `all_of` / `not` / …). Findings flow through the same scoring, gating, and SARIF as built-ins. See [docs/writing_a_custom_rule.md](docs/writing_a_custom_rule.md). |
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

The marketplace action wraps install, scan, gate, and SARIF upload in
one step. Findings show up in the GitHub Security tab.

```yaml
permissions:
  contents: read
  security-events: write   # required by upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dmartinochoa/pipeline-check@v1
        with:
          pipeline: auto       # or: github, gitlab, terraform, k8s, ...
          fail-on: HIGH
```

Inputs (all optional): `pipeline`, `path`, `fail-on`, `min-grade`,
`max-failures`, `severity-threshold`, `baseline`, `baseline-from-git`,
`diff-base`, `standard`, `output`, `output-file`, `upload-sarif`,
`pipeline-check-version`, `python-version`, `resolve-remote`,
`extra-args`. Outputs: `exit-code`, `findings-count`, `failed-count`,
`score`, `grade`, `sarif-file`. See [`action.yml`](action.yml) for the
full surface.

For PR review comments on the changed lines, see the companion
[pipeline-check-pr action](.github/actions/pipeline-check-pr/README.md).

For finer control, the manual three-step form still works:

```yaml
- run: pip install pipeline-check
- run: pipeline_check --pipeline github --output sarif --output-file pipeline-check.sarif --fail-on HIGH
- if: always()
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

### Pre-commit

`pipeline_check` ships hook definitions for the [pre-commit](https://pre-commit.com)
framework. Each hook is scoped to one provider so a Dockerfile change
doesn't run the GitHub Actions scanner. Enable just the hooks for the
providers your repo ships through:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/dmartinochoa/pipeline-check
    rev: v0.3.3   # pin to a release tag
    hooks:
      - id: pipeline-check-github
      - id: pipeline-check-dockerfile
```

All hooks default to `--fail-on HIGH`. Override with `args:` for a softer
gate (e.g. `args: [--fail-on, CRITICAL]`).

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
| [NIST SP 800-190](docs/standards/nist_800_190.md) | 2017 | Container CI/CD subset |
| [NIST CSF 2.0](docs/standards/nist_csf_2.md) | 2.0 | CI/CD subset |
| [CIS Software Supply Chain](docs/standards/cis_supply_chain.md) | 1.0 | CI/CD subset |
| [CIS AWS Foundations](docs/standards/cis_aws_foundations.md) | 3.0.0 | CI/CD subset |
| [PCI DSS v4.0](docs/standards/pci_dss_v4.md) | 4.0 | CI/CD subset |
| [SOC 2 Trust Services Criteria](docs/standards/soc2.md) | 2017 (rev. 2022) | CC6/CC7/CC8 subset |
| [NSA/CISA ESF Supply Chain](docs/standards/esf_supply_chain.md) | 2022 | CI/CD subset |
| [OpenSSF Scorecard](docs/standards/openssf_scorecard.md) | v5 | CI/CD subset |
| [Microsoft S2C2F](docs/standards/s2c2f.md) | 2024-05 | CI/CD subset |

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
| `--pipeline` / `-p` | `auto` | `auto` (detect from cwd), `aws`, `terraform`, `cloudformation`, `github`, `gitlab`, `bitbucket`, `azure`, `jenkins`, `circleci`, `cloudbuild`, `buildkite`, `drone`, `tekton`, `argo`, `dockerfile`, `kubernetes`, `helm`, `oci` |
| `--pipelines` | | Comma-separated multi-provider list (e.g. `--pipelines github,oci`). Mutually exclusive with `--pipeline`. Activates cross-provider attack chains (`XPC-NNN`) by evaluating the chain engine over the union of every sub-scan's findings. |
| `--output` / `-o` | `terminal` | `terminal`, `json`, `html`, `sarif`, `junit`, `markdown`, `both` |
| `--output-file` / `-O` | | Required with `html`; optional with `sarif` |
| `--fail-on` / `-f` | | Fail if any finding >= severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `--min-grade` | | Fail if grade worse than `A`/`B`/`C`/`D` |
| `--max-failures` | | Fail if > N effective findings |
| `--fail-on-check` | | Fail if named check fails (repeat for multiple) |
| `--baseline` | | Prior JSON report; existing findings don't gate |
| `--baseline-from-git` | | `REF:PATH`. Resolves baseline via `git show` |
| `--ignore-file` | `.pipelinecheckignore` | Suppressions (flat or YAML with `expires:`) |
| `--diff-base` | | Only scan files changed vs this git ref |
| `--fix` | | Emit unified-diff patches to stdout |
| `--apply` | | With `--fix`, write patches in place |
| `--checks` / `-c` | all | Check ID(s) or globs (`GHA-*`, `*-008`) |
| `--severity-threshold` | `INFO` | Minimum severity to display |
| `--secret-pattern` | | Extra regex for credential scanning (repeat) |
| `--custom-rules` | | YAML rule file or directory of rule files; loaded alongside the built-in catalog (repeatable) |
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
`--azure-path`, `--jenkinsfile-path`, `--circleci-path`, `--tf-plan`,
`--cloudbuild-path`, `--buildkite-path`, `--drone-path`, `--tekton-path`, `--argo-path`,
`--dockerfile-path`, `--k8s-path`, `--helm-path`, `--oci-manifest`) are
auto-detected from the working directory when omitted. The Helm provider also
takes `--helm-values FILE` and `--helm-set KEY=VALUE` (both repeatable),
forwarded to `helm template`.

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
    ├── autofix.py             # 111 fixers (text-based, comment-preserving)
    ├── reporter.py            # Terminal + JSON
    ├── html_reporter.py       # Self-contained HTML
    ├── sarif_reporter.py      # SARIF 2.1.0
    ├── config.py              # TOML/YAML/env config loader
    ├── providers/             # One module per provider (register + go)
    ├── standards/data/        # One module per compliance standard
    └── checks/
        ├── base.py            # Finding, Severity, shared detection patterns
        ├── aws/rules/         # 71 rule-based checks (CB, CP, CD, ECR, IAM, PBAC, S3, CT, CWL, SM, CA, CCM, LMB, KMS, SSM, EB, SIGN, CW)
        ├── terraform/         # AWS-parity checks against plan JSON
        ├── cloudformation/    # AWS-parity checks against CFN templates (YAML/JSON)
        ├── github/rules/      # GHA-001 .. GHA-038
        ├── gitlab/rules/      # GL-001 .. GL-032
        ├── bitbucket/rules/   # BB-001 .. BB-029
        ├── azure/rules/       # ADO-001 .. ADO-030
        ├── jenkins/rules/     # JF-001 .. JF-032
        ├── circleci/rules/    # CC-001 .. CC-031
        ├── cloudbuild/rules/  # GCB-001 .. GCB-026
        ├── dockerfile/rules/  # DF-001 .. DF-020
        ├── kubernetes/rules/  # K8S-001 .. K8S-040
        ├── helm/              # Renders charts; reuses the K8s rule pack
        └── custom/            # YAML rule loader + predicate engine
```

Adding a new check is a one-file change. Adding a new provider is three files.
See [docs/providers/](docs/providers/) for the full pattern.

---

## Python API

Embed pipeline-check in your own tooling without `subprocess` + JSON
parsing. The top-level surface is small and stable across minor
releases:

```python
from pipeline_check import Scanner, Severity, score

scanner = Scanner(pipeline="github", gha_path=".github/workflows")
findings = scanner.run()

critical = [
    f for f in findings
    if not f.passed and f.severity is Severity.CRITICAL
]
result = score(findings)
print(f"score={result['score']} grade={result['grade']}")
```

Public surface: `Scanner`, `Finding`, `Severity`, `Confidence`,
`ControlRef`, `score`, `ScoreResult`, `Chain`, `ChainRule`,
`evaluate_chains`, `list_chain_rules`, `available_providers()`,
`available_standards()`, `load_custom_rules()`, `LoadedCustomRules`,
`CustomRuleError`, `__version__`. Anything reached through
`pipeline_check.core.*` is internal and may move between releases.

---

## Lambda deployment

Pipeline-Check can run as an AWS Lambda for scheduled scans.
Run `pipeline_check --man lambda` for packaging, IAM permissions, event
payload shapes, and SNS alerting.

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

MIT. See [LICENSE](LICENSE).


