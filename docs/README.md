# Pipeline-Check documentation

- [Scoring model](scoring_model.md) — severity weights, grade bands, exit codes.
- [Providers](providers/README.md) — supported CI/CD platforms and their checks.
  - [AWS](providers/aws.md) — full check reference.
  - [Terraform](providers/terraform.md) — scan `terraform show -json` plans.
  - [GitHub Actions](providers/github.md) — scan workflow YAML under `.github/workflows`.
  - [GitLab CI](providers/gitlab.md) — scan `.gitlab-ci.yml`.
  - [Bitbucket Pipelines](providers/bitbucket.md) — scan `bitbucket-pipelines.yml`.
  - [Azure DevOps Pipelines](providers/azure.md) — scan `azure-pipelines.yml`.
  - [Jenkins](providers/jenkins.md) — scan `Jenkinsfile` (Declarative or Scripted).
  - [CircleCI](providers/circleci.md) — scan `.circleci/config.yml`.
- [Output formats](output.md) — terminal, JSON, HTML (with client-side
  filters), and SARIF 2.1.0 (line-number annotations + AWS ARN metadata).
- [CI gate](ci_gate.md) — severity thresholds, baseline diff (file or
  git ref), `.pipeline-check-ignore.yml` with expiries, `--diff-base`
  scoping, autofix (emit or `--apply`), glob check selection, custom
  secret patterns.
- [Attack chains](attack_chains.md) — multi-finding correlations mapped
  to MITRE ATT&CK (AC-001…AC-008). Includes gating (`--fail-on-chain`,
  `--fail-on-any-chain`), confidence inheritance, and how chains surface
  in each output format.
- [Configuration](config.md) — `pyproject.toml` / `.pipeline-check.yml` /
  env-var surface, plus `--config-check` to fail CI on unknown keys.
- [Compliance standards](standards/README.md) — how findings are annotated
  with control references. Use `pipeline_check --standard-report NAME` to
  print the control→check matrix and any unmapped gaps for a standard.
  - [OWASP Top 10 CI/CD Security Risks](standards/owasp_cicd_top_10.md)
  - [CIS AWS Foundations Benchmark (subset)](standards/cis_aws_foundations.md)
  - [CIS Software Supply Chain Security Guide](standards/cis_supply_chain.md)
  - [NIST Secure Software Development Framework (SP 800-218)](standards/nist_ssdf.md)
  - [NIST SP 800-53 Rev. 5 (CI/CD subset)](standards/nist_800_53.md)
  - [SLSA Build Track v1.0](standards/slsa.md)
  - [PCI DSS v4.0 (CI/CD subset)](standards/pci_dss_v4.md)
  - [NSA/CISA ESF — Securing the Software Supply Chain](standards/esf_supply_chain.md)

For installation, usage, architecture, Lambda deployment (including the
multi-region fan-out payload), and the full CLI options table, see the
[top-level README](../README.md).
