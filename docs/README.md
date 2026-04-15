# Pipeline-Check documentation

- [Scoring model](scoring_model.md) — severity weights, grade bands, exit codes.
- [Providers](providers/README.md) — supported CI/CD platforms and their checks.
  - [AWS](providers/aws.md) — full check reference.
  - [Terraform](providers/terraform.md) — scan `terraform show -json` plans.
  - [GitHub Actions](providers/github.md) — scan workflow YAML under `.github/workflows`.
  - [GitLab CI](providers/gitlab.md) — scan `.gitlab-ci.yml`.
  - [Bitbucket Pipelines](providers/bitbucket.md) — scan `bitbucket-pipelines.yml`.
- [Output formats](output.md) — terminal, JSON, HTML, and SARIF 2.1.0.
- [CI gate](ci_gate.md) — fine-grained pass/fail control: severity thresholds, baseline diff, ignore files.
- [Compliance standards](standards/README.md) — how findings are annotated with control references.
  - [OWASP Top 10 CI/CD Security Risks](standards/owasp_cicd_top_10.md)
  - [CIS AWS Foundations Benchmark (subset)](standards/cis_aws_foundations.md)
  - [CIS Software Supply Chain Security Guide](standards/cis_supply_chain.md)
  - [NIST Secure Software Development Framework (SP 800-218)](standards/nist_ssdf.md)
  - [NIST SP 800-53 Rev. 5 (CI/CD subset)](standards/nist_800_53.md)
  - [SLSA Build Track v1.0](standards/slsa.md)
  - [PCI DSS v4.0 (CI/CD subset)](standards/pci_dss_v4.md)

For installation, usage, and architecture, see the [top-level README](../README.md).
