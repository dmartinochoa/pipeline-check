---
hide:
  - navigation
  - toc
---

# Pipeline-Check

**Find security risks in your CI/CD pipelines before attackers do.**

Scans CI/CD configurations against the
[OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
and 12 other compliance frameworks. Scores findings A–D so you can gate
merges on the result.

[![CI](https://github.com/dmartinochoa/pipeline-check/actions/workflows/python-app.yml/badge.svg)](https://github.com/dmartinochoa/pipeline-check/actions/workflows/python-app.yml)
[![PyPI](https://img.shields.io/pypi/v/pipeline-check.svg)](https://pypi.org/project/pipeline-check/)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://github.com/dmartinochoa/pipeline-check/blob/master/pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/dmartinochoa/pipeline-check/blob/master/LICENSE)

---

## What it scans

<div class="grid cards" markdown>

-   :material-aws:{ .lg .middle } **AWS** — live account via boto3

    71 checks across CodeBuild, CodePipeline, CodeDeploy, ECR, IAM, S3,
    CloudTrail, CloudWatch, Secrets Manager, CodeArtifact, CodeCommit,
    Lambda, KMS, SSM, EventBridge, Signer.

    [:octicons-arrow-right-24: AWS reference](providers/aws.md)

-   :material-language-python:{ .lg .middle } **Shift-left IaC**

    Scan Terraform plans and CloudFormation templates *before*
    provisioning, with parity to the live-AWS rules.

    [:octicons-arrow-right-24: Terraform](providers/terraform.md) ·
    [:octicons-arrow-right-24: CloudFormation](providers/cloudformation.md)

-   :material-source-branch:{ .lg .middle } **CI workflow files**

    GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure DevOps,
    Jenkins, CircleCI, Google Cloud Build — all from disk, no API tokens.

    [:octicons-arrow-right-24: All providers](providers/README.md)

-   :material-shield-check:{ .lg .middle } **13 compliance standards**

    OWASP Top 10 CI/CD, CIS, NIST SSDF / 800-53 / 800-190 / CSF 2, SLSA,
    PCI DSS v4, ESF, OpenSSF Scorecard, S2C2F, SOC 2.

    [:octicons-arrow-right-24: Standards](standards/README.md)

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

No API tokens required. CI configs are parsed from disk; AWS uses the
standard boto3 credential chain.

[:octicons-book-24: Full usage guide](usage.md){ .md-button .md-button--primary }
[:octicons-mark-github-16: GitHub](https://github.com/dmartinochoa/pipeline-check){ .md-button }

---

## Why Pipeline-Check

- **One tool, ten providers.** Same severity model and report format
  whether you're scanning a Jenkinsfile or a live AWS account.
- **Mapped to the standards your auditor cares about.** Every finding
  carries control IDs for OWASP, CIS, NIST SSDF, SLSA, and more.
- **CI-gate ready.** Severity thresholds, baseline diffs, ignore files
  with expiries, autofix emit-or-apply.
- **Attack chain correlation.** Multi-finding chains mapped to MITRE
  ATT&CK so you see the kill chain, not just the symptoms.
  [Read more](attack_chains.md).
- **Open source, zero telemetry.** MIT-licensed, no phone-home.
