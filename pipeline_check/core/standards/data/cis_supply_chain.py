"""CIS Software Supply Chain Security Guide v1.0.

Purpose-built for CI/CD posture. The guide is organized into five
sections: (1) Source Code, (2) Build Pipelines, (3) Build Dependencies,
(4) Artifacts, (5) Deployment. This module maps the sub-controls that
this scanner can evidence from AWS / GitHub Actions / Terraform state.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="cis_supply_chain",
    title="CIS Software Supply Chain Security Guide",
    version="1.0",
    url="https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide",
    controls={
        # 1 — Source Code
        "1.3.4": "Ensure organization identity is required for contribution (no long-lived personal tokens)",
        "1.4.1": "Ensure third-party artifacts and open-source libraries are verified",
        # 2 — Build Pipelines
        "2.1.3": "Ensure the build environment is hardened",
        "2.1.6": "Ensure build workers have minimal network connectivity",
        "2.2.2": "Ensure build workers are single-use",
        "2.3.4": "Ensure pipelines are scanned for secrets and sensitive data",
        "2.3.7": "Ensure pipeline steps produce audit logs",
        "2.3.8": "Ensure pipeline configuration files are reviewed before execution",
        "2.4.2": "Ensure pipeline integrity — artifacts are signed by the pipeline",
        "2.4.3": "Ensure access to the pipeline execution environment is restricted",
        # 3 — Build Dependencies
        "3.1.3": "Ensure signed metadata of dependencies is verified",
        "3.1.5": "Ensure only trusted package managers and repositories are used",
        # 4 — Artifacts
        "4.1.1": "Ensure all artifacts on all releases are verified (signed, integrity-checked)",
        "4.2.1": "Ensure access to artifacts is limited",
        "4.3.3": "Ensure package registries use authentication and authorisation",
        "4.4.1": "Ensure artifacts have provenance/SBOM metadata",
        # 5 — Deployment
        "5.1.4": "Ensure deployment configuration manifests are reviewed before apply",
        "5.2.1": "Ensure deployment environments are separated",
        "5.2.3": "Ensure deployment environment activity is audited",
    },
    mappings={
        # CodeBuild
        "CB-001":   ["2.3.4", "2.4.3"],                  # plaintext secrets
        "CB-002":   ["2.1.3", "2.1.6"],                  # privileged mode / host network
        "CB-003":   ["2.3.7"],                           # build logs disabled
        "CB-004":   ["2.2.2"],                           # no timeout → not single-use
        "CB-005":   ["2.1.3", "1.4.1"],                  # outdated managed build image
        "CB-006":   ["1.3.4"],                           # long-lived source token
        "CB-007":   ["2.3.8"],                           # webhook no filter group
        # CodePipeline
        "CP-001":   ["2.3.8", "5.1.4"],                  # no manual approval
        "CP-002":   ["2.4.2", "4.1.1"],                  # artifact store not CMK-encrypted
        "CP-003":   ["2.3.8"],                           # polling source
        "CP-004":   ["1.3.4"],                           # OAuth token source
        # CodeDeploy
        "CD-001":   ["5.1.4"],                           # no auto rollback
        "CD-002":   ["5.1.4", "5.2.1"],                  # AllAtOnce
        "CD-003":   ["5.2.3"],                           # no CloudWatch alarm
        # ECR
        "ECR-001":  ["1.4.1", "3.1.3"],                  # no image scan on push
        "ECR-002":  ["4.1.1", "4.4.1"],                  # mutable tags break provenance
        "ECR-003":  ["4.2.1", "4.3.3"],                  # public repo policy
        "ECR-004":  ["2.1.3"],                           # no lifecycle policy
        "ECR-005":  ["4.1.1"],                           # AES256 (no CMK → weaker integrity)
        # IAM
        "IAM-001":  ["2.4.3"],
        "IAM-002":  ["2.4.3"],
        "IAM-003":  ["2.4.3"],
        "IAM-004":  ["2.4.3"],
        "IAM-005":  ["2.4.3", "1.3.4"],                  # sts:ExternalId
        "IAM-006":  ["2.4.3"],
        # PBAC
        "PBAC-001": ["2.1.6"],                           # no VPC boundary
        "PBAC-002": ["2.2.2", "2.4.3"],                  # shared service role
        # S3 artifact bucket
        "S3-001":   ["4.2.1"],
        "S3-002":   ["4.1.1"],
        "S3-003":   ["4.1.1", "4.4.1"],                  # versioning = provenance history
        "S3-004":   ["2.3.7", "5.2.3"],
        "S3-005":   ["4.2.1"],
        # GitHub Actions
        "GHA-001":  ["1.4.1", "3.1.5"],                  # unpinned 3rd-party action
        "GHA-002":  ["2.1.3", "2.3.8"],                  # pull_request_target + PR head
        "GHA-003":  ["2.1.3"],                           # script injection
        "GHA-004":  ["2.4.3"],                           # unrestricted GITHUB_TOKEN
        "GHA-005":  ["1.3.4"],                           # long-lived AWS keys
        # GitLab CI
        "GL-001":   ["1.4.1", "3.1.5"],
        "GL-002":   ["2.1.3", "2.3.8"],
        "GL-003":   ["2.3.4", "2.4.3"],
        "GL-004":   ["5.1.4", "5.2.1"],
        "GL-005":   ["1.4.1", "3.1.3", "3.1.5"],
        # Bitbucket Pipelines
        "BB-001":   ["1.4.1", "3.1.5"],
        "BB-002":   ["2.1.3", "2.3.8"],
        "BB-003":   ["2.3.4", "2.4.3"],
        "BB-004":   ["5.1.4", "5.2.1"],
        "BB-005":   ["2.2.2"],
    },
)
