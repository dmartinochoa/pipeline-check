"""OWASP Top 10 CI/CD Security Risks (2022)."""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="owasp_cicd_top_10",
    title="OWASP Top 10 CI/CD Security Risks",
    version="2022",
    url="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
    controls={
        "CICD-SEC-1":  "Insufficient Flow Control Mechanisms",
        "CICD-SEC-2":  "Inadequate Identity and Access Management",
        "CICD-SEC-3":  "Dependency Chain Abuse",
        "CICD-SEC-4":  "Poisoned Pipeline Execution",
        "CICD-SEC-5":  "Insufficient PBAC",
        "CICD-SEC-6":  "Insufficient Credential Hygiene",
        "CICD-SEC-7":  "Insecure System Configuration",
        "CICD-SEC-8":  "Ungoverned Usage of 3rd-Party Services",
        "CICD-SEC-9":  "Improper Artifact Integrity Validation",
        "CICD-SEC-10": "Insufficient Logging and Visibility",
    },
    mappings={
        # CodeBuild
        "CB-001":   ["CICD-SEC-6"],
        "CB-002":   ["CICD-SEC-7"],
        "CB-003":   ["CICD-SEC-10"],
        "CB-004":   ["CICD-SEC-7"],
        "CB-005":   ["CICD-SEC-7"],
        "CB-006":   ["CICD-SEC-6"],
        "CB-007":   ["CICD-SEC-1"],
        # CodePipeline
        "CP-001":   ["CICD-SEC-1"],
        "CP-002":   ["CICD-SEC-9"],
        "CP-003":   ["CICD-SEC-4"],
        "CP-004":   ["CICD-SEC-6"],
        # CodeDeploy
        "CD-001":   ["CICD-SEC-1"],
        "CD-002":   ["CICD-SEC-1"],
        "CD-003":   ["CICD-SEC-10"],
        # ECR
        "ECR-001":  ["CICD-SEC-3"],
        "ECR-002":  ["CICD-SEC-9"],
        "ECR-003":  ["CICD-SEC-8"],
        "ECR-004":  ["CICD-SEC-7"],
        "ECR-005":  ["CICD-SEC-9"],
        # IAM
        "IAM-001":  ["CICD-SEC-2"],
        "IAM-002":  ["CICD-SEC-2"],
        "IAM-003":  ["CICD-SEC-2"],
        "IAM-004":  ["CICD-SEC-2"],
        "IAM-005":  ["CICD-SEC-2"],
        "IAM-006":  ["CICD-SEC-2"],
        # PBAC
        "PBAC-001": ["CICD-SEC-5"],
        "PBAC-002": ["CICD-SEC-5"],
        # S3
        "S3-001":   ["CICD-SEC-9"],
        "S3-002":   ["CICD-SEC-9"],
        "S3-003":   ["CICD-SEC-9"],
        "S3-004":   ["CICD-SEC-10"],
        "S3-005":   ["CICD-SEC-9"],
    },
)
