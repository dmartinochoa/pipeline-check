"""PCI DSS v4.0 — subset covering CI/CD-relevant requirements.

Only requirements whose evidence can be collected from CI/CD
configuration state are mapped here. Requirements about network
segmentation, physical security, cryptographic key management
lifecycles, and cardholder data handling are out of scope.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="pci_dss_v4",
    title="PCI DSS v4.0",
    version="4.0",
    url="https://www.pcisecuritystandards.org/document_library/",
    controls={
        # Req 6 — develop and maintain secure systems and software
        "6.3.1": "Security vulnerabilities are identified and managed",
        "6.3.3": "All system components protected from known vulnerabilities by installing applicable patches",
        "6.4.1": "Public-facing web apps are protected against attacks (secure build/config)",
        "6.4.3": "Changes to systems are managed via documented change control",
        "6.5.1": "Changes to system components follow secure development procedures",
        # Req 7 — restrict access by business need to know
        "7.2.1": "Access control is defined per job role with least privilege",
        "7.2.2": "Access is assigned based on job classification and function",
        "7.2.5": "System and application accounts have least-privilege access",
        # Req 8 — identify users and authenticate access
        "8.2.1": "Strong unique identifiers are assigned to each user and service account",
        "8.2.2": "Group, shared, or generic accounts are managed and justified",
        # Req 10 — log and monitor all access to system components
        "10.2.1": "Audit logs are enabled and active for all system components",
        "10.3.2": "Audit logs are protected from unauthorized modifications",
        "10.3.3": "Audit logs are promptly backed up to a centralized log server",
    },
    mappings={
        # CodeBuild
        "CB-001":   ["6.5.1", "8.2.1"],                  # plaintext secrets
        "CB-002":   ["6.4.1", "6.5.1"],                  # privileged mode
        "CB-003":   ["10.2.1"],                          # build logging disabled
        "CB-004":   ["6.4.1"],                           # no build timeout
        "CB-005":   ["6.3.3"],                           # outdated managed image
        "CB-006":   ["8.2.1"],                           # long-lived source token
        "CB-007":   ["6.4.1"],                           # webhook no filter
        # CodePipeline
        "CP-001":   ["6.4.3", "6.5.1"],                  # no manual approval
        "CP-002":   ["6.5.1", "10.3.2"],                 # artifact store not CMK-encrypted
        "CP-003":   ["6.4.1"],                           # polling source
        "CP-004":   ["8.2.1"],                           # OAuth-token source
        # CodeDeploy
        "CD-001":   ["6.4.3"],                           # no auto rollback
        "CD-002":   ["6.4.3"],                           # AllAtOnce deployment
        "CD-003":   ["10.2.1"],                          # no CloudWatch alarm
        # ECR
        "ECR-001":  ["6.3.1", "6.3.3"],                  # no image scan on push
        "ECR-002":  ["6.5.1", "10.3.2"],                 # mutable tags
        "ECR-003":  ["7.2.5"],                           # public repo policy
        "ECR-004":  ["6.5.1"],                           # no lifecycle policy
        "ECR-005":  ["10.3.2"],                          # AES256 not CMK
        # IAM
        "IAM-001":  ["7.2.1", "7.2.5"],
        "IAM-002":  ["7.2.1", "7.2.5"],
        "IAM-003":  ["7.2.5"],
        "IAM-004":  ["7.2.5"],
        "IAM-005":  ["7.2.1"],                           # sts:ExternalId confused-deputy
        "IAM-006":  ["7.2.5"],
        # PBAC
        "PBAC-001": ["6.4.1"],                           # no VPC boundary
        "PBAC-002": ["7.2.5", "8.2.2"],                  # shared service role
        # S3 artifact bucket
        "S3-001":   ["10.3.2"],
        "S3-002":   ["10.3.2"],
        "S3-003":   ["10.3.2"],
        "S3-004":   ["10.2.1", "10.3.3"],
        "S3-005":   ["10.3.2"],
        # GitHub Actions
        "GHA-001":  ["6.3.3"],                           # unpinned action
        "GHA-002":  ["6.5.1"],                           # pull_request_target + PR head
        "GHA-003":  ["6.5.1"],                           # script injection
        "GHA-004":  ["7.2.5"],                           # unrestricted GITHUB_TOKEN
        "GHA-005":  ["8.2.1"],                           # long-lived AWS keys
        # GitLab CI
        "GL-001":   ["6.3.3"],
        "GL-002":   ["6.5.1"],
        "GL-003":   ["8.2.1", "6.5.1"],
        "GL-004":   ["6.4.3"],
        "GL-005":   ["6.3.3"],
        # Bitbucket Pipelines
        "BB-001":   ["6.3.3"],
        "BB-002":   ["6.5.1"],
        "BB-003":   ["8.2.1", "6.5.1"],
        "BB-004":   ["6.4.3"],
        "BB-005":   ["6.4.1"],
        # Azure DevOps Pipelines
        "ADO-001":  ["6.3.3"],
        "ADO-002":  ["6.5.1"],
        "ADO-003":  ["8.2.1", "6.5.1"],
        "ADO-004":  ["6.4.3"],
        "ADO-005":  ["6.3.3"],
    },
)
