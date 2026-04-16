"""NIST Secure Software Development Framework (SP 800-218 v1.1).

Subset covering the practices and tasks this scanner can evidence from
CI/CD state. The SSDF is grouped into four practice areas:

- PO — Prepare the Organization
- PS — Protect the Software
- PW — Produce Well-Secured Software
- RV — Respond to Vulnerabilities

Only the tasks for which at least one check produces evidence are
included. A single task may be evidenced by multiple checks, and a
single check may evidence multiple tasks across different practices.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="nist_ssdf",
    title="NIST Secure Software Development Framework",
    version="SP 800-218 v1.1",
    url="https://csrc.nist.gov/pubs/sp/800/218/final",
    controls={
        # Prepare the Organization
        "PO.3.2": "Implement and maintain supporting toolchains with security controls",
        "PO.3.3": "Configure the toolchain to generate an audit trail of SDLC activities",
        "PO.5.1": "Separate and protect each environment involved in software development",
        "PO.5.2": "Secure and harden endpoints used for software development",
        # Protect the Software
        "PS.1.1": "Store all forms of code based on least-privilege and tamper-resistance",
        "PS.2.1": "Make software integrity verification information available to acquirers",
        "PS.3.1": "Securely archive the necessary files and data for each software release",
        "PS.3.2": "Collect, safeguard, maintain, and share provenance data for releases",
        # Produce Well-Secured Software
        "PW.4.1": "Acquire and maintain well-secured 3rd-party software components",
        "PW.4.4": "Verify that acquired components are what is expected and behave as expected",
        "PW.6.1": "Use compiler, interpreter, and build tool features to improve security",
        "PW.9.1": "Configure software to have secure settings by default",
        # Respond to Vulnerabilities
        "RV.1.1": "Gather information about potential vulnerabilities in released software",
    },
    mappings={
        # CodeBuild
        "CB-001":   ["PS.1.1"],                        # plaintext secrets
        "CB-002":   ["PO.5.1", "PW.9.1"],              # privileged mode
        "CB-003":   ["PO.3.3"],                        # build logging disabled
        "CB-004":   ["PO.5.2", "PW.9.1"],              # no build timeout
        "CB-005":   ["PW.4.1", "PW.4.4", "RV.1.1"],    # outdated managed image
        "CB-006":   ["PS.1.1"],                        # long-lived source token
        "CB-007":   ["PO.5.1", "PW.9.1"],              # webhook no filter group
        # CodePipeline
        "CP-001":   ["PO.5.1"],                        # no manual approval
        "CP-002":   ["PS.1.1", "PS.3.1"],              # artifact store not CMK-encrypted
        "CP-003":   ["PO.3.2"],                        # polling source
        "CP-004":   ["PS.1.1"],                        # OAuth-token source
        # CodeDeploy
        "CD-001":   ["PO.3.2"],                        # no auto rollback
        "CD-002":   ["PO.5.1"],                        # AllAtOnce deployment
        "CD-003":   ["PO.3.3", "RV.1.1"],              # no CloudWatch alarm
        # ECR
        "ECR-001":  ["PW.4.4", "RV.1.1"],              # no image scan on push
        "ECR-002":  ["PS.3.1", "PS.3.2"],              # mutable tags
        "ECR-003":  ["PO.5.1", "PS.1.1"],              # public repo policy
        "ECR-004":  ["PO.3.2"],                        # no lifecycle policy
        "ECR-005":  ["PS.1.1"],                        # AES256 not CMK
        # IAM
        "IAM-001":  ["PO.5.1"],
        "IAM-002":  ["PO.5.1"],
        "IAM-003":  ["PO.5.1"],
        "IAM-004":  ["PO.5.1"],
        "IAM-005":  ["PO.5.1"],
        "IAM-006":  ["PO.5.1"],
        # PBAC
        "PBAC-001": ["PO.5.1", "PO.3.2"],              # no VPC for CodeBuild
        "PBAC-002": ["PO.5.1", "PO.3.2"],              # shared service role
        # S3 artifact store
        "S3-001":   ["PS.1.1"],                        # public access block
        "S3-002":   ["PS.1.1", "PS.3.1"],              # server-side encryption
        "S3-003":   ["PS.3.1", "PS.3.2"],              # versioning (provenance history)
        "S3-004":   ["PO.3.3"],                        # access logging
        "S3-005":   ["PS.1.1"],                        # SecureTransport deny
        # GitHub Actions
        "GHA-001":  ["PW.4.1", "PW.4.4"],              # action not pinned to SHA
        "GHA-002":  ["PO.5.1", "PW.9.1"],              # pull_request_target with PR head
        "GHA-003":  ["PW.6.1", "PW.9.1"],              # script injection
        "GHA-004":  ["PO.5.1"],                        # no explicit permissions
        "GHA-005":  ["PS.1.1"],                        # long-lived AWS keys
        # GitLab CI
        "GL-001":   ["PW.4.1", "PW.4.4"],
        "GL-002":   ["PW.6.1", "PW.9.1"],
        "GL-003":   ["PS.1.1"],
        "GL-004":   ["PO.5.1"],
        "GL-005":   ["PW.4.1", "PW.4.4"],
        # Bitbucket Pipelines
        "BB-001":   ["PW.4.1", "PW.4.4"],
        "BB-002":   ["PW.6.1", "PW.9.1"],
        "BB-003":   ["PS.1.1"],
        "BB-004":   ["PO.5.1"],
        "BB-005":   ["PO.5.2", "PW.9.1"],
        # Azure DevOps Pipelines
        "ADO-001":  ["PW.4.1", "PW.4.4"],
        "ADO-002":  ["PW.6.1", "PW.9.1"],
        "ADO-003":  ["PS.1.1"],
        "ADO-004":  ["PO.5.1"],
        "ADO-005":  ["PW.4.1", "PW.4.4"],
        # CircleCI
        "CC-001":   ["PW.4.1", "PW.4.4"],              # orb not pinned to SHA
        "CC-002":   ["PW.6.1", "PW.9.1"],              # script injection
        "CC-003":   ["PW.4.1", "PW.4.4"],              # image not pinned to digest
        "CC-004":   ["PS.1.1"],                        # unrestricted context
        "CC-005":   ["PS.1.1"],                        # long-lived AWS keys
        "CC-006":   ["PS.2.1", "PS.3.2"],              # unsigned artifacts
        "CC-007":   ["PS.3.2"],                        # no SBOM / provenance
        "CC-008":   ["PS.1.1"],                        # literal secrets in config
        "CC-009":   ["PO.5.1"],                        # no deployment approval
        "CC-010":   ["PO.5.2", "PW.9.1"],              # self-hosted runner
        "CC-011":   ["PO.3.3"],                        # no build retention
        "CC-012":   ["PW.6.1", "PW.9.1"],              # setup / dynamic config
        "CC-013":   ["PO.5.1"],                        # no branch filter
        "CC-014":   ["PO.5.1", "PO.5.2"],              # resource class isolation
        "CC-015":   ["PO.5.2", "PW.9.1"],              # no timeout
        "CC-016":   ["PW.4.1", "PW.4.4"],              # curl | bash
        "CC-017":   ["PO.5.2", "PW.9.1"],              # insecure Docker config
        "CC-018":   ["PW.4.1", "PW.4.4"],              # insecure package source
        "CC-019":   ["PS.1.1"],                        # SSH key in config
        "CC-020":   ["RV.1.1"],                        # no vulnerability scanning
        "CC-021":   ["PW.4.4"],                        # no lockfile
        "CC-022":   ["PW.4.1"],                        # no dependency updates
        "CC-023":   ["PW.4.4"],                        # TLS verification bypass
    },
)
