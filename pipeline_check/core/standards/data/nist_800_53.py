"""NIST SP 800-53 Rev. 5 — CI/CD-relevant control subset.

800-53 is the federal security and privacy control catalog. This module
covers the controls whose evidence can be collected from CI/CD state,
spanning the AC (Access Control), AU (Audit & Accountability), CM
(Configuration Management), IA (Identification & Authentication), RA
(Risk Assessment), SA (System & Services Acquisition), SC (System &
Comm Protection), SI (System & Information Integrity), and SR (Supply
Chain Risk Management) families.

Controls for privacy (PT, PM), incident response (IR), personnel
security (PS), physical security (PE), and maintenance (MA) are out of
scope.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="nist_800_53",
    title="NIST SP 800-53 Rev. 5",
    version="Rev. 5",
    url="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    controls={
        # Access Control
        "AC-2":  "Account Management",
        "AC-3":  "Access Enforcement",
        "AC-6":  "Least Privilege",
        # Audit and Accountability
        "AU-2":  "Event Logging",
        "AU-9":  "Protection of Audit Information",
        "AU-12": "Audit Record Generation",
        # Configuration Management
        "CM-2":  "Baseline Configuration",
        "CM-6":  "Configuration Settings",
        "CM-7":  "Least Functionality",
        "CM-8":  "System Component Inventory",
        # Identification and Authentication
        "IA-5":  "Authenticator Management",
        # Risk Assessment
        "RA-5":  "Vulnerability Monitoring and Scanning",
        # System and Services Acquisition
        "SA-10": "Developer Configuration Management",
        "SA-11": "Developer Testing and Evaluation",
        "SA-15": "Development Process, Standards, and Tools",
        # System and Communications Protection
        "SC-7":  "Boundary Protection",
        "SC-8":  "Transmission Confidentiality and Integrity",
        "SC-12": "Cryptographic Key Establishment and Management",
        "SC-13": "Cryptographic Protection",
        "SC-28": "Protection of Information at Rest",
        # System and Information Integrity
        "SI-2":  "Flaw Remediation",
        "SI-7":  "Software, Firmware, and Information Integrity",
        # Supply Chain Risk Management
        "SR-3":  "Supply Chain Controls and Processes",
        "SR-4":  "Provenance",
        "SR-11": "Component Authenticity",
    },
    mappings={
        # CodeBuild
        "CB-001":   ["IA-5"],                            # plaintext secrets
        "CB-002":   ["CM-6", "CM-7"],                    # privileged mode
        "CB-003":   ["AU-2", "AU-12"],                   # no build logs
        "CB-004":   ["CM-6"],                            # no build timeout
        "CB-005":   ["CM-2", "SI-2", "RA-5"],            # outdated managed image
        "CB-006":   ["IA-5"],                            # long-lived source token
        "CB-007":   ["CM-6", "CM-7"],                    # webhook no filter
        # CodePipeline
        "CP-001":   ["SA-10", "SA-15"],                  # no manual approval
        "CP-002":   ["SC-12", "SC-13", "SC-28", "SI-7", "SR-4"], # artifact store not CMK
        "CP-003":   ["CM-6"],                            # polling source
        "CP-004":   ["IA-5"],                            # OAuth token source
        # CodeDeploy
        "CD-001":   ["SA-10"],                           # no auto rollback
        "CD-002":   ["SA-10"],                           # AllAtOnce
        "CD-003":   ["AU-2", "AU-12"],                   # no CloudWatch alarm
        # ECR
        "ECR-001":  ["RA-5", "SI-2", "SA-11"],           # no scan on push
        "ECR-002":  ["CM-8", "SI-7", "SR-4", "SR-11"],   # mutable tags
        "ECR-003":  ["AC-3", "SC-7", "SR-3"],            # public repo policy
        "ECR-004":  ["CM-2", "CM-8"],                    # no lifecycle
        "ECR-005":  ["SC-12", "SC-13", "SC-28", "SR-4"], # AES256 not CMK
        # IAM
        "IAM-001":  ["AC-3", "AC-6"],
        "IAM-002":  ["AC-3", "AC-6"],
        "IAM-003":  ["AC-2", "AC-6"],
        "IAM-004":  ["AC-3", "AC-6"],
        "IAM-005":  ["AC-2", "AC-3"],                    # sts:ExternalId (confused deputy)
        "IAM-006":  ["AC-3", "AC-6"],
        # PBAC
        "PBAC-001": ["SC-7"],                            # no VPC boundary
        "PBAC-002": ["AC-2", "AC-6"],                    # shared service role
        # S3 artifact bucket
        "S3-001":   ["AC-3", "SC-7", "AU-9"],
        "S3-002":   ["SC-12", "SC-13", "SC-28", "AU-9"],
        "S3-003":   ["SI-7", "AU-9"],
        "S3-004":   ["AU-2", "AU-12"],
        "S3-005":   ["SC-8", "AU-9"],
        # GitHub Actions
        "GHA-001":  ["SR-3", "SR-11", "SI-2", "RA-5"],   # unpinned action
        "GHA-002":  ["CM-6", "SI-7", "SA-11"],           # pull_request_target + PR head
        "GHA-003":  ["CM-6", "SA-11", "SA-15"],          # script injection
        "GHA-004":  ["AC-6", "CM-6", "CM-7"],            # unrestricted GITHUB_TOKEN
        "GHA-005":  ["IA-5"],                            # long-lived AWS keys
        # GitLab CI
        "GL-001":   ["SR-3", "SR-11", "SI-2"],
        "GL-002":   ["SI-7", "SA-11", "CM-6"],
        "GL-003":   ["IA-5"],
        "GL-004":   ["SA-10", "AC-3"],
        "GL-005":   ["SR-3", "SR-11", "CM-6"],
        # Bitbucket Pipelines
        "BB-001":   ["SR-3", "SR-11", "SI-2"],
        "BB-002":   ["SI-7", "SA-11", "CM-6"],
        "BB-003":   ["IA-5"],
        "BB-004":   ["SA-10", "AC-3"],
        "BB-005":   ["CM-6"],
    },
)
