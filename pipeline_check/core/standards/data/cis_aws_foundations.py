"""CIS AWS Foundations Benchmark v3.0.0 — subset covering CI/CD-relevant controls.

Only the controls this scanner's checks can evidence are included. A single
pipeline_check check may satisfy evidence for multiple CIS controls; likewise,
a given CIS control may be supported by multiple checks.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="cis_aws_foundations",
    title="CIS AWS Foundations Benchmark",
    version="3.0.0",
    url="https://www.cisecurity.org/benchmark/amazon_web_services",
    controls={
        # IAM
        "1.16": "Ensure IAM policies that allow full '*:*' administrative privileges are not attached",
        "1.17": "Ensure a support role has been created to manage incidents with AWS Support",
        # Logging
        "3.6":  "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
        "3.8":  "Ensure rotation for customer-created symmetric CMKs is enabled",
        # Storage
        "2.1.1": "Ensure all S3 buckets employ encryption-at-rest",
        "2.1.2": "Ensure S3 Bucket Policy is set to deny HTTP requests",
        "2.1.4": "Ensure that S3 Buckets are configured with 'Block public access'",
    },
    mappings={
        # IAM-001 (AdministratorAccess attached) ↔ CIS 1.16 full admin privileges
        "IAM-001": ["1.16"],
        # IAM-002 (wildcard action) ↔ CIS 1.16
        "IAM-002": ["1.16"],
        # S3 bucket encryption / public access / HTTPS
        "S3-001": ["2.1.4"],  # public access block
        "S3-002": ["2.1.1"],  # encryption at rest
        "S3-003": ["2.1.2"],  # HTTPS-only bucket policy
        "S3-004": ["3.6"],    # access logging
    },
)
