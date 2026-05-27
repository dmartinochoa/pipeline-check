"""CIS Google Cloud Platform Foundations Benchmark v3.0.0, CI/CD-relevant subset.

Only the controls this scanner's checks can evidence are included.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="cis_gcp_foundations",
    title="CIS Google Cloud Platform Foundations Benchmark",
    version="3.0.0",
    url="https://www.cisecurity.org/benchmark/google_cloud_computing_platform",
    controls={
        # Identity and Access Management
        "1.4": "Ensure that Service Account has no Admin privileges",
        "1.5": "Ensure that Service Account Keys are managed and rotated",
        "1.6": "Ensure IAM Users are not assigned SA User or Token Creator roles at project level",
        # Logging and Monitoring
        "2.1": "Ensure Cloud Audit Logging is configured properly for all services and all users in a project",
        "2.2": "Ensure that sinks are configured for all log entries",
        "2.3": "Ensure log metric filter and alerts exist for Audit Configuration changes",
        "2.12": "Ensure that Cloud Audit Logging is configured properly",
        # Storage
        "5.1": "Ensure that Cloud Storage bucket is not anonymously or publicly accessible",
        "5.2": "Ensure that Cloud Storage buckets have uniform bucket-level access enabled",
        # KMS
        "7.1": "Ensure KMS Encryption Keys are rotated within a period of 365 days",
        "7.2": "Ensure KMS Encryption Keys are not anonymously or publicly accessible",
        "7.3": "Ensure KMS keys are protected by a Hardware Security Module (HSM)",
    },
    mappings={
        # IAM
        "GCIAM-001": ["1.4"],
        "GCIAM-002": ["1.5"],
        "GCIAM-003": ["1.6"],
        # Logging
        "GCLOG-001": ["2.1", "2.12"],
        "GCLOG-002": ["2.2"],
        "GCLOG-003": ["2.3"],
        # Storage
        "GCS-001": ["5.1"],
        "GCS-002": ["5.2"],
        "GCS-003": ["5.1"],
        # KMS
        "GCKMS-001": ["7.1"],
        "GCKMS-002": ["7.2"],
        "GCKMS-003": ["7.3"],
        # Artifact Registry (no direct CIS control, mapped to closest)
        "GAR-001": ["5.1"],
        "GAR-002": ["5.1"],
        "GAR-003": ["5.1"],
    },
)
