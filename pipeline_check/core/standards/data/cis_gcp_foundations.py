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
        # Networking
        "3.1": "Ensure the default network does not exist in a project",
        "3.6": "Ensure that SSH access is restricted from the Internet",
        "3.7": "Ensure that RDP access is restricted from the Internet",
        "3.8": "Ensure that VPC flow logs are enabled for every subnet in a VPC network",
        "3.9": "Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites",
        "3.10": "Ensure firewall rules logging is enabled",
        # Compute
        "4.1": "Ensure that instances are not configured to use default service accounts",
        "4.2": "Ensure that instances are not configured to use default service accounts with full access to all Cloud APIs",
        "4.3": "Ensure 'Block Project-wide SSH keys' is enabled for VM instances",
        "4.4": "Ensure oslogin is enabled for a project",
        "4.5": "Ensure 'Enable connecting to serial ports' is not enabled for a VM instance",
        "4.6": "Ensure that IP forwarding is not enabled on instances",
        "4.11": "Ensure Compute instances are launched with Shielded VM enabled",
        # Cloud SQL
        "6.1": "Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges",
        "6.2": "Ensure 'skip_show_database' database flag for Cloud SQL MySQL instance is set to 'on'",
        "6.5": "Ensure that Cloud SQL database instances are not open to the world",
        "6.6": "Ensure that Cloud SQL database instances do not have public IPs",
        "6.7": "Ensure that Cloud SQL database instances are configured with automated backups",
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
        # ── Phase-2 GCP rules ────────────────────────────────────────
        "GCIAM-004": ["4.1", "4.2"],                       # default SA
        "GCIAM-005": ["1.4"],                              # domain restrict
        "GCIAM-006": ["1.5"],                              # SA key age
        "GCS-004":   ["5.1"],                              # CMEK
        "GCS-005":   ["5.1"],                              # access logging
        "GCLOG-004": ["3.8"],                              # VPC flow logs
        "GCLOG-005": ["3.10"],                             # firewall logging
        "GCLOG-006": ["2.1", "2.12"],                      # data access
        "GCLOG-007": ["2.3"],                              # metric filter IAM
        "GCLOG-008": ["2.3"],                              # metric filter firewall
        "GCLOG-009": ["2.3"],                              # metric filter route
        "GCLOG-010": ["2.3"],                              # metric filter SQL
        "GCLOG-011": ["2.3"],                              # metric filter custom role
        "GCNET-001": ["3.1"],                              # default network
        "GCNET-002": ["3.9"],                              # deny-all
        "GCNET-003": ["3.6", "3.7"],                       # SSH/RDP (CRITICAL)
        "GCNET-004": ["3.8"],                              # private access
        "GCNET-005": ["3.8"],                              # Cloud NAT
        "GCCE-001":  ["4.11"],                             # shielded VM
        "GCCE-002":  ["4.4"],                              # OS Login
        "GCCE-003":  ["4.5"],                              # serial port
        "GCCE-004":  ["4.6"],                              # public IP
        "GCCE-005":  ["4.3"],                              # project SSH keys
        "GCSQL-001": ["6.5", "6.6"],                       # public IP
        "GCSQL-002": ["6.7"],                              # backups
        "GCSQL-003": ["6.1"],                              # SSL
        "GCSQL-004": ["6.1"],                              # IAM auth
        "GCSQL-005": ["6.7"],                              # PITR
        "GCRUN-001": ["1.4"],                              # unauth
        "GCRUN-002": ["4.1"],                              # custom SA
        "GCRUN-003": ["4.1"],                              # min instances
        "GCRUN-004": ["3.8"],                              # VPC connector
        "GCKMS-004": ["7.2"],                              # keyring IAM
        "GCKMS-005": ["7.1"],                              # destroy sched
        "GCKMS-006": ["7.3"],                              # imported key
    },
)
