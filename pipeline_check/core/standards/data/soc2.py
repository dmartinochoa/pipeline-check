"""SOC 2 — Trust Services Criteria (AICPA).

SOC 2 organizes its Trust Services Criteria into five categories:
Security (required), Availability, Processing Integrity,
Confidentiality, and Privacy. The Security category is expressed via
the Common Criteria (CC1–CC9), which apply across all trust services.

This scanner evidences the CC-series criteria that have a concrete
CI/CD pipeline footprint — primarily CC6 (logical access), CC7
(system operations / anomaly detection), and CC8 (change management).
CC1 (control environment), CC2 (communication), CC3 (risk
assessment), CC4 (monitoring), CC5 (control activities), and CC9
(risk mitigation) are organizational/process criteria that don't
reduce to pipeline config and are intentionally unmapped.

The mappings are intentionally *indicative*, not *sufficient* — SOC 2
attestation requires auditor-reviewed evidence of control operation
over time, not just a point-in-time config scan. Findings here
identify *gaps* in the config substrate that typical SOC 2 controls
sit on top of; passing all mapped checks does not by itself demonstrate
compliance.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="soc2",
    title="SOC 2 Trust Services Criteria",
    version="2017 (revised 2022)",
    url="https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
    controls={
        # ── CC6 — Logical and Physical Access ───────────────────────
        "CC6.1": "Logical access controls restrict entities to authorized system resources",
        "CC6.2": "New internal and external users are registered, authorized, and provisioned",
        "CC6.3": "Access modifications (including revocation) are tracked and timely",
        "CC6.6": "Boundary-protection measures restrict access from outside the system boundary",
        "CC6.7": "Data in transit is protected from unauthorized disclosure",
        "CC6.8": "Controls prevent or detect the introduction of malicious software",
        # ── CC7 — System Operations ─────────────────────────────────
        "CC7.1": "Detection procedures identify configuration changes that introduce vulnerabilities",
        "CC7.2": "System components are monitored for anomalies indicative of malicious acts or failures",
        "CC7.3": "Security events are evaluated to determine if they require response",
        "CC7.4": "Identified security incidents trigger a response process",
        # ── CC8 — Change Management ─────────────────────────────────
        "CC8.1": (
            "Changes to infrastructure, data, software, and procedures are "
            "authorized, designed, tested, approved, and implemented"
        ),
    },
    mappings={
        # ── CC6.1 — Logical access controls ─────────────────────────
        "IAM-001":  ["CC6.1"],
        "IAM-002":  ["CC6.1"],
        "IAM-003":  ["CC6.1"],
        "IAM-004":  ["CC6.1"],
        "IAM-006":  ["CC6.1"],
        "KMS-002":  ["CC6.1"],
        "GHA-004":  ["CC6.1"],
        "GHA-019":  ["CC6.1"],
        "GL-020":   ["CC6.1"],
        "BB-017":   ["CC6.1"],
        "CC-030":   ["CC6.1"],
        "GCB-002":  ["CC6.1"],
        "CCM-003":  ["CC6.1"],
        "CA-004":   ["CC6.1"],
        "PBAC-001": ["CC6.1"],
        "PBAC-002": ["CC6.1"],
        "PBAC-003": ["CC6.1"],
        "PBAC-005": ["CC6.1"],

        # ── CC6.2 / CC6.3 — User provisioning & trust relationships ─
        "IAM-005":  ["CC6.2", "CC6.3"],    # relaxed external trust = weak provisioning
        "IAM-007":  ["CC6.3"],             # stale access keys = untimely revocation
        "IAM-008":  ["CC6.2"],             # OIDC audience pin = federated authz
        "CB-006":   ["CC6.3"],             # long-lived source token
        "CP-004":   ["CC6.3"],             # legacy OAuth = non-revocable token
        "GHA-005":  ["CC6.2", "CC6.3"],
        "GHA-008":  ["CC6.2"],
        "GL-003":   ["CC6.2"],
        "GL-008":   ["CC6.2"],
        "GL-013":   ["CC6.2", "CC6.3"],
        "BB-003":   ["CC6.2"],
        "BB-008":   ["CC6.2"],
        "BB-011":   ["CC6.2", "CC6.3"],
        "ADO-003":  ["CC6.2"],
        "ADO-008":  ["CC6.2"],
        "ADO-014":  ["CC6.2", "CC6.3"],
        "JF-004":   ["CC6.2", "CC6.3"],
        "JF-008":   ["CC6.2"],
        "JF-010":   ["CC6.2"],
        "CC-005":   ["CC6.2", "CC6.3"],
        "CC-008":   ["CC6.2"],
        "CC-019":   ["CC6.3"],
        "CB-001":   ["CC6.2"],
        "GCB-003":  ["CC6.2"],
        # GCB-007 co-maps: secret-alias (CC6.3) + drift-hide (CC7.1).
        "GCB-007":  ["CC6.3", "CC7.1"],

        # ── CC6.6 — Boundary protection ─────────────────────────────
        "CB-002":   ["CC6.6"],             # privileged mode breaks sandbox boundary
        "GHA-017":  ["CC6.6"],
        "GL-017":   ["CC6.6"],
        "BB-013":   ["CC6.6"],
        "ADO-017":  ["CC6.6"],
        "JF-017":   ["CC6.6"],
        "CC-017":   ["CC6.6"],
        "JF-025":   ["CC6.6"],             # k8s privileged
        "GHA-026":  ["CC6.6"],             # container egress
        "GHA-012":  ["CC6.6"],             # self-hosted runner
        "GL-014":   ["CC6.6"],
        "BB-016":   ["CC6.6"],
        "ADO-013":  ["CC6.6"],
        "JF-003":   ["CC6.6"],
        "JF-014":   ["CC6.6"],
        "CC-010":   ["CC6.6"],
        "ECR-003":  ["CC6.6"],             # public repo
        "S3-001":   ["CC6.6"],             # public artifact bucket
        "LMB-002":  ["CC6.6"],             # public Lambda URL
        "LMB-004":  ["CC6.6"],             # public Lambda policy
        "SM-002":   ["CC6.6"],             # Secrets Manager public
        "CP-003":   ["CC6.6"],             # polling source leaks cred to SCM
        "CP-007":   ["CC6.6"],

        # ── CC6.7 — Data in transit ─────────────────────────────────
        # S3-005 covers both boundary (6.6) and transit (6.7): the
        # bucket policy deny of non-TLS requests is a boundary control
        # whose effect is transit protection.
        "S3-005":   ["CC6.6", "CC6.7"],
        "GHA-023":  ["CC6.7"],
        "GL-023":   ["CC6.7"],
        "BB-023":   ["CC6.7"],
        "ADO-023":  ["CC6.7"],
        "JF-023":   ["CC6.7"],
        "CC-023":   ["CC6.7"],

        # ── CC6.8 — Malicious software prevention / detection ───────
        "CB-011":   ["CC6.8"],
        "GHA-003":  ["CC6.8"],             # script injection = malware vector
        "GHA-016":  ["CC6.8"],             # curl|bash = malware vector
        "GHA-020":  ["CC6.8"],             # vuln scanning
        "GHA-027":  ["CC6.8"],             # malicious activity
        "GHA-028":  ["CC6.8"],             # shell eval
        "GL-002":   ["CC6.8"],
        "GL-016":   ["CC6.8"],
        "GL-019":   ["CC6.8"],
        "GL-025":   ["CC6.8"],
        "GL-026":   ["CC6.8"],
        "BB-002":   ["CC6.8"],
        "BB-012":   ["CC6.8"],
        "BB-015":   ["CC6.8"],
        "BB-025":   ["CC6.8"],
        "BB-026":   ["CC6.8"],
        "ADO-002":  ["CC6.8"],
        "ADO-016":  ["CC6.8"],
        "ADO-020":  ["CC6.8"],
        "ADO-026":  ["CC6.8"],
        "ADO-027":  ["CC6.8"],
        "JF-002":   ["CC6.8"],
        "JF-016":   ["CC6.8"],
        "JF-020":   ["CC6.8"],
        "JF-029":   ["CC6.8"],
        "JF-030":   ["CC6.8"],
        "CC-002":   ["CC6.8"],
        "CC-016":   ["CC6.8"],
        "CC-020":   ["CC6.8"],
        "CC-026":   ["CC6.8"],
        "CC-027":   ["CC6.8"],
        "GCB-006":  ["CC6.8"],
        "GCB-008":  ["CC6.8"],
        "ECR-001":  ["CC6.8"],
        "ECR-007":  ["CC6.8"],

        # ── CC7.1 — Change-introduced vulnerability detection ──────
        "CB-005":   ["CC7.1"],             # outdated build image = unpatched vuln
        "ECR-002":  ["CC7.1"],             # mutable tags hide drift
        # GCB-007 co-mapped up under CC6.3.

        # ── CC7.2 — Monitoring for anomalies ───────────────────────
        "CB-003":   ["CC7.2"],             # build logs disabled
        "CT-001":   ["CC7.2"],
        "CT-002":   ["CC7.2"],
        "CT-003":   ["CC7.2"],
        "CWL-001":  ["CC7.2"],
        "CWL-002":  ["CC7.2"],
        "EB-001":   ["CC7.2"],
        "CW-001":   ["CC7.2"],
        "S3-003":   ["CC7.2"],             # versioning = tamper detection
        "S3-004":   ["CC7.2"],             # access logging
        "JF-011":   ["CC7.2"],             # build retention
        "CC-011":   ["CC7.2"],             # build retention

        # ── CC7.3 / CC7.4 — Event evaluation & response ────────────
        "CD-001":   ["CC7.4"],             # auto-rollback = response
        "CD-003":   ["CC7.3", "CC7.4"],    # CW alarm on deploy group

        # ── CC8.1 — Change management ──────────────────────────────
        # Approval gates
        "CP-001":   ["CC8.1"],
        "CP-005":   ["CC8.1"],
        "CD-002":   ["CC8.1"],
        "CCM-001":  ["CC8.1"],
        "CB-008":   ["CC8.1"],
        "GHA-014":  ["CC8.1"],
        "GL-004":   ["CC8.1"],
        "GL-029":   ["CC8.1"],
        "BB-004":   ["CC8.1"],
        "ADO-004":  ["CC8.1"],
        "JF-005":   ["CC8.1"],
        "JF-024":   ["CC8.1"],
        "JF-026":   ["CC8.1"],
        "CC-009":   ["CC8.1"],
        "CC-013":   ["CC8.1"],
        # Pinning (changes require explicit review, not silent drift)
        "GHA-001":  ["CC8.1"],
        "GHA-025":  ["CC8.1"],
        "GL-001":   ["CC8.1"],
        "GL-005":   ["CC8.1"],
        "BB-001":   ["CC8.1"],
        "ADO-001":  ["CC8.1"],
        "ADO-025":  ["CC8.1"],
        "JF-001":   ["CC8.1"],
        "CC-001":   ["CC8.1"],
        "GCB-001":  ["CC8.1"],
        # Integrity / attestation (change record)
        "SIGN-001": ["CC8.1"],
        "SIGN-002": ["CC8.1"],
        "GHA-024":  ["CC8.1"],
        "GL-024":   ["CC8.1"],
        "BB-024":   ["CC8.1"],
        "ADO-024":  ["CC8.1"],
        "JF-028":   ["CC8.1"],
        "CC-024":   ["CC8.1"],
        "GCB-009":  ["CC8.1"],
    },
)
