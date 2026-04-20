# SOC 2 Trust Services Criteria

- **Version:** 2017 (revised 2022)
- **URL:** https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
- **Scope:** CI/CD-relevant controls only. Findings evidence gaps, not full attestation.

## Controls

| ID    | Title |
|-------|-------|
| CC6.1 | Logical access controls restrict entities to authorized system resources |
| CC6.2 | New internal and external users are registered, authorized, and provisioned |
| CC6.3 | Access modifications (including revocation) are tracked and timely |
| CC6.6 | Boundary-protection measures restrict access from outside the system boundary |
| CC6.7 | Data in transit is protected from unauthorized disclosure |
| CC6.8 | Controls prevent or detect the introduction of malicious software |
| CC7.1 | Detection procedures identify configuration changes that introduce vulnerabilities |
| CC7.2 | System components are monitored for anomalies indicative of malicious acts or failures |
| CC7.3 | Security events are evaluated to determine if they require response |
| CC7.4 | Identified security incidents trigger a response process |
| CC8.1 | Changes to infrastructure, data, software, and procedures are authorized, designed, tested, approved, and implemented |

## Mapping to checks

| Control | Checks |
|-------|--------|
| CC6.1 | BB-017, CA-004, CC-030, CCM-003, GCB-002, GHA-004, GHA-019, GL-020, IAM-001, IAM-002, IAM-003, IAM-004, IAM-006, KMS-002, PBAC-001, PBAC-002, PBAC-003, PBAC-005 |
| CC6.2 | ADO-003, ADO-008, ADO-014, BB-003, BB-008, BB-011, CB-001, CC-005, CC-008, GCB-003, GHA-005, GHA-008, GL-003, GL-008, GL-013, IAM-005, IAM-008, JF-004, JF-008, JF-010 |
| CC6.3 | ADO-014, BB-011, CB-006, CC-005, CC-019, CP-004, GCB-007, GHA-005, GL-013, IAM-005, IAM-007, JF-004 |
| CC6.6 | ADO-013, ADO-017, BB-013, BB-016, CB-002, CC-010, CC-017, CP-003, CP-007, ECR-003, GHA-012, GHA-017, GHA-026, GL-014, GL-017, JF-003, JF-014, JF-017, JF-025, LMB-002, LMB-004, S3-001, S3-005, SM-002 |
| CC6.7 | ADO-023, BB-023, CC-023, GHA-023, GL-023, JF-023, S3-005 |
| CC6.8 | ADO-002, ADO-016, ADO-020, ADO-026, ADO-027, BB-002, BB-012, BB-015, BB-025, BB-026, CB-011, CC-002, CC-016, CC-020, CC-026, CC-027, ECR-001, ECR-007, GCB-006, GCB-008, GHA-003, GHA-016, GHA-020, GHA-027, GHA-028, GL-002, GL-016, GL-019, GL-025, GL-026, JF-002, JF-016, JF-020, JF-029, JF-030 |
| CC7.1 | CB-005, ECR-002, GCB-007 |
| CC7.2 | CB-003, CC-011, CT-001, CT-002, CT-003, CW-001, CWL-001, CWL-002, EB-001, JF-011, S3-003, S3-004 |
| CC7.3 | CD-003 |
| CC7.4 | CD-001, CD-003 |
| CC8.1 | ADO-001, ADO-004, ADO-024, ADO-025, BB-001, BB-004, BB-024, CB-008, CC-001, CC-009, CC-013, CC-024, CCM-001, CD-002, CP-001, CP-005, GCB-001, GCB-009, GHA-001, GHA-014, GHA-024, GHA-025, GL-001, GL-004, GL-005, GL-024, GL-029, JF-001, JF-005, JF-024, JF-026, JF-028, SIGN-001, SIGN-002 |

## Summary

- Checks with mappings: **158**
- Control-to-check mappings: **168** (some checks map to multiple controls)
- Controls with at least one check: **11** / 11
