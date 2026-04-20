# NIST Cybersecurity Framework 2.0

- **Version:** 2.0
- **URL:** https://doi.org/10.6028/NIST.CSWP.29
- **Scope:** CI/CD-relevant controls only. Findings evidence gaps, not full attestation.

## Controls

| ID       | Title |
|----------|-------|
| GV.SC-03 | Cybersecurity supply chain risk management is integrated into CS and ERM programs |
| GV.SC-04 | Suppliers are known and prioritized by criticality |
| GV.SC-05 | Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts |
| GV.SC-07 | Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored |
| GV.SC-08 | Relevant suppliers and other third parties are included in incident planning, response, and recovery activities |
| PR.AA-01 | Identities and credentials for authorized users, services, and hardware are managed |
| PR.AA-03 | Users, services, and hardware are authenticated |
| PR.AA-05 | Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed |
| PR.DS-01 | The confidentiality, integrity, and availability of data-at-rest are protected |
| PR.DS-02 | The confidentiality, integrity, and availability of data-in-transit are protected |
| PR.PS-01 | Configuration management practices are established and applied |
| PR.PS-02 | Software is maintained, replaced, and removed commensurate with risk |
| PR.PS-04 | Log records are generated and made available for continuous monitoring |
| PR.PS-05 | Installation and execution of unauthorized software are prevented |
| PR.PS-06 | Secure software development practices are integrated, and their performance is monitored throughout the SDLC |
| PR.IR-01 | Networks and environments are protected from unauthorized logical access and usage |
| PR.IR-03 | Mechanisms are implemented to achieve resilience requirements in normal and adverse situations |
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events |
| DE.CM-06 | External service provider activities and services are monitored |
| DE.CM-09 | Computing hardware and software, runtime environments, and their data are monitored |
| DE.AE-03 | Information is correlated from multiple sources |
| RS.MA-01 | The incident response plan is executed once an incident is declared |
| RC.RP-01 | The recovery portion of the incident response plan is executed once initiated |

## Mapping to checks

| Control  | Checks |
|----------|--------|
| GV.SC-03 | ADO-007, BB-007, CC-007, GHA-007, GL-007, JF-007 |
| GV.SC-04 | ADO-007, ADO-018, BB-007, BB-014, CA-002, CC-007, CC-018, ECR-006, GHA-007, GHA-018, GL-007, GL-018, JF-007, JF-018 |
| GV.SC-05 | ADO-001, ADO-005, ADO-009, ADO-021, ADO-025, ADO-028, BB-001, BB-009, BB-021, BB-027, CB-009, CC-001, CC-003, CC-021, CC-028, CC-029, ECR-002, GCB-001, GHA-001, GHA-021, GHA-025, GHA-029, GL-001, GL-005, GL-009, GL-021, GL-027, GL-028, GL-030, JF-001, JF-009, JF-021, JF-031 |
| GV.SC-07 | ADO-001, ADO-022, BB-001, BB-022, CA-002, CB-005, CC-001, CC-022, ECR-006, GHA-001, GHA-022, GL-001, GL-022, JF-001, JF-022 |
| GV.SC-08 | _(organizational control — no direct pipeline signal)_ |
| PR.AA-01 | ADO-003, ADO-008, ADO-014, BB-003, BB-008, BB-011, BB-017, BB-019, CB-001, CB-006, CC-005, CC-008, CC-019, CP-004, GCB-003, GCB-007, GHA-005, GHA-008, GHA-019, GL-003, GL-008, GL-013, GL-020, IAM-005, IAM-007, JF-004, JF-008, JF-010, SM-001, SSM-001 |
| PR.AA-03 | GCB-002, IAM-005, IAM-008 |
| PR.AA-05 | CA-004, CC-030, CCM-003, GHA-004, IAM-001, IAM-002, IAM-003, IAM-004, IAM-006, KMS-002, SM-002 |
| PR.DS-01 | CA-001, CP-002, ECR-005, KMS-001, LMB-003, S3-002, S3-003, SSM-002 |
| PR.DS-02 | ADO-023, BB-023, CC-023, GHA-023, GL-023, JF-023, S3-005 |
| PR.PS-01 | ADO-013, ADO-015, ADO-017, BB-005, BB-013, BB-016, BB-020, CB-002, CB-004, CC-010, CC-014, CC-015, CC-017, GCB-005, GHA-012, GHA-015, GHA-017, GHA-026, GL-014, GL-015, GL-017, JF-003, JF-014, JF-015, JF-017, JF-025 |
| PR.PS-02 | ADO-020, BB-015, CB-005, CC-020, ECR-001, ECR-002, ECR-007, GCB-008, GHA-020, GL-019, JF-020 |
| PR.PS-04 | CB-003, CC-011, CT-001, CT-002, CT-003, CWL-001, CWL-002, JF-011, S3-004 |
| PR.PS-05 | ADO-002, ADO-016, ADO-026, ADO-027, BB-002, BB-012, BB-025, BB-026, CB-011, CC-002, CC-016, CC-026, CC-027, GCB-004, GCB-006, GHA-003, GHA-016, GHA-027, GHA-028, GL-002, GL-016, GL-025, GL-026, JF-002, JF-012, JF-016, JF-019, JF-029, JF-030 |
| PR.PS-06 | ADO-006, ADO-024, BB-006, BB-024, CC-006, CC-024, GCB-009, GHA-006, GHA-024, GL-006, GL-024, JF-006, JF-028, LMB-001, SIGN-001, SIGN-002 |
| PR.IR-01 | ADO-010, ADO-011, ADO-012, ADO-019, BB-010, BB-018, CC-012, CC-013, CC-025, CP-003, CP-007, ECR-003, GHA-002, GHA-009, GHA-010, GHA-011, GHA-013, GL-010, GL-011, GL-012, JF-013, LMB-002, LMB-004, PBAC-001, PBAC-002, PBAC-003, PBAC-005, S3-001 |
| PR.IR-03 | CD-001, CD-003, S3-003 |
| DE.CM-01 | S3-004 |
| DE.CM-06 | CB-007, EB-002 |
| DE.CM-09 | CB-003, CT-001, CT-002, CT-003, CW-001, CWL-001, CWL-002, EB-001 |
| DE.AE-03 | CT-002, S3-004 |
| RS.MA-01 | CD-003 |
| RC.RP-01 | CD-001, S3-003 |

## Controls without direct check coverage

The following controls are listed above for completeness but have
no checks mapped to them in this scanner — they typically require
process evidence, runtime telemetry, or audit artefacts outside
the pipeline-config surface.

- **GV.SC-08** — Relevant suppliers and other third parties are included in incident planning, response, and recovery activities

## Summary

- Checks with mappings: **235**
- Control-to-check mappings: **265** (some checks map to multiple controls)
- Controls with at least one check: **22** / 23
