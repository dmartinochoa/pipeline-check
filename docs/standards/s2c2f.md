# Secure Supply Chain Consumption Framework

- **Version:** 2024-05
- **URL:** https://github.com/ossf/s2c2f/blob/main/specification/framework.md
- **Scope:** CI/CD-relevant controls only. Findings evidence gaps, not full attestation.

## Controls

| ID    | Title |
|-------|-------|
| ING-1 | L1: Use package managers trusted by your organization |
| ING-3 | L1: Have the capability to deny-list specific vulnerable / malicious OSS |
| SCA-1 | L1: Scan OSS for known vulnerabilities |
| SCA-3 | L2: Scan OSS for malware |
| UPD-1 | L1: Update vulnerable OSS manually (pin + track versions) |
| UPD-2 | L3: Enable automated OSS updates (Dependabot / Renovate) |
| ENF-1 | L2: Enforce security policy of OSS usage (block on violation) |
| ENF-2 | L2: Break the build when a violation is detected |
| REB-2 | L4: Digitally sign rebuilt / produced OSS artifacts |
| REB-3 | L4: Generate SBOMs for artifacts produced |
| REB-4 | L4: Digitally sign SBOMs produced (attested provenance) |

## Mapping to checks

| Control | Checks |
|-------|--------|
| ING-1 | ADO-018, ADO-028, BB-014, BB-027, CA-002, CC-018, CC-028, ECR-006, GHA-018, GHA-029, GL-018, GL-027, JF-018, JF-031 |
| ING-3 | CA-002 |
| SCA-1 | ADO-020, BB-015, CC-020, ECR-001, ECR-007, GCB-008, GHA-020, GL-019, JF-020 |
| SCA-3 | ADO-026, BB-025, CB-011, CC-026, GHA-027, GL-025, JF-029 |
| UPD-1 | ADO-001, ADO-005, ADO-009, ADO-021, ADO-025, BB-001, BB-009, BB-021, CB-005, CB-009, CC-001, CC-003, CC-021, CC-029, ECR-002, GCB-001, GHA-001, GHA-021, GHA-025, GL-001, GL-005, GL-009, GL-021, GL-028, GL-030, JF-001, JF-009, JF-021 |
| UPD-2 | ADO-022, BB-022, CC-022, GHA-022, GL-022, JF-022 |
| ENF-1 | ADO-004, BB-004, CB-008, CC-009, CD-002, CP-001, CP-005, GHA-014, GL-004, JF-005, JF-024 |
| ENF-2 | CP-001, CP-005, GL-004, GL-029 |
| REB-2 | ADO-006, BB-006, CA-001, CC-006, CP-002, ECR-005, GCB-009, GHA-006, GL-006, JF-006, LMB-001, SIGN-001, SIGN-002 |
| REB-3 | ADO-007, BB-007, CC-007, GHA-007, GL-007, JF-007 |
| REB-4 | ADO-024, BB-024, CC-024, GHA-024, GL-024, JF-028 |

## Summary

- Checks with mappings: **101**
- Control-to-check mappings: **105** (some checks map to multiple controls)
- Controls with at least one check: **11** / 11
