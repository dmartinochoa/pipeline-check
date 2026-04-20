# OpenSSF Scorecard

- **Version:** 5
- **URL:** https://github.com/ossf/scorecard/blob/main/docs/checks.md
- **Scope:** CI/CD-relevant controls only. Findings evidence gaps, not full attestation.

## Controls

| ID                     | Title |
|------------------------|-------|
| Code-Review            | Changes merged to the default branch require review |
| Dangerous-Workflow     | No dangerous patterns in CI workflows (untrusted checkout, script injection) |
| Dependency-Update-Tool | Project uses an automated dependency-update tool (Dependabot / Renovate) |
| Pinned-Dependencies    | Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources |
| SAST                   | Project uses static analysis / vulnerability scanning |
| SBOM                   | Releases publish a software bill of materials |
| Signed-Releases        | Release artifacts are cryptographically signed |
| Token-Permissions      | CI tokens are scoped to the minimum required permissions |
| Vulnerabilities        | Project scans for and resolves known vulnerabilities |

## Mapping to checks

| Control                | Checks |
|------------------------|--------|
| Code-Review            | ADO-004, BB-004, CB-008, CC-009, CCM-001, CD-002, CP-001, CP-005, GHA-014, GL-004, GL-029, JF-005, JF-024, JF-026 |
| Dangerous-Workflow     | ADO-002, ADO-011, ADO-012, ADO-016, ADO-019, ADO-023, ADO-026, ADO-027, BB-002, BB-012, BB-018, BB-023, BB-025, BB-026, CB-010, CB-011, CC-002, CC-012, CC-013, CC-016, CC-023, CC-025, CC-026, CC-027, CP-003, CP-007, GCB-004, GCB-006, GHA-002, GHA-003, GHA-009, GHA-010, GHA-011, GHA-013, GHA-016, GHA-023, GHA-026, GHA-027, GHA-028, GL-002, GL-011, GL-012, GL-016, GL-023, GL-025, GL-026, JF-002, JF-012, JF-013, JF-016, JF-019, JF-023, JF-029, JF-030 |
| Dependency-Update-Tool | ADO-022, BB-022, CC-022, GHA-022, GL-022, JF-022 |
| Pinned-Dependencies    | ADO-001, ADO-005, ADO-009, ADO-018, ADO-021, ADO-025, ADO-028, BB-001, BB-009, BB-014, BB-021, BB-027, CA-002, CB-005, CB-009, CC-001, CC-003, CC-018, CC-021, CC-028, CC-029, ECR-002, ECR-006, GCB-001, GHA-001, GHA-018, GHA-021, GHA-025, GHA-029, GL-001, GL-005, GL-009, GL-018, GL-021, GL-027, GL-028, GL-030, JF-001, JF-009, JF-018, JF-021, JF-031 |
| SAST                   | ADO-020, BB-015, CC-020, ECR-001, ECR-007, GCB-008, GHA-020, GL-019, JF-020 |
| SBOM                   | ADO-007, BB-007, CC-007, GHA-007, GL-007, JF-007 |
| Signed-Releases        | ADO-006, ADO-024, BB-006, BB-024, CA-001, CC-006, CC-024, CP-002, ECR-005, GCB-009, GHA-006, GHA-024, GL-006, GL-024, JF-006, JF-028, LMB-001, SIGN-001, SIGN-002 |
| Token-Permissions      | ADO-003, ADO-008, ADO-014, BB-003, BB-008, BB-011, BB-017, BB-019, CA-004, CB-001, CB-006, CC-005, CC-008, CC-019, CC-030, CCM-003, CP-004, GCB-002, GCB-003, GCB-007, GHA-004, GHA-005, GHA-008, GHA-019, GL-003, GL-008, GL-013, GL-020, IAM-001, IAM-002, IAM-003, IAM-004, IAM-005, IAM-006, IAM-007, IAM-008, JF-004, JF-008, JF-010, KMS-001, KMS-002, LMB-002, LMB-003, LMB-004, SM-001, SM-002, SSM-001, SSM-002 |
| Vulnerabilities        | ADO-020, BB-015, CC-020, ECR-001, ECR-007, GCB-008, GHA-020, GL-019, JF-020 |

## Summary

- Checks with mappings: **198**
- Control-to-check mappings: **207** (some checks map to multiple controls)
- Controls with at least one check: **9** / 9
