# NIST Secure Software Development Framework (SP 800-218 v1.1)

- **Version:** SP 800-218 v1.1
- **URL:** https://csrc.nist.gov/pubs/sp/800/218/final
- **Scope:** Tasks in the Prepare the Organization (PO), Protect the
  Software (PS), Produce Well-Secured Software (PW), and Respond to
  Vulnerabilities (RV) practice areas whose evidence can be collected
  from CI/CD configuration state.

## Tasks evidenced

| Task   | Title                                                                             |
|--------|-----------------------------------------------------------------------------------|
| PO.3.2 | Implement and maintain supporting toolchains with security controls               |
| PO.3.3 | Configure the toolchain to generate an audit trail of SDLC activities             |
| PO.5.1 | Separate and protect each environment involved in software development            |
| PS.1.1 | Store all forms of code based on least-privilege and tamper-resistance            |
| PS.2.1 | Make software integrity verification information available                        |
| PS.3.1 | Securely archive the necessary files and data for each software release           |
| PS.3.2 | Collect, safeguard, maintain, and share provenance data                           |
| PW.4.1 | Acquire and maintain well-secured 3rd-party software components                   |
| PW.4.4 | Verify that acquired components behave as expected                                |
| PW.9.1 | Configure software to have secure settings by default                             |
| RV.1.1 | Gather information about potential vulnerabilities in released software           |

## Mapping to checks

Each row below pairs a `check_id` with the SSDF tasks its passing state
evidences. Source of truth:
`pipeline_check/core/standards/data/nist_ssdf.py` — regenerate with
`python scripts/gen_standards_mappings.py nist_ssdf`.

| Check | Control(s) |
|-------|------------|
| `ADO-001` | `PW.4.1` · `PW.4.4` |
| `ADO-002` | `PW.6.1` · `PW.9.1` |
| `ADO-003` | `PS.1.1` |
| `ADO-004` | `PO.5.1` |
| `ADO-005` | `PW.4.1` · `PW.4.4` |
| `BB-001` | `PW.4.1` · `PW.4.4` |
| `BB-002` | `PW.6.1` · `PW.9.1` |
| `BB-003` | `PS.1.1` |
| `BB-004` | `PO.5.1` |
| `BB-005` | `PO.5.2` · `PW.9.1` |
| `CB-001` | `PS.1.1` |
| `CB-002` | `PO.5.1` · `PW.9.1` |
| `CB-003` | `PO.3.3` |
| `CB-004` | `PO.5.2` · `PW.9.1` |
| `CB-005` | `PW.4.1` · `PW.4.4` · `RV.1.1` |
| `CB-006` | `PS.1.1` |
| `CB-007` | `PO.5.1` · `PW.9.1` |
| `CC-001` | `PW.4.1` · `PW.4.4` |
| `CC-002` | `PW.6.1` · `PW.9.1` |
| `CC-003` | `PW.4.1` · `PW.4.4` |
| `CC-004` | `PS.1.1` |
| `CC-005` | `PS.1.1` |
| `CC-006` | `PS.2.1` · `PS.3.2` |
| `CC-007` | `PS.3.2` |
| `CC-008` | `PS.1.1` |
| `CC-009` | `PO.5.1` |
| `CC-010` | `PO.5.2` · `PW.9.1` |
| `CC-011` | `PO.3.3` |
| `CC-012` | `PW.6.1` · `PW.9.1` |
| `CC-013` | `PO.5.1` |
| `CC-014` | `PO.5.1` · `PO.5.2` |
| `CC-015` | `PO.5.2` · `PW.9.1` |
| `CC-016` | `PW.4.1` · `PW.4.4` |
| `CC-017` | `PO.5.2` · `PW.9.1` |
| `CC-018` | `PW.4.1` · `PW.4.4` |
| `CC-019` | `PS.1.1` |
| `CC-020` | `RV.1.1` |
| `CC-021` | `PW.4.4` |
| `CC-022` | `PW.4.1` |
| `CC-023` | `PW.4.4` |
| `CD-001` | `PO.3.2` |
| `CD-002` | `PO.5.1` |
| `CD-003` | `PO.3.3` · `RV.1.1` |
| `CP-001` | `PO.5.1` |
| `CP-002` | `PS.1.1` · `PS.3.1` |
| `CP-003` | `PO.3.2` |
| `CP-004` | `PS.1.1` |
| `ECR-001` | `PW.4.4` · `RV.1.1` |
| `ECR-002` | `PS.3.1` · `PS.3.2` |
| `ECR-003` | `PO.5.1` · `PS.1.1` |
| `ECR-004` | `PO.3.2` |
| `ECR-005` | `PS.1.1` |
| `GHA-001` | `PW.4.1` · `PW.4.4` |
| `GHA-002` | `PO.5.1` · `PW.9.1` |
| `GHA-003` | `PW.6.1` · `PW.9.1` |
| `GHA-004` | `PO.5.1` |
| `GHA-005` | `PS.1.1` |
| `GL-001` | `PW.4.1` · `PW.4.4` |
| `GL-002` | `PW.6.1` · `PW.9.1` |
| `GL-003` | `PS.1.1` |
| `GL-004` | `PO.5.1` |
| `GL-005` | `PW.4.1` · `PW.4.4` |
| `IAM-001` | `PO.5.1` |
| `IAM-002` | `PO.5.1` |
| `IAM-003` | `PO.5.1` |
| `IAM-004` | `PO.5.1` |
| `IAM-005` | `PO.5.1` |
| `IAM-006` | `PO.5.1` |
| `PBAC-001` | `PO.5.1` · `PO.3.2` |
| `PBAC-002` | `PO.5.1` · `PO.3.2` |
| `S3-001` | `PS.1.1` |
| `S3-002` | `PS.1.1` · `PS.3.1` |
| `S3-003` | `PS.3.1` · `PS.3.2` |
| `S3-004` | `PO.3.3` |
| `S3-005` | `PS.1.1` |

## Not covered

Tasks requiring SCM policy introspection (PO.1 governance, PO.2
role assignment), human process (PW.7 code review), or incident response
telemetry (RV.2, RV.3) are out of scope for a CI/CD configuration scan.
