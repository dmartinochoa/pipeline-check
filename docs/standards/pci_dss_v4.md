# PCI DSS v4.0 (CI/CD subset)

- **Version:** 4.0
- **URL:** https://www.pcisecuritystandards.org/document_library/
- **Scope:** Requirements whose evidence can be collected from CI/CD
  configuration state. Requirements around network segmentation
  (Req 1), physical security (Req 9), cryptographic key lifecycles
  (Req 3), and cardholder-data handling are out of scope.

## Requirements evidenced

| Requirement | Description                                                                       |
|-------------|-----------------------------------------------------------------------------------|
| 6.3.1       | Security vulnerabilities are identified and managed                               |
| 6.3.3       | System components protected from known vulnerabilities by installing patches      |
| 6.4.1       | Public-facing web apps are protected (secure build/config)                        |
| 6.4.3       | Changes to systems are managed via documented change control                      |
| 6.5.1       | Changes to system components follow secure development procedures                 |
| 7.2.1       | Access control is defined per job role with least privilege                       |
| 7.2.2       | Access is assigned based on job classification and function                       |
| 7.2.5       | System and application accounts have least-privilege access                       |
| 8.2.1       | Strong unique identifiers are assigned to each user and service account           |
| 8.2.2       | Group, shared, or generic accounts are managed and justified                      |
| 10.2.1      | Audit logs are enabled and active for all system components                       |
| 10.3.2      | Audit logs are protected from unauthorized modifications                          |
| 10.3.3      | Audit logs are promptly backed up to a centralized log server                     |

## Mapping to checks

Each row below pairs a `check_id` with the PCI DSS requirements its
passing state evidences. Source of truth:
`pipeline_check/core/standards/data/pci_dss_v4.py` — regenerate with
`python scripts/gen_standards_mappings.py pci_dss_v4`.

| Check | Control(s) |
|-------|------------|
| `ADO-001` | `6.3.3` |
| `ADO-002` | `6.5.1` |
| `ADO-003` | `8.2.1` · `6.5.1` |
| `ADO-004` | `6.4.3` |
| `ADO-005` | `6.3.3` |
| `BB-001` | `6.3.3` |
| `BB-002` | `6.5.1` |
| `BB-003` | `8.2.1` · `6.5.1` |
| `BB-004` | `6.4.3` |
| `BB-005` | `6.4.1` |
| `CB-001` | `6.5.1` · `8.2.1` |
| `CB-002` | `6.4.1` · `6.5.1` |
| `CB-003` | `10.2.1` |
| `CB-004` | `6.4.1` |
| `CB-005` | `6.3.3` |
| `CB-006` | `8.2.1` |
| `CB-007` | `6.4.1` |
| `CC-001` | `6.3.3` |
| `CC-002` | `6.5.1` |
| `CC-003` | `6.3.3` |
| `CC-004` | `8.2.1` · `6.5.1` |
| `CC-005` | `8.2.1` |
| `CC-006` | `6.5.1` · `10.3.2` |
| `CC-007` | `6.5.1` |
| `CC-008` | `8.2.1` · `6.5.1` |
| `CC-009` | `6.4.3` |
| `CC-010` | `6.4.1` |
| `CC-011` | `10.2.1` |
| `CC-012` | `6.5.1` |
| `CC-013` | `6.4.3` |
| `CC-014` | `7.2.5` |
| `CC-015` | `6.4.1` |
| `CC-016` | `6.3.3` |
| `CC-017` | `6.4.1` |
| `CC-018` | `6.3.3` |
| `CC-019` | `8.2.1` |
| `CC-020` | `6.3.1` · `6.3.3` |
| `CC-021` | `6.3.3` |
| `CC-022` | `6.3.3` |
| `CC-023` | `6.5.1` |
| `CD-001` | `6.4.3` |
| `CD-002` | `6.4.3` |
| `CD-003` | `10.2.1` |
| `CP-001` | `6.4.3` · `6.5.1` |
| `CP-002` | `6.5.1` · `10.3.2` |
| `CP-003` | `6.4.1` |
| `CP-004` | `8.2.1` |
| `ECR-001` | `6.3.1` · `6.3.3` |
| `ECR-002` | `6.5.1` · `10.3.2` |
| `ECR-003` | `7.2.5` |
| `ECR-004` | `6.5.1` |
| `ECR-005` | `10.3.2` |
| `GHA-001` | `6.3.3` |
| `GHA-002` | `6.5.1` |
| `GHA-003` | `6.5.1` |
| `GHA-004` | `7.2.5` |
| `GHA-005` | `8.2.1` |
| `GL-001` | `6.3.3` |
| `GL-002` | `6.5.1` |
| `GL-003` | `8.2.1` · `6.5.1` |
| `GL-004` | `6.4.3` |
| `GL-005` | `6.3.3` |
| `IAM-001` | `7.2.1` · `7.2.5` |
| `IAM-002` | `7.2.1` · `7.2.5` |
| `IAM-003` | `7.2.5` |
| `IAM-004` | `7.2.5` |
| `IAM-005` | `7.2.1` |
| `IAM-006` | `7.2.5` |
| `PBAC-001` | `6.4.1` |
| `PBAC-002` | `7.2.5` · `8.2.2` |
| `S3-001` | `10.3.2` |
| `S3-002` | `10.3.2` |
| `S3-003` | `10.3.2` |
| `S3-004` | `10.2.1` · `10.3.3` |
| `S3-005` | `10.3.2` |

## Not covered

- Cardholder data discovery and handling (Req 3)
- Network segmentation and firewall rules (Req 1)
- MFA enforcement on interactive logins (Req 8.3–8.5) — requires IdP
  inspection outside the CI/CD surface.
