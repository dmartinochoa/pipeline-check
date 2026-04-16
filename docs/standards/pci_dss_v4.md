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
| 7.2.2       | Access is assigned based on job classification                                    |
| 7.2.5       | System and application accounts have least-privilege access                       |
| 8.2.1       | Strong unique identifiers are assigned to each user and service account           |
| 10.2.1      | Audit logs are enabled and active for all system components                       |
| 10.3.2      | Audit logs are protected from unauthorized modifications                          |
| 10.3.3      | Audit logs are promptly backed up to a centralized log server                     |

## Not covered

- Cardholder data discovery and handling (Req 3)
- Network segmentation and firewall rules (Req 1)
- MFA enforcement on interactive logins (Req 8.3–8.5) — requires IdP
  inspection outside the CI/CD surface.
