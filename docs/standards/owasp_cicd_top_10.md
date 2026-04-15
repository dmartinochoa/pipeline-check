# OWASP Top 10 CI/CD Security Risks

- **Version:** 2022
- **URL:** https://owasp.org/www-project-top-10-ci-cd-security-risks/
- **Scope:** Applies to every check emitted by this scanner.

## Controls

| ID           | Title                                      |
|--------------|--------------------------------------------|
| CICD-SEC-1   | Insufficient Flow Control Mechanisms       |
| CICD-SEC-2   | Inadequate Identity and Access Management  |
| CICD-SEC-3   | Dependency Chain Abuse                     |
| CICD-SEC-4   | Poisoned Pipeline Execution                |
| CICD-SEC-5   | Insufficient PBAC                          |
| CICD-SEC-6   | Insufficient Credential Hygiene            |
| CICD-SEC-7   | Insecure System Configuration              |
| CICD-SEC-8   | Ungoverned Usage of 3rd-Party Services     |
| CICD-SEC-9   | Improper Artifact Integrity Validation     |
| CICD-SEC-10  | Insufficient Logging and Visibility        |

## Mapping to checks

| Control      | Checks                                                     |
|--------------|------------------------------------------------------------|
| CICD-SEC-1   | CP-001, CD-001, CD-002                                     |
| CICD-SEC-2   | CB-000, CP-000, CD-000, ECR-000, IAM-000, IAM-001, IAM-002, IAM-003 |
| CICD-SEC-3   | ECR-001                                                    |
| CICD-SEC-4   | CP-003                                                     |
| CICD-SEC-5   | PBAC-000, PBAC-001, PBAC-002                               |
| CICD-SEC-6   | CB-001                                                     |
| CICD-SEC-7   | CB-002, CB-004, CB-005, ECR-004                            |
| CICD-SEC-8   | ECR-003                                                    |
| CICD-SEC-9   | CP-002, ECR-002, S3-001, S3-002, S3-003                    |
| CICD-SEC-10  | CB-003, CD-003, S3-004                                     |
