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

| Control      | Checks                                                                 |
|--------------|------------------------------------------------------------------------|
| CICD-SEC-1   | CB-007, CP-001, CD-001, CD-002, GL-004, BB-004, ADO-004                |
| CICD-SEC-2   | IAM-001, IAM-002, IAM-003, IAM-004, IAM-005, IAM-006                   |
| CICD-SEC-3   | ECR-001, GHA-001, GL-001, GL-005, BB-001, ADO-001, ADO-005             |
| CICD-SEC-4   | CP-003, GHA-002, GHA-003, GL-002, BB-002, ADO-002                      |
| CICD-SEC-5   | PBAC-001, PBAC-002, GHA-004                                            |
| CICD-SEC-6   | CB-001, CB-006, CP-004, GHA-005, GL-003, BB-003, ADO-003               |
| CICD-SEC-7   | CB-002, CB-004, CB-005, ECR-004, BB-005                                |
| CICD-SEC-8   | ECR-003                                                                |
| CICD-SEC-9   | CP-002, ECR-002, ECR-005, S3-001, S3-002, S3-003, S3-005               |
| CICD-SEC-10  | CB-003, CD-003, S3-004                                                 |
