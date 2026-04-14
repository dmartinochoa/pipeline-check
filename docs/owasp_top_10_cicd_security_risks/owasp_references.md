## Checks Reference

### CodeBuild

| ID | Title | Severity | OWASP CI/CD |
|---|---|---|---|
| CB-001 | Secrets in plaintext environment variables | CRITICAL | CICD-SEC-6 |
| CB-002 | Privileged mode enabled | HIGH | CICD-SEC-7 |
| CB-003 | Build logging not enabled | MEDIUM | CICD-SEC-10 |
| CB-004 | No build timeout configured | LOW | CICD-SEC-7 |
| CB-005 | Outdated managed build image | MEDIUM | CICD-SEC-7 |

### CodePipeline

| ID | Title | Severity | OWASP CI/CD |
|---|---|---|---|
| CP-001 | No approval action before deploy stages | HIGH | CICD-SEC-1 |
| CP-002 | Artifact store not encrypted with customer KMS key | MEDIUM | CICD-SEC-9 |
| CP-003 | Source stage using polling instead of event-driven trigger | LOW | CICD-SEC-4 |

### CodeDeploy

| ID | Title | Severity | OWASP CI/CD |
|---|---|---|---|
| CD-001 | Automatic rollback on failure not enabled | MEDIUM | CICD-SEC-1 |
| CD-002 | AllAtOnce deployment config — no canary/rolling strategy | HIGH | CICD-SEC-1 |
| CD-003 | No CloudWatch alarm monitoring on deployment group | MEDIUM | CICD-SEC-10 |

### ECR

| ID | Title | Severity | OWASP CI/CD |
|---|---|---|---|
| ECR-001 | Image scanning on push not enabled | HIGH | CICD-SEC-3 |
| ECR-002 | Image tags are mutable | HIGH | CICD-SEC-9 |
| ECR-003 | Repository policy allows public access | CRITICAL | CICD-SEC-8 |
| ECR-004 | No lifecycle policy configured | LOW | CICD-SEC-7 |

### IAM (CI/CD service roles only)

| ID | Title | Severity | OWASP CI/CD |
|---|---|---|---|
| IAM-001 | CI/CD role has AdministratorAccess policy attached | CRITICAL | CICD-SEC-2 |
| IAM-002 | CI/CD role has wildcard Action in inline policy | HIGH | CICD-SEC-2 |
| IAM-003 | CI/CD role has no permission boundary | MEDIUM | CICD-SEC-2 |

### S3 (CodePipeline artifact buckets only)

| ID | Title | Severity | OWASP CI/CD |
|---|---|---|---|
| S3-001 | Artifact bucket public access block not fully enabled | CRITICAL | CICD-SEC-9 |
| S3-002 | Artifact bucket server-side encryption not configured | HIGH | CICD-SEC-9 |
| S3-003 | Artifact bucket versioning not enabled | MEDIUM | CICD-SEC-9 |
| S3-004 | Artifact bucket access logging not enabled | LOW | CICD-SEC-10 |