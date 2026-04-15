# CIS AWS Foundations Benchmark (subset)

- **Version:** 3.0.0
- **URL:** https://www.cisecurity.org/benchmark/amazon_web_services
- **Scope:** Only the controls this scanner can evidence from CodeBuild /
  IAM / S3 / ECR state are mapped. Host-level controls (CloudTrail,
  Config, Security Hub, etc.) are out of scope for a CI/CD-focused scan.

## Controls evidenced

| ID    | Title                                                                            |
|-------|----------------------------------------------------------------------------------|
| 1.16  | Ensure IAM policies that allow full `*:*` administrative privileges are not attached |
| 2.1.1 | Ensure all S3 buckets employ encryption-at-rest                                  |
| 2.1.2 | Ensure S3 Bucket Policy is set to deny HTTP requests                             |
| 2.1.4 | Ensure that S3 Buckets are configured with 'Block public access'                 |
| 3.6   | Ensure S3 bucket access logging is enabled                                       |

## Mapping to checks

| Control | Checks            |
|---------|-------------------|
| 1.16    | IAM-001, IAM-002  |
| 2.1.1   | S3-002            |
| 2.1.2   | S3-003            |
| 2.1.4   | S3-001            |
| 3.6     | S3-004            |

## Not yet covered

Controls not currently evidenced by any check — contributions welcome:

- 1.17 (support role) — no relevant check; add an IAM check scanning for a
  role with AWS Support managed policy.
- 3.8 (CMK rotation) — would require a new KMS check module.
