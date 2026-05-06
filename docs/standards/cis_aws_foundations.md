# CIS AWS Foundations Benchmark (subset)

- **Version:** 3.0.0
- **URL:** https://www.cisecurity.org/benchmark/amazon_web_services
- **Scope:** Controls this scanner can evidence from live AWS state
  (IAM, S3, KMS, CloudTrail, CloudWatch Logs, CodeBuild, CodeDeploy,
  ECR). Host-level controls (Config conformance packs, OS-level
  monitoring, network ACL design) remain out of scope for a
  CI/CD-focused scan.
- **Source of truth:** `pipeline_check/core/standards/data/cis_aws_foundations.py`

## Controls evidenced

| ID    | Title                                                                                |
|-------|--------------------------------------------------------------------------------------|
| 1.14  | Ensure access keys are rotated every 90 days or less                                 |
| 1.16  | Ensure IAM policies that allow full `*:*` administrative privileges are not attached |
| 1.17  | Ensure a support role has been created to manage incidents with AWS Support          |
| 2.1.1 | Ensure all S3 buckets employ encryption-at-rest                                      |
| 2.1.2 | Ensure S3 Bucket Policy is set to deny HTTP requests                                 |
| 2.1.4 | Ensure that S3 Buckets are configured with 'Block public access'                     |
| 3.1   | Ensure CloudTrail is enabled in all regions                                          |
| 3.2   | Ensure CloudTrail log file validation is enabled                                     |
| 3.4   | Ensure CloudTrail trails are integrated with CloudWatch Logs                         |
| 3.6   | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket               |
| 3.7   | Ensure CloudTrail logs are encrypted at rest using KMS CMKs                          |
| 3.8   | Ensure rotation for customer-created symmetric CMKs is enabled                       |
| 4.3   | Ensure a log metric filter and alarm exist for usage of the root account             |
| 4.16  | Ensure AWS Security Hub is enabled                                                   |

## Mapping to checks

| Control | Checks                                                  |
|---------|---------------------------------------------------------|
| 1.14    | `IAM-007`                                               |
| 1.16    | `IAM-001`, `IAM-002`, `IAM-003`, `IAM-004`, `IAM-006`, `KMS-002` |
| 2.1.1   | `S3-002`                                                |
| 2.1.2   | `S3-003`, `S3-005`                                      |
| 2.1.4   | `S3-001`                                                |
| 3.1     | `CT-001`, `CT-003`                                      |
| 3.2     | `CT-002`                                                |
| 3.4     | `CB-003`, `CD-003`, `CWL-001`                           |
| 3.6     | `S3-004`                                                |
| 3.7     | `CWL-002`                                               |
| 3.8     | `KMS-001`                                               |
| 4.16    | `ECR-001`, `ECR-007`                                    |

## Not yet covered

Controls listed above but not yet evidenced by any check — contributions
welcome:

- **1.17** (support role) — needs an IAM check scanning for a role
  with the AWS-managed `AWSSupportAccess` policy.
- **4.3** (root-account log metric filter) — needs a CloudWatch
  metric-filter check.
