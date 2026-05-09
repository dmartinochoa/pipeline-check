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
| 1.14    | [`IAM-007`](../providers/aws.md)                                               |
| 1.16    | [`IAM-001`](../providers/aws.md), [`IAM-002`](../providers/aws.md), [`IAM-003`](../providers/aws.md), [`IAM-004`](../providers/aws.md), [`IAM-006`](../providers/aws.md), [`KMS-002`](../providers/aws.md) |
| 2.1.1   | [`S3-002`](../providers/aws.md)                                                |
| 2.1.2   | [`S3-003`](../providers/aws.md), [`S3-005`](../providers/aws.md)                                      |
| 2.1.4   | [`S3-001`](../providers/aws.md)                                                |
| 3.1     | [`CT-001`](../providers/aws.md), [`CT-003`](../providers/aws.md)                                      |
| 3.2     | [`CT-002`](../providers/aws.md)                                                |
| 3.4     | [`CB-003`](../providers/aws.md), [`CD-003`](../providers/aws.md), [`CWL-001`](../providers/aws.md)                           |
| 3.6     | [`S3-004`](../providers/aws.md)                                                |
| 3.7     | [`CWL-002`](../providers/aws.md)                                               |
| 3.8     | [`KMS-001`](../providers/aws.md)                                               |
| 4.16    | [`ECR-001`](../providers/aws.md), [`ECR-007`](../providers/aws.md)                                    |

## Not yet covered

Controls listed above but not yet evidenced by any check, contributions
welcome:

- **1.17** (support role): needs an IAM check scanning for a role
  with the AWS-managed `AWSSupportAccess` policy.
- **4.3** (root-account log metric filter): needs a CloudWatch
  metric-filter check.
