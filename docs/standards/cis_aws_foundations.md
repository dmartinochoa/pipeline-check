# CIS AWS Foundations Benchmark (subset)

- **Version:** 3.0.0
- **URL:** https://www.cisecurity.org/benchmark/amazon_web_services
- **Scope:** Only the controls this scanner can evidence from CodeBuild /
  CodeDeploy / IAM / S3 / ECR state are mapped. Host-level controls
  (CloudTrail, Config, detailed monitoring) are out of scope for a
  CI/CD-focused scan.

## Controls evidenced

| ID    | Title                                                                              |
|-------|------------------------------------------------------------------------------------|
| 1.16  | Ensure IAM policies that allow full `*:*` administrative privileges are not attached |
| 1.17  | Ensure a support role has been created to manage incidents with AWS Support        |
| 2.1.1 | Ensure all S3 buckets employ encryption-at-rest                                    |
| 2.1.2 | Ensure S3 Bucket Policy is set to deny HTTP requests                               |
| 2.1.4 | Ensure that S3 Buckets are configured with 'Block public access'                   |
| 3.1   | Ensure CloudTrail is enabled in all regions                                        |
| 3.4   | Ensure CloudTrail trails are integrated with CloudWatch Logs                       |
| 3.6   | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket             |
| 3.8   | Ensure rotation for customer-created symmetric CMKs is enabled                     |
| 4.3   | Ensure a log metric filter and alarm exist for usage of the root account           |
| 4.16  | Ensure AWS Security Hub is enabled                                                 |

## Mapping to checks

| Control | Checks                                       |
|---------|----------------------------------------------|
| 1.16    | IAM-001, IAM-002, IAM-003, IAM-004, IAM-006  |
| 2.1.1   | S3-002                                       |
| 2.1.2   | S3-003, S3-005                               |
| 2.1.4   | S3-001                                       |
| 3.4     | CB-003, CD-003                               |
| 3.6     | S3-004                                       |
| 4.16    | ECR-001                                      |

## Not yet covered

Controls listed above but not yet evidenced by any check — contributions
welcome:

- **1.17** (support role) — requires an IAM check scanning for a role
  with the AWS-managed `AWSSupportAccess` policy.
- **3.1** (multi-region CloudTrail) — requires a CloudTrail discovery
  check.
- **3.8** (CMK rotation) — requires a KMS check module.
- **4.3** (root-account log metric filter) — requires a CloudWatch
  metric-filter check.
