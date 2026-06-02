"""CIS AWS Foundations Benchmark v3.0.0, subset covering CI/CD-relevant controls.

Only the controls this scanner's checks can evidence are included. A single
pipeline_check check may satisfy evidence for multiple CIS controls; likewise,
a given CIS control may be supported by multiple checks.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="cis_aws_foundations",
    title="CIS AWS Foundations Benchmark",
    version="3.0.0",
    url="https://www.cisecurity.org/benchmark/amazon_web_services",
    controls={
        # IAM
        "1.14": "Ensure access keys are rotated every 90 days or less",
        "1.16": "Ensure IAM policies that allow full '*:*' administrative privileges are not attached",
        "1.17": "Ensure a support role has been created to manage incidents with AWS Support",
        # Storage
        "2.1.1": "Ensure all S3 buckets employ encryption-at-rest",
        "2.1.2": "Ensure S3 Bucket Policy is set to deny HTTP requests",
        "2.1.4": "Ensure that S3 Buckets are configured with 'Block public access'",
        # Logging
        "3.1":  "Ensure CloudTrail is enabled in all regions",
        "3.2":  "Ensure CloudTrail log file validation is enabled",
        "3.4":  "Ensure CloudTrail trails are integrated with CloudWatch Logs",
        "3.6":  "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
        "3.7":  "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
        "3.8":  "Ensure rotation for customer-created symmetric CMKs is enabled",
        # Monitoring (CI/CD-adjacent)
        "4.3":  "Ensure a log metric filter and alarm exist for usage of the root account",
        "4.16": "Ensure AWS Security Hub is enabled",
    },
    mappings={
        # IAM
        "IAM-001": ["1.16"],
        "IAM-002": ["1.16"],
        "IAM-003": ["1.16"],
        "IAM-004": ["1.16"],
        "IAM-006": ["1.16"],
        # IAM-007 (access key age): the canonical CIS 1.14 control.
        "IAM-007": ["1.14"],
        # S3 artifact buckets
        "S3-001":  ["2.1.4"],
        "S3-002":  ["2.1.1"],
        "S3-003":  ["2.1.2"],
        "S3-004":  ["3.6"],
        "S3-005":  ["2.1.2"],
        # KMS, rotation is direct (3.8); a wildcard policy on a CMK is
        # the same admin-privilege failure mode CIS 1.16 calls out for
        # IAM, applied to a key resource policy.
        "KMS-001": ["3.8"],
        "KMS-002": ["1.16"],
        # CloudTrail, trail existence + multi-region together evidence
        # 3.1; log file validation is the dedicated 3.2 control.
        "CT-001":  ["3.1"],
        "CT-002":  ["3.2"],
        "CT-003":  ["3.1"],
        # CloudWatch Logs integration is 3.4; KMS-encrypted log groups
        # are 3.7 (the same encryption-at-rest control CIS scopes to
        # CloudTrail's log delivery target).
        "CWL-001": ["3.4"],
        "CWL-002": ["3.7"],
        # CodeBuild / CodeDeploy logging (CloudWatch integration)
        "CB-003":  ["3.4"],
        "CD-003":  ["3.4"],
        # ECR scanning complements Security Hub posture
        "ECR-001": ["4.16"],
        "ECR-007": ["4.16"],
        # ── Encryption-at-rest extensions ──
        # CIS 3.7 scopes "logs encrypted at rest with CMK" to
        # CloudTrail's S3 destination. The same control applies by
        # analogy to every CI/CD storage surface that holds artifact
        # / source / config / secret material, pipeline-check
        # extends 3.7 to CodeArtifact domains, CodeCommit repos,
        # CodePipeline artifact stores, ECR repos, Lambda env vars,
        # and SSM SecureStrings. CIS doesn't enumerate these
        # services individually but the "use a CMK, not the
        # AWS-owned default" expectation is the same.
        "CA-001":  ["3.7"],   # CodeArtifact domain CMK
        "CCM-002": ["3.7"],   # CodeCommit repo CMK
        "CP-002":  ["3.7"],   # Pipeline artifact-store CMK
        "ECR-005": ["3.7"],   # ECR repository CMK
        "LMB-003": ["3.7"],   # Lambda env plaintext secrets
        "SSM-001": ["3.7"],   # SSM SecureString (vs plain String)
        "SSM-002": ["3.7", "3.8"],   # SSM uses CMK + rotation
        # ── Over-broad principals / admin privileges (1.16) ──
        # CIS 1.16 is canonically "no IAM policy attaches '*:*'
        # admin to a user". The principle generalizes to any
        # resource policy that grants more than the consumer needs:
        # CodeArtifact domain / repo policies, ECR repo policies,
        # Lambda resource policies, Secrets Manager resource
        # policies. Trust-policy gaps that let an external
        # principal assume the role without an ExternalId or
        # OIDC-claim guard are the same shape from the trust side.
        "CA-003":  ["1.16"],  # CodeArtifact domain policy public
        "CA-004":  ["1.16"],  # codeartifact:* + Resource '*'
        "ECR-003": ["1.16"],  # ECR repo policy public
        "IAM-005": ["1.16"],  # trust policy missing ExternalId
        "IAM-008": ["1.16"],  # OIDC trust missing audience/sub
        "LMB-002": ["1.16"],  # Lambda function URL AuthType=NONE
        "LMB-004": ["1.16"],  # Lambda resource policy wildcard
        "PBAC-002": ["1.16"], # CodeBuild service role shared
        "PBAC-005": ["1.16"], # Pipeline stage role reuse
        "SM-002":  ["1.16"],  # Secrets Manager resource policy public
        "CCM-003": ["1.16"],  # CodeCommit trigger SNS/Lambda in different account
        "EB-002":  ["1.16"],  # EventBridge rule with wildcard target ARN
        # ── Credential rotation (1.14) ──
        # CIS 1.14 requires IAM access keys rotated every 90 days.
        # Secrets Manager rotation extends the same expectation to
        # the secret material the pipeline issues to applications.
        "SM-001":  ["1.14"],  # Secrets Manager no rotation
        # CIS 1.14 generalizes to "no long-lived authenticators" for
        # any pipeline credential surface; the same rotation
        # principle applies to CI-side source tokens and OAuth.
        "CB-006":  ["1.14"],  # long-lived source token in CodeBuild
        "CP-004":  ["1.14"],  # legacy OAuth-token source in CodePipeline
        # ── Degraded-mode findings (API access failures) ────────
        # When the scanner cannot enumerate an AWS provider surface,
        # CIS 3.1 (CloudTrail enabled in all regions) is the natural
        # home: the visibility gap is the audit-trail evidence gap
        # CIS 3.1 is designed to prevent. Mirrors the cross-standard
        # precedent for `-000` findings (CIS SSCS 2.3.7, NIST 800-53
        # AU-2/AU-12, NIST CSF 2.0 PR.PS-04+DE.CM-09, SOC 2 CC7.2,
        # PCI DSS v4 10.2.1).
        "CB-000":   ["3.1"],
        "CP-000":   ["3.1"],
        "CD-000":   ["3.1"],
        "ECR-000":  ["3.1"],
        "IAM-000":  ["3.1"],
        "PBAC-000": ["3.1"],
        "CT-000":   ["3.1"],
        "CWL-000":  ["3.1"],
        "EB-000":   ["3.1"],
        "CA-000":   ["3.1"],
        "CCM-000":  ["3.1"],
        "LMB-000":  ["3.1"],
        "KMS-000":  ["3.1"],
        "SM-000":   ["3.1"],
        "SSM-000":  ["3.1"],
        "S3-000":   ["3.1", "3.6"],   # S3 specifically also evidences 3.6 (access logging)
        # ── Security Hub posture (4.16) ──
        # CIS 4.16 asks for Security Hub on as the org's findings
        # aggregator. ECR scanning checks already feed it (above);
        # CodeBuild / CodePipeline failure-monitoring posture
        # complements the same "detection capability is enabled"
        # control, even though CIS scopes it broader than CI/CD.
        "CW-001":  ["4.16"],  # CloudWatch alarm on FailedBuilds
        "EB-001":  ["4.16"],  # EventBridge rule for pipeline failure
        # ── Unmapped controls ──
        # 1.17 (support role for incident management): needs a new
        # IAM-* rule that checks for an AWSSupportAccess-bound role.
        # 4.3  (log metric filter + alarm on root account usage):
        # needs a new CloudWatch / CloudTrail metric-filter rule.
        # Both gaps require net-new checks, not mappings.
    },
)
