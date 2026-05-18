"""CIS Software Supply Chain Security Guide v1.0.

Purpose-built for CI/CD posture. The guide is organized into five
sections: (1) Source Code, (2) Build Pipelines, (3) Build Dependencies,
(4) Artifacts, (5) Deployment. This module maps the sub-controls that
this scanner can evidence from AWS / GitHub Actions / Terraform state.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="cis_supply_chain",
    title="CIS Software Supply Chain Security Guide",
    version="1.0",
    url="https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide",
    controls={
        # 1. Source Code
        "1.1.5": "Ensure any change to code requires the review of additional strong authenticators",
        "1.1.6": "Ensure any change to code is signed",
        "1.1.7": "Ensure any change to code is automatically scanned for risks (SAST)",
        "1.1.8": "Ensure scanners are in place to identify and confirm presence of vulnerabilities (SCA)",
        "1.1.17": "Ensure default branches' commits are protected from being deleted/rewritten",
        "1.3.4": "Ensure organization identity is required for contribution (no long-lived personal tokens)",
        "1.4.1": "Ensure third-party artifacts and open-source libraries are verified",
        "1.5.1": "Ensure scanners are in place to identify and prevent sensitive data in code",
        # 2. Build Pipelines
        "2.1.3": "Ensure the build environment is hardened",
        "2.1.6": "Ensure build workers have minimal network connectivity",
        "2.2.2": "Ensure build workers are single-use",
        "2.3.4": "Ensure pipelines are scanned for secrets and sensitive data",
        "2.3.7": "Ensure pipeline steps produce audit logs",
        "2.3.8": "Ensure pipeline configuration files are reviewed before execution",
        "2.4.2": "Ensure pipeline integrity, artifacts are signed by the pipeline",
        "2.4.3": "Ensure access to the pipeline execution environment is restricted",
        # 3. Build Dependencies
        "3.1.3": "Ensure signed metadata of dependencies is verified",
        "3.1.5": "Ensure only trusted package managers and repositories are used",
        # 4. Artifacts
        "4.1.1": "Ensure all artifacts on all releases are verified (signed, integrity-checked)",
        "4.2.1": "Ensure access to artifacts is limited",
        "4.3.3": "Ensure package registries use authentication and authorization",
        "4.4.1": "Ensure artifacts have provenance/SBOM metadata",
        # 5. Deployment
        "5.1.4": "Ensure deployment configuration manifests are reviewed before apply",
        "5.2.1": "Ensure deployment environments are separated",
        "5.2.3": "Ensure deployment environment activity is audited",
    },
    mappings={
        # CodeBuild
        "CB-001":   ["1.5.1", "2.3.4", "2.4.3"],         # plaintext secrets
        "CB-002":   ["2.1.3", "2.1.6"],                  # privileged mode / host network
        "CB-003":   ["2.3.7"],                           # build logs disabled
        "CB-004":   ["2.2.2"],                           # no timeout → not single-use
        "CB-005":   ["2.1.3", "1.4.1"],                  # outdated managed build image
        "CB-006":   ["1.3.4"],                           # long-lived source token
        "CB-007":   ["2.3.8"],                           # webhook no filter group
        "CB-008":   ["2.3.8"],                           # inline buildspec, not from protected repo
        "CB-009":   ["1.4.1", "3.1.3"],                  # build image not digest-pinned
        "CB-010":   ["2.3.8"],                           # webhook accepts fork-PR builds unfiltered
        "CB-011":   ["1.4.1", "2.1.3"],                  # buildspec malicious-activity indicators
        # CodePipeline
        "CP-001":   ["2.3.8", "5.1.4"],                  # no manual approval
        "CP-002":   ["2.4.2", "4.1.1"],                  # artifact store not CMK-encrypted
        "CP-003":   ["2.3.8"],                           # polling source
        "CP-004":   ["1.3.4"],                           # OAuth token source
        "CP-005":   ["5.1.4", "5.2.1"],                  # prod Deploy stage no manual approval
        "CP-007":   ["2.3.8", "5.2.1"],                  # v2 PR trigger accepts all branches
        # CodeDeploy
        "CD-001":   ["5.1.4"],                           # no auto rollback
        "CD-002":   ["5.1.4", "5.2.1"],                  # AllAtOnce
        "CD-003":   ["5.2.3"],                           # no CloudWatch alarm
        # ECR
        "ECR-001":  ["1.4.1", "3.1.3"],                  # no image scan on push
        "ECR-002":  ["4.1.1", "4.4.1"],                  # mutable tags break provenance
        "ECR-003":  ["4.2.1", "4.3.3"],                  # public repo policy
        "ECR-004":  ["2.1.3"],                           # no lifecycle policy
        "ECR-005":  ["4.1.1"],                           # AES256 (no CMK → weaker integrity)
        "ECR-006":  ["1.4.1", "3.1.5"],                  # pull-through cache untrusted upstream
        "ECR-007":  ["1.1.8", "1.4.1"],                  # Inspector v2 enhanced scanning disabled
        # IAM
        "IAM-001":  ["2.4.3"],
        "IAM-002":  ["2.4.3"],
        "IAM-003":  ["2.4.3"],
        "IAM-004":  ["2.4.3"],
        "IAM-005":  ["2.4.3", "1.3.4"],                  # sts:ExternalId
        "IAM-006":  ["2.4.3"],
        "IAM-007":  ["1.3.4"],                           # access key > 90 days
        "IAM-008":  ["1.3.4", "2.4.3"],                  # OIDC trust missing aud/sub pin
        # PBAC
        "PBAC-001": ["2.1.6"],                           # no VPC boundary
        "PBAC-002": ["2.2.2", "2.4.3"],                  # shared service role
        "PBAC-003": ["2.1.6"],                           # SG 0.0.0.0/0 egress
        "PBAC-005": ["2.4.3"],                           # stage action roles mirror pipeline role
        # S3 artifact bucket
        "S3-001":   ["4.2.1", "4.3.3"],                  # public bucket = unauthenticated artifact registry
        "S3-002":   ["4.1.1"],
        "S3-003":   ["4.1.1", "4.4.1"],                  # versioning = provenance history
        "S3-004":   ["2.3.7", "5.2.3"],
        "S3-005":   ["4.2.1"],
        # CodeArtifact (package registry)
        "CA-001":   ["4.1.1", "4.3.3"],                  # domain not encrypted with customer CMK
        "CA-002":   ["4.3.3", "1.4.1"],                  # public external connection
        "CA-003":   ["4.3.3", "4.2.1"],                  # domain policy cross-account wildcard
        "CA-004":   ["4.3.3", "4.2.1"],                  # repo policy wildcard codeartifact:*
        # CodeCommit (source repository)
        "CCM-001":  ["1.1.5"],                           # no approval rule template (required-reviews surface)
        "CCM-002":  ["4.1.1"],                           # not encrypted with customer CMK (integrity)
        "CCM-003":  ["4.2.1"],                           # trigger targets cross-account SNS/Lambda
        # Lambda deployment / AWS Signer
        "SIGN-001": ["2.4.2", "4.1.1"],                  # no AWS Signer profile for Lambda
        "SIGN-002": ["2.4.2", "4.1.1"],                  # Signer profile revoked / inactive
        "LMB-001":  ["2.4.2", "4.1.1"],                  # Lambda has no code-signing config
        "LMB-002":  ["4.2.1"],                           # Lambda function URL has AuthType=NONE
        "LMB-003":  ["1.5.1", "2.3.4"],                  # Lambda env vars contain plaintext secrets
        "LMB-004":  ["4.2.1"],                           # Lambda resource policy wildcard principal
        # KMS / Secrets Manager / SSM Parameter Store
        "KMS-002":  ["4.2.1"],                           # KMS key policy grants wildcard actions
        "SM-002":   ["4.2.1"],                           # Secrets Manager resource policy wildcard principal
        "SSM-001":  ["1.5.1"],                           # secret-like Parameter not SecureString
        "SSM-002":  ["4.2.1"],                           # SecureString uses default AWS-managed key (broad decrypt)
        # CloudTrail / CloudWatch / EventBridge (pipeline + deploy audit)
        "CT-001":   ["2.3.7", "5.2.3"],                  # no active CloudTrail
        "CT-002":   ["2.3.7", "5.2.3"],                  # log-file validation disabled
        "CT-003":   ["2.3.7", "5.2.3"],                  # trail not multi-region
        "CWL-001":  ["2.3.7"],                           # CodeBuild log group no retention
        "CWL-002":  ["2.3.7"],                           # CodeBuild log group not KMS-encrypted
        "CW-001":   ["2.3.7", "5.2.3"],                  # no CloudWatch alarm on FailedBuilds
        "EB-001":   ["2.3.7"],                           # no EventBridge rule for pipeline failure
        "EB-002":   ["2.4.3"],                           # EventBridge rule wildcard target ARN
        # GitHub Actions
        "GHA-001":  ["1.4.1", "3.1.5"],                  # unpinned 3rd-party action
        "GHA-002":  ["2.1.3", "2.3.8"],                  # pull_request_target + PR head
        "GHA-003":  ["2.1.3"],                           # script injection
        "GHA-004":  ["2.4.3"],                           # unrestricted GITHUB_TOKEN
        "GHA-005":  ["1.3.4"],                           # long-lived AWS keys
        "GHA-006":  ["4.1.1"],                           # artifact signing
        "GHA-007":  ["4.4.1"],                           # SBOM
        "GHA-008":  ["1.5.1", "2.3.4"],                  # literal secrets in workflow
        "GHA-009":  ["1.4.1", "2.3.8"],                  # workflow_run upstream artifact unverified
        "GHA-010":  ["2.1.3", "2.3.8"],                  # local action on untrusted-trigger workflow
        "GHA-011":  ["2.1.3", "2.3.8"],                  # cache key tainted by attacker input
        "GHA-012":  ["2.2.2"],                           # self-hosted runner not ephemeral
        "GHA-013":  ["2.3.8", "2.1.3"],                  # issue_comment trigger no author guard
        "GHA-014":  ["5.1.4", "5.2.1"],                  # deploy job missing environment
        "GHA-015":  ["2.2.2"],                           # job has no timeout-minutes
        "GHA-016":  ["1.4.1", "3.1.5"],                  # remote script piped to shell
        "GHA-017":  ["3.1.5", "1.4.1"],                  # package install from insecure source
        "GHA-018":  ["1.3.4", "2.4.3"],                  # GITHUB_TOKEN persisted to storage
        "GHA-019":  ["1.4.1", "3.1.3"],                  # install without lockfile enforcement
        "GHA-020":  ["1.1.8", "1.4.1"],                  # no vulnerability scanning step
        "GHA-021":  ["1.4.1", "3.1.3"],                  # dep-update command bypasses lockfile pins
        "GHA-022":  ["3.1.5", "1.4.1"],                  # TLS verification bypass
        "GHA-023":  ["1.4.1", "3.1.3"],                  # reusable workflow not pinned to SHA
        "GHA-024":  ["2.4.2", "4.4.1"],                  # no SLSA provenance attestation
        "GHA-025":  ["1.4.1", "2.1.3"],                  # workflow malicious-activity indicators
        "GHA-026":  ["2.1.3", "2.1.6"],                  # container job disables isolation
        "GHA-027":  ["2.1.3"],                           # dangerous shell idiom
        "GHA-028":  ["1.4.1", "3.1.5"],                  # install bypasses registry integrity
        "GHA-029":  ["1.4.1", "3.1.5"],                  # package install from git/path/tarball
        "GHA-030":  ["1.3.4", "2.4.3", "5.2.1"],         # OIDC token w/o env-protected job
        "GHA-031":  ["2.1.3"],                           # retired set-output / save-state
        "GHA-032":  ["2.1.3", "2.3.8"],                  # run: invokes local script on untrusted trigger
        "GHA-033":  ["1.5.1", "2.3.4"],                  # secret echoed / printed
        "GHA-034":  ["2.4.3", "1.5.1"],                  # secrets: inherit (broad cred surface)
        "GHA-035":  ["2.1.3"],                           # github-script step interpolates untrusted context
        "GHA-036":  ["2.1.3"],                           # runs-on interpolates untrusted context
        "GHA-037":  ["1.3.4", "2.4.3"],                  # checkout persists GITHUB_TOKEN
        "GHA-038":  ["2.1.3"],                           # ACTIONS_ALLOW_UNSECURE_COMMANDS re-enabled
        "GHA-039":  ["1.5.1", "2.3.4"],                  # services container creds literal
        "GHA-040":  ["1.4.1", "3.1.3"],                  # known-compromised action ref
        "GHA-041":  ["3.1.3"],                           # single-maintainer action
        "GHA-042":  ["3.1.3"],                           # very-young action repo
        "GHA-043":  ["3.1.3"],                           # low-star + sensitive perms
        "GHA-044":  ["2.1.3", "2.3.8"],                  # build-tool PPE on untrusted trigger
        "GHA-045":  ["2.1.3", "2.3.8"],                  # caller-ref input drives checkout
        "GHA-046":  ["2.1.3", "2.3.8"],                  # manual PR-head fetch on untrusted trigger
        "GHA-047":  ["3.1.3"],                           # fresh-ref cooldown
        "GHA-048":  ["1.1.17", "2.3.8"],                 # workflow self-mutation (history protection)
        "GHA-049":  ["2.4.3", "1.1.17"],                 # cross-repo push from CI
        "GHA-050":  ["1.3.4", "2.4.2", "4.3.3"],         # long-lived registry publish token
        "GHA-051":  ["1.4.1", "3.1.3"],                  # services/container image unpinned
        "GHA-052":  ["2.1.3", "2.3.8"],                  # cache key untrusted-input poisoning
        "GHA-053":  ["2.1.3"],                           # if: predicate untrusted-context
        "GHA-054":  ["1.3.4", "2.4.3"],                  # checkout ssh-key persists
        "GHA-055":  ["1.5.1", "2.3.4"],                  # reusable outputs leak secret
        "GHA-056":  ["1.4.1", "2.1.3"],                  # known supply-chain worm IOC strings
        "GHA-057":  ["2.1.6", "1.5.1"],                  # secret-scanner output piped to egress
        "GHA-058":  ["2.1.3"],                           # agentic CLI with permission-bypass flags
        # GitLab CI
        "GL-001":   ["1.4.1", "3.1.5"],
        "GL-002":   ["2.1.3", "2.3.8"],
        "GL-003":   ["1.5.1", "2.3.4", "2.4.3"],
        "GL-004":   ["5.1.4", "5.2.1"],
        "GL-005":   ["1.4.1", "3.1.3", "3.1.5"],
        "GL-006":   ["4.1.1"],
        "GL-007":   ["4.4.1"],
        "GL-008":   ["1.5.1", "2.3.4"],                  # literal secrets
        "GL-009":   ["1.4.1", "3.1.3"],                  # image pinned to tag not digest
        "GL-010":   ["1.4.1", "2.3.8"],                  # multi-project pipeline upstream artifact unverified
        "GL-011":   ["2.1.3", "2.3.8"],                  # include: local file in MR pipeline
        "GL-012":   ["2.1.3", "2.3.8"],                  # cache key from MR-controlled variable
        "GL-013":   ["1.3.4"],                           # long-lived AWS keys
        "GL-014":   ["2.2.2"],                           # self-managed runner not ephemeral
        "GL-015":   ["2.2.2"],                           # job has no timeout
        "GL-016":   ["1.4.1", "3.1.5"],                  # remote script piped to shell
        "GL-017":   ["2.1.3"],                           # docker run privileged/host mount
        "GL-018":   ["3.1.5", "1.4.1"],                  # package install insecure source
        "GL-019":   ["1.1.8", "1.4.1"],                  # no vulnerability scanning
        "GL-020":   ["1.3.4", "2.4.3"],                  # CI_JOB_TOKEN persisted
        "GL-021":   ["1.4.1", "3.1.3"],                  # install without lockfile enforcement
        "GL-022":   ["1.4.1", "3.1.3"],                  # dep-update bypasses lockfile pins
        "GL-023":   ["3.1.5", "1.4.1"],                  # TLS bypass
        "GL-024":   ["2.4.2", "4.4.1"],                  # no SLSA provenance
        "GL-025":   ["1.4.1", "2.1.3"],                  # malicious-activity indicators
        "GL-026":   ["2.1.3"],                           # dangerous shell idiom
        "GL-027":   ["1.4.1", "3.1.5"],                  # install bypasses registry integrity
        "GL-028":   ["1.4.1", "3.1.3"],                  # services: image not pinned
        "GL-029":   ["5.1.4", "5.2.1"],                  # manual deploy defaults allow_failure
        "GL-030":   ["1.4.1", "3.1.3"],                  # trigger: include: pulls child pipeline w/o pinned ref
        "GL-031":   ["1.3.4", "2.4.3", "5.2.1"],         # id_tokens missing audience/env binding
        "GL-032":   ["2.1.3"],                           # tags: interpolates untrusted variable
        "GL-033":   ["2.1.3", "2.3.8"],                  # global before_script taint
        # Bitbucket Pipelines
        "BB-001":   ["1.4.1", "3.1.5"],
        "BB-002":   ["2.1.3", "2.3.8"],
        "BB-003":   ["1.5.1", "2.3.4", "2.4.3"],
        "BB-004":   ["5.1.4", "5.2.1"],
        "BB-005":   ["2.2.2"],
        "BB-006":   ["4.1.1"],
        "BB-007":   ["4.4.1"],
        "BB-008":   ["1.5.1", "2.3.4"],                  # literal secrets
        "BB-009":   ["1.4.1", "3.1.3"],                  # pipe pinned by version not digest
        "BB-010":   ["1.4.1", "2.3.8"],                  # deploy step ingests PR artifact unverified
        "BB-011":   ["1.3.4"],                           # long-lived AWS keys
        "BB-012":   ["1.4.1", "3.1.5"],                  # remote script piped to shell
        "BB-013":   ["2.1.3"],                           # docker run privileged / host mount
        "BB-014":   ["3.1.5", "1.4.1"],                  # package install insecure source
        "BB-015":   ["1.1.8", "1.4.1"],                  # no vulnerability scanning
        "BB-016":   ["2.2.2"],                           # self-hosted runner not ephemeral
        "BB-017":   ["1.3.4", "2.4.3"],                  # repo token persisted to storage
        "BB-018":   ["2.1.3", "2.3.8"],                  # cache key tainted by attacker input
        "BB-019":   ["1.5.1", "2.3.4"],                  # after-script references secrets
        "BB-020":   ["1.5.1"],                           # full clone depth exposes history
        "BB-021":   ["1.4.1", "3.1.3"],                  # install without lockfile enforcement
        "BB-022":   ["1.4.1", "3.1.3"],                  # dep-update bypasses lockfile pins
        "BB-023":   ["3.1.5", "1.4.1"],                  # TLS bypass
        "BB-024":   ["2.4.2", "4.4.1"],                  # no SLSA provenance
        "BB-025":   ["1.4.1", "2.1.3"],                  # malicious-activity indicators
        "BB-026":   ["2.1.3"],                           # dangerous shell idiom
        "BB-027":   ["1.4.1", "3.1.5"],                  # install bypasses registry integrity
        "BB-028":   ["1.3.4", "2.4.3", "5.2.1"],         # OIDC step w/o deployment-gated env
        "BB-029":   ["1.4.1", "3.1.3"],                  # step+service image not digest-pinned
        # Azure DevOps Pipelines
        "ADO-001":  ["1.4.1", "3.1.5"],
        "ADO-002":  ["2.1.3", "2.3.8"],
        "ADO-003":  ["1.5.1", "2.3.4", "2.4.3"],
        "ADO-004":  ["5.1.4", "5.2.1"],
        "ADO-005":  ["1.4.1", "3.1.5"],
        "ADO-006":  ["4.1.1"],
        "ADO-007":  ["4.4.1"],
        "ADO-008":  ["1.5.1", "2.3.4"],                  # literal secrets
        "ADO-009":  ["1.4.1", "3.1.3"],                  # container image not digest-pinned
        "ADO-010":  ["1.4.1", "2.3.8"],                  # cross-pipeline download unverified
        "ADO-011":  ["2.1.3", "2.3.8"],                  # template: <local-path> on PR-validated pipeline
        "ADO-012":  ["2.1.3", "2.3.8"],                  # Cache@2 key from PullRequest context
        "ADO-013":  ["2.2.2"],                           # self-hosted pool not ephemeral
        "ADO-014":  ["1.3.4"],                           # long-lived AWS keys
        "ADO-015":  ["2.2.2"],                           # job has no timeoutInMinutes
        "ADO-016":  ["1.4.1", "3.1.5"],                  # remote script piped to shell
        "ADO-017":  ["2.1.3"],                           # docker run privileged/host mount
        "ADO-018":  ["3.1.5", "1.4.1"],                  # package install insecure source
        "ADO-019":  ["2.1.3", "2.3.8"],                  # extends: template on PR-validated pipeline
        "ADO-020":  ["1.1.8", "1.4.1"],                  # no vulnerability scanning
        "ADO-021":  ["1.4.1", "3.1.3"],                  # install without lockfile enforcement
        "ADO-022":  ["1.4.1", "3.1.3"],                  # dep-update bypasses lockfile pins
        "ADO-023":  ["3.1.5", "1.4.1"],                  # TLS bypass
        "ADO-024":  ["2.4.2", "4.4.1"],                  # no SLSA provenance
        "ADO-025":  ["1.4.1", "3.1.3"],                  # cross-repo template not SHA-pinned
        "ADO-026":  ["1.4.1", "2.1.3"],                  # malicious-activity indicators
        "ADO-027":  ["2.1.3"],                           # dangerous shell idiom
        "ADO-028":  ["1.4.1", "3.1.5"],                  # install bypasses registry integrity
        "ADO-029":  ["5.1.4", "5.2.1"],                  # service-conn job w/o env/branch gate
        "ADO-030":  ["2.1.3"],                           # pool interpolates untrusted value
        # CircleCI
        "CC-001":   ["1.4.1", "3.1.5"],
        "CC-002":   ["2.1.3"],
        "CC-003":   ["1.4.1", "3.1.5"],
        "CC-004":   ["1.5.1", "2.3.4", "2.4.3"],
        "CC-005":   ["1.3.4"],
        "CC-006":   ["4.1.1"],
        "CC-007":   ["4.4.1"],
        "CC-008":   ["1.5.1", "2.3.4", "2.4.3"],
        "CC-009":   ["2.3.8", "5.1.4"],
        "CC-010":   ["2.1.3", "2.1.6"],
        "CC-011":   ["2.3.7"],
        "CC-012":   ["2.1.3"],
        "CC-013":   ["2.3.8"],
        "CC-014":   ["2.1.6"],
        "CC-015":   ["2.2.2"],
        "CC-016":   ["1.4.1", "3.1.5"],
        "CC-017":   ["2.1.3"],
        "CC-018":   ["3.1.5"],
        "CC-019":   ["1.3.4"],
        "CC-020":   ["1.4.1", "3.1.3"],
        "CC-021":   ["3.1.3"],
        "CC-022":   ["3.1.3"],
        "CC-023":   ["3.1.5"],
        "CC-024":   ["2.4.2", "4.4.1"],            # no SLSA provenance
        "CC-025":   ["2.1.3", "2.3.8"],            # cache key tainted by attacker input
        "CC-026":   ["1.4.1", "2.1.3"],            # malicious-activity indicators
        "CC-027":   ["2.1.3"],                     # dangerous shell idiom
        "CC-028":   ["1.4.1", "3.1.5"],            # install bypasses registry integrity
        "CC-029":   ["1.4.1", "3.1.3"],            # machine executor image not pinned
        "CC-030":   ["5.1.4", "5.2.1"],            # job w/o branch filter / approval gate
        "CC-031":   ["1.3.4", "5.2.1"],            # OIDC role assumption w/o branch filter
        # ── Buildkite ─────────────────────────────────────────────
        "BK-001":   ["1.4.1", "3.1.5"],            # plugin not pinned
        "BK-002":   ["1.5.1", "2.3.4"],            # secret in env
        "BK-003":   ["2.1.3", "2.3.8"],            # untrusted variable injection
        "BK-004":   ["1.4.1", "3.1.5"],            # curl | bash
        "BK-005":   ["2.1.3"],                     # Docker privileged
        "BK-006":   ["2.2.2"],                     # no timeout
        "BK-007":   ["2.3.8", "5.1.4"],            # deploy not gated
        "BK-008":   ["3.1.3"],                     # TLS bypass
        "BK-009":   ["4.1.1"],                     # artifact signing
        "BK-010":   ["4.4.1"],                     # SBOM
        "BK-011":   ["4.1.1", "4.4.1"],            # SLSA provenance
        "BK-012":   ["1.1.8", "1.4.1", "3.1.3"],   # vuln scanning
        "BK-013":   ["5.1.4", "5.2.1"],            # deploy step no branches: filter
        "BK-014":   ["1.4.1", "3.1.5"],            # unpinned package install
        "BK-015":   ["2.1.3"],                     # agents map interpolates untrusted variable
        # ── Tekton ────────────────────────────────────────────────
        "TKN-001":  ["1.4.1", "3.1.3"],            # step image not digest-pinned
        "TKN-002":  ["2.1.3"],                     # step privileged
        "TKN-003":  ["2.1.3", "2.3.8"],            # param injection
        "TKN-004":  ["2.1.3"],                     # hostPath / host namespaces
        "TKN-005":  ["1.5.1", "2.3.4"],            # leaked creds
        "TKN-006":  ["2.2.2"],                     # no timeout
        "TKN-007":  ["2.4.3"],                     # default SA
        "TKN-008":  ["1.4.1", "3.1.5"],            # remote install / TLS
        "TKN-009":  ["4.1.1"],                     # artifact signing
        "TKN-010":  ["4.4.1"],                     # SBOM
        "TKN-011":  ["4.1.1", "4.4.1"],            # SLSA provenance
        "TKN-012":  ["1.1.8", "1.4.1", "3.1.3"],   # vuln scanning
        "TKN-013":  ["2.1.3"],                     # sidecar privileged / root
        "TKN-014":  ["1.4.1", "3.1.5"],            # unpinned package install
        "TKN-015":  ["2.1.3", "2.3.8"],            # workspace subPath param injection
        # ── Argo Workflows ────────────────────────────────────────
        "ARGO-001": ["1.4.1", "3.1.3"],            # template image not pinned
        "ARGO-002": ["2.1.3"],                     # template privileged
        "ARGO-003": ["2.4.3"],                     # default SA
        "ARGO-004": ["2.1.3"],                     # hostPath / host namespaces
        "ARGO-005": ["2.1.3", "2.3.8"],            # parameter injection
        "ARGO-006": ["1.5.1", "2.3.4"],            # leaked creds
        "ARGO-007": ["2.2.2"],                     # no activeDeadlineSeconds
        "ARGO-008": ["1.4.1", "3.1.5"],            # remote install / TLS
        "ARGO-009": ["4.1.1"],                     # artifact signing
        "ARGO-010": ["4.4.1"],                     # SBOM
        "ARGO-011": ["4.1.1", "4.4.1"],            # SLSA provenance
        "ARGO-012": ["1.1.8", "1.4.1", "3.1.3"],   # vuln scanning
        "ARGO-013": ["2.4.3"],                     # SA token automount default
        "ARGO-014": ["1.4.1", "3.1.5"],            # unpinned package install
        "ARGO-015": ["1.4.1", "4.1.1"],            # insecure (non-HTTPS) artifact URL
        # ── Helm chart-supply-chain ───────────────────────────────
        # Chart packaging metadata sits at the artifact / build-deps
        # boundary. HELM-002's missing-digest is the exact "signed
        # metadata of dependencies is verified" failure (3.1.3).
        "HELM-001": ["1.4.1", "3.1.3"],            # legacy v1 (no in-tree dep manifest)
        "HELM-002": ["3.1.3", "4.1.1"],            # missing Chart.lock digests
        "HELM-003": ["3.1.5"],                     # non-HTTPS dep repo
        "HELM-004": ["1.4.1", "3.1.3"],            # version range
        "HELM-005": ["4.4.1"],                     # maintainers chain-of-custody
        "HELM-006": ["2.3.8"],                     # missing kubeVersion (manifest review)
        "HELM-007": ["4.4.1"],                     # description (provenance metadata)
        "HELM-008": ["1.4.1", "3.1.3"],            # stale Chart.lock
        "HELM-009": ["3.1.5"],                     # non-HTTPS home/sources URL
        "HELM-010": ["4.4.1"],                     # appVersion (provenance metadata)
        # ── Dockerfile (image build supply chain) ──────────────────
        # The CIS Supply Chain Benchmark Section 2 (build) and 3
        # (dependencies) cover the same ground a hardened Dockerfile
        # touches. Pinning rules tie to 1.4.1 / 3.1.3 (verify and
        # pin third-party / dependency); privileged / root rules tie
        # to 2.1.3 (build env hardened); credential-shape rules tie
        # to 2.3.4 (scan for secrets).
        "DF-001": ["1.4.1", "3.1.3"],              # FROM not digest-pinned
        "DF-002": ["2.1.3"],                       # runs as root
        "DF-003": ["1.4.1", "3.1.3"],              # ADD remote, no integrity
        "DF-004": ["3.1.5", "1.4.1"],              # curl-pipe in RUN
        "DF-005": ["2.1.3"],                       # shell-eval
        "DF-006": ["1.5.1", "2.3.4"],              # ENV credential literal
        "DF-008": ["2.1.3"],                       # docker --privileged
        "DF-009": ["1.4.1", "3.1.3"],              # ADD where COPY suffices
        "DF-010": ["1.4.1"],                       # apt upgrade unpinned
        "DF-011": ["1.4.1"],                       # no cache cleanup
        "DF-012": ["2.1.3"],                       # RUN sudo
        "DF-013": ["2.1.3", "2.1.6"],              # sensitive EXPOSE / network
        "DF-014": ["2.1.3"],                       # WORKDIR /etc
        "DF-015": ["2.1.3"],                       # chmod 777
        "DF-016": ["4.4.1"],                       # OCI provenance labels
        "DF-017": ["2.1.3"],                       # PATH world-writable
        "DF-018": ["2.1.3"],                       # chown system path
        "DF-019": ["1.5.1", "2.3.4"],              # COPY credential file
        "DF-020": ["1.5.1", "2.3.4"],              # credential ARG
        "DF-021": ["3.1.5", "1.4.1"],              # pip install TLS bypass / http index
        "DF-022": ["1.4.1", "3.1.3"],              # npm install (not npm ci)
        "DF-023": ["2.1.3"],                       # LD_PRELOAD / LD_LIBRARY_PATH
        "DF-024": ["2.1.3", "3.1.3"],              # npm install runs lifecycle scripts
        "DF-025": ["1.5.1", "2.3.4"],              # registry token in image layer
        "DF-026": ["3.1.5", "1.4.1"],              # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027": ["3.1.5", "1.4.1"],              # PYTHONHTTPSVERIFY=0
        "DF-028": ["3.1.5", "1.4.1"],              # GIT_SSL_NO_VERIFY=1
        "DF-029": ["3.1.5", "1.4.1"],              # REQUESTS_CA_BUNDLE neutered
        "DF-030": ["2.1.3"],                       # NODE_OPTIONS --require / --inspect
        # ── OCI image metadata ────────────────────────────────────
        "OCI-001":   ["4.4.1"],                    # missing provenance annotations
        "OCI-002":   ["2.4.2", "4.4.1"],           # missing build attestation
        "OCI-003":   ["4.4.1"],                    # missing image.created
        "OCI-004":   ["1.4.1", "4.1.1"],           # foreign-layer URL reference
        "OCI-005":   ["4.4.1"],                    # missing image.licenses
        # OCI-006 (excessive layer count): no CIS SSCS control fit; left unmapped.
        "OCI-007":   ["4.1.1", "3.1.3"],           # legacy schemaVersion 1
        "OCI-008":   ["3.1.3", "4.1.1"],           # weak digest algorithm
        # ── SLSA / in-toto attestation ────────────────────────────
        "ATTEST-001": ["2.4.2", "4.4.1"],          # untrusted builder identity
        "ATTEST-002": ["1.4.1", "4.4.1"],          # source repo claim unverifiable
        "ATTEST-003": ["3.1.3", "4.4.1"],          # SBOM floating versions
        "ATTEST-004": ["4.4.1"],                   # missing resolved dependencies
        "ATTEST-005": ["4.1.1", "4.4.1"],          # in-toto subject unpinned
        "ATTEST-006": ["4.4.1"],                   # missing buildType
        "ATTEST-007": ["4.4.1"],                   # SBOM missing supplier
        # ── Jenkins ───────────────────────────────────────────────
        "JF-001":   ["1.4.1", "3.1.3"],            # shared library not pinned
        "JF-002":   ["2.1.3", "2.3.8"],            # script step interpolates untrusted env
        "JF-003":   ["2.4.3"],                     # agent any (no executor isolation)
        "JF-004":   ["1.3.4"],                     # AWS long-lived keys via withCredentials
        "JF-005":   ["5.1.4", "5.2.1"],            # deploy stage missing manual input
        "JF-006":   ["4.1.1"],                     # artifacts not signed
        "JF-007":   ["4.4.1"],                     # SBOM not produced
        "JF-008":   ["1.5.1", "2.3.4"],            # credential-shaped literal in pipeline
        "JF-009":   ["1.4.1", "3.1.3"],            # agent docker image not digest-pinned
        "JF-010":   ["1.3.4"],                     # long-lived AWS keys in environment {}
        "JF-011":   ["2.3.7"],                     # no buildDiscarder retention
        "JF-012":   ["1.4.1", "3.1.3"],            # load step pulls Groovy w/o integrity pin
        "JF-013":   ["1.4.1", "2.3.8"],            # copyArtifacts ingests upstream unverified
        "JF-014":   ["2.2.2"],                     # agent label missing ephemeral marker
        "JF-015":   ["2.2.2"],                     # pipeline has no timeout wrapper
        "JF-016":   ["1.4.1", "3.1.5"],            # remote script piped to shell
        "JF-017":   ["2.1.3"],                     # docker run privileged / host mount
        "JF-018":   ["3.1.5", "1.4.1"],            # package install insecure source
        "JF-019":   ["2.1.3"],                     # Groovy sandbox escape pattern
        "JF-020":   ["1.1.8", "1.4.1"],            # no vulnerability scanning step
        "JF-021":   ["1.4.1", "3.1.3"],            # install without lockfile enforcement
        "JF-022":   ["1.4.1", "3.1.3"],            # dep-update bypasses lockfile pins
        "JF-023":   ["3.1.5", "1.4.1"],            # TLS bypass
        "JF-024":   ["1.1.5", "5.1.4"],            # input approval missing submitter restriction
        "JF-025":   ["2.1.3", "2.1.6"],            # K8s agent privileged / hostPath
        "JF-026":   ["2.3.8"],                     # build job: trigger ignores downstream failure
        "JF-027":   ["4.4.1"],                     # archiveArtifacts no fingerprint
        "JF-028":   ["2.4.2", "4.4.1"],            # no SLSA provenance attestation
        "JF-029":   ["1.4.1", "2.1.3"],            # malicious-activity indicators
        "JF-030":   ["2.1.3"],                     # dangerous shell idiom
        "JF-031":   ["1.4.1", "3.1.5"],            # install bypasses registry integrity
        "JF-032":   ["2.1.3"],                     # agent label interpolates untrusted value
        "JF-033":   ["1.5.1", "2.3.4"],            # withCredentials leaked via Groovy ${} in sh
        "JF-034":   ["1.5.1", "2.3.4"],            # password() build parameter declared
        "JF-035":   ["1.4.1", "3.1.5"],            # httpRequest SSL verification off
        # ── Drone CI ──────────────────────────────────────────────
        "DR-001":   ["1.4.1", "3.1.3"],            # step image not digest-pinned
        "DR-002":   ["2.1.3"],                     # step privileged
        "DR-003":   ["2.1.3", "2.3.8"],            # Drone variable injection in shell
        "DR-004":   ["1.5.1", "2.3.4"],            # literal credential in env
        "DR-005":   ["1.4.1", "3.1.3"],            # plugin floating tag
        "DR-006":   ["3.1.5", "1.4.1"],            # TLS bypass in commands
        "DR-007":   ["2.1.3"],                     # sensitive host-path mount
        "DR-008":   ["1.4.1", "3.1.3"],            # pull: never policy
        "DR-009":   ["2.1.3", "2.3.8"],            # cache key tainted by attacker input
        "DR-010":   ["1.4.1", "3.1.5"],            # unpinned package install
        "DR-011":   ["2.1.3"],                     # node map interpolates untrusted variable
        # ── Cloud Build ────────────────────────────────────────────
        # Mirrors the GCB-* coverage other CI providers got across
        # rounds 22-24 in the catalog.
        "GCB-001": ["1.4.1", "3.1.3"],             # step image not pinned
        "GCB-002": ["2.1.3"],                      # plaintext env secret
        "GCB-003": ["1.5.1", "2.3.4"],             # plain script secret
        "GCB-004": ["1.4.1", "3.1.3"],             # community step not SHA-pinned
        "GCB-005": ["1.5.1", "2.3.4"],             # secret-shaped substitution
        "GCB-006": ["2.3.7"],                      # build logging disabled
        "GCB-007": ["1.4.1", "3.1.3"],             # version: latest secret
        "GCB-008": ["2.4.2"],                      # no signing step
        "GCB-009": ["4.4.1"],                      # no SBOM
        "GCB-010": ["2.1.6"],                      # default network egress
        "GCB-011": ["3.1.5"],                      # TLS bypass
        "GCB-012": ["1.1.8", "1.4.1"],             # no vuln scan
        "GCB-013": ["2.1.6"],                      # default service account
        "GCB-014": ["2.3.8"],                      # untrusted substitution
        "GCB-015": ["2.4.2"],                      # no provenance attestation
        "GCB-016": ["2.1.3"],                      # no timeout
        "GCB-017": ["2.3.7"],                      # default logs
        "GCB-018": ["3.1.5"],                      # gcr.io legacy
        "GCB-019": ["2.1.3"],                      # privileged step
        "GCB-020": ["4.2.1"],                      # SA email default
        "GCB-021": ["2.1.6"],                      # no private worker pool
        "GCB-022": ["2.3.8"],                      # ALLOW_LOOSE substitution
        "GCB-023": ["2.4.2"],                      # build artifacts not signed
        "GCB-024": ["4.4.1"],                      # no provenance labels
        "GCB-025": ["1.4.1"],                      # outdated runner image
        "GCB-026": ["2.4.3"],                      # public storage bucket
        # ── npm (dep supply-chain) ────────────────────────────────
        # Section 3 (Build Dependencies) is the natural home for the
        # NPM/PyPI/Maven lockfile + manifest static analysis. Pinning
        # and integrity belong to 3.1.3 (signed metadata of deps
        # verified); registry trust belongs to 3.1.5 (only trusted
        # package managers / repositories).
        "NPM-001":  ["1.4.1", "3.1.3"],            # floating range in package.json
        "NPM-002":  ["3.1.3", "4.1.1"],            # lock entry missing integrity
        "NPM-003":  ["3.1.5", "1.4.1"],            # non-registry source (git / path / tarball)
        "NPM-004":  ["2.1.3", "3.1.3"],            # install-time lifecycle script
        "NPM-005":  ["1.4.1", "3.1.3"],            # git dep with mutable ref
        "NPM-006":  ["1.4.1", "3.1.3"],            # compromised-package registry
        "NPM-007":  ["2.1.3"],                     # .npmrc ignore-scripts enforcement
        "NPM-011":  ["1.5.1", "2.3.4"],            # secret-shaped paths in files field
        # ── pypi (dep supply-chain) ───────────────────────────────
        "PYPI-001": ["1.4.1", "3.1.3"],            # requirements line lacks ==pin
        "PYPI-002": ["3.1.3", "4.1.1"],            # hash pinning missing
        "PYPI-003": ["3.1.5", "1.4.1"],            # http index / --trusted-host
        "PYPI-004": ["1.4.1", "3.1.3"],            # VCS dep without commit SHA
        "PYPI-005": ["3.1.5", "1.4.1"],            # --extra-index-url (dep confusion)
        "PYPI-006": ["1.4.1", "3.1.3"],            # compromised-package registry
        # ── maven (dep supply-chain) ──────────────────────────────
        "MVN-001":  ["1.4.1", "3.1.3"],            # floating Maven version range
        "MVN-002":  ["1.4.1", "3.1.3"],            # mutable SNAPSHOT dependency
        "MVN-003":  ["3.1.5", "1.4.1"],            # plaintext-HTTP repository
        "MVN-004":  ["1.4.1", "3.1.3"],            # missing <version> element
        "MVN-005":  ["3.1.3"],                     # lax repository checksumPolicy
        "MVN-006":  ["1.4.1", "3.1.3"],            # compromised-package registry
        "MVN-007":  ["3.1.5", "1.4.1"],            # settings.xml wildcard mirror
        # ── Cross-cutting dataflow / taint engine ─────────────────
        # The taint family flags cross-step / cross-job flows where
        # untrusted input reaches a privileged sink. That's the
        # textbook 2.3.8 (pipeline configuration reviewed before
        # execution) failure mode, plus 2.1.3 (build env hardened
        # against attacker-controllable execution).
        "TAINT-001": ["2.3.8", "2.1.3"],           # cross-step taint via $GITHUB_OUTPUT
        "TAINT-002": ["2.3.8", "2.1.3"],           # cross-job taint via jobs.<id>.outputs:
        "TAINT-003": ["2.3.8", "2.1.3"],           # tainted with: forward into reusable workflow
        "TAINT-004": ["2.3.8", "2.1.3"],           # GitLab dotenv cross-job taint flow
        "TAINT-005": ["2.3.8", "2.1.3"],           # Buildkite meta-data cross-step taint flow
        "TAINT-006": ["2.3.8", "2.1.3"],           # Tekton results cross-task taint flow
        "TAINT-007": ["2.3.8", "2.1.3"],           # Argo outputs.parameters cross-template
        "TAINT-008": ["2.3.8", "2.1.3"],           # GitLab extends-chain inheritance
        # ── Terraform / CloudFormation (IaC-native gap-fill) ──────
        # Long-lived IAM access keys declared as code conflict with
        # 1.3.4 (no long-lived credentials) and also leak through
        # the source surface (1.5.1). Hard-coded secrets in resource
        # attributes are the same code-leak shape as DF-006 / GHA-008
        # (1.5.1 + 2.3.4). CodeBuild VPC sharing a public-subnet
        # network is the textbook 2.1.6 (build worker minimal
        # network connectivity) failure mode.
        "TF-001":   ["1.3.4", "1.5.1"],            # aws_iam_access_key declared as code
        "TF-002":   ["1.5.1", "2.3.4"],            # hard-coded secret in resource attr
        "TF-003":   ["2.1.6"],                     # CodeBuild VPC shares public subnet
        "CF-001":   ["1.3.4", "1.5.1"],            # AWS::IAM::AccessKey declared as code
        "CF-002":   ["1.5.1", "2.3.4"],            # hard-coded secret in resource property
        "CF-003":   ["2.1.6"],                     # CodeBuild VPC shares public subnet
        # SCM posture (governance scanned via the GitHub REST API)
        "SCM-001":  ["1.1.17"],                     # default branch unprotected
        "SCM-002":  ["1.1.5"],                      # required reviews missing
        "SCM-003":  ["1.1.7"],                      # default code scanning disabled (SAST)
        "SCM-004":  ["1.5.1"],                      # secret scanning disabled
        "SCM-005":  ["1.1.8"],                      # Dependabot security updates off (SCA)
        "SCM-006":  ["1.1.6"],                      # signed commits not required
        "SCM-007":  ["1.1.17"],                     # force-push allowed
        "SCM-008":  ["1.1.5"],                      # required status checks missing (any CI gate, not SAST-specific)
        "SCM-009":  ["1.1.17"],                     # branch deletions allowed
        "SCM-010":  ["1.1.5"],                      # admin bypass allowed
        "SCM-011":  ["1.1.5"],                      # CODEOWNERS reviews not required
        "SCM-012":  ["1.1.5"],                      # stale reviews not dismissed
        "SCM-013":  ["1.1.5"],                      # conversation resolution not required
        "SCM-014":  ["1.1.5"],                      # last-push approval not required
        "SCM-015":  ["1.5.1"],                      # secret scanning push protection off
        "SCM-016":  ["1.4.1"],                      # private vulnerability reporting off
        "SCM-017":  ["1.1.5"],                      # CODEOWNERS file missing
        "SCM-018":  ["1.1.5"],                      # PR review bypass allowed
        "SCM-019":  ["1.1.17"],                     # push-restriction allowlist names users
        # ── Actions governance + environment protection ─────────────
        "SCM-020":  ["2.4.3"],                      # workflow_token default write (pipeline exec access)
        "SCM-021":  ["1.1.5"],                      # Actions can approve PRs (PR review trust)
        "SCM-022":  ["1.4.1", "3.1.5"],             # allowed_actions unrestricted (3rd-party verify, trusted pkg mgrs)
        "SCM-023":  ["5.1.4", "1.1.5"],             # env missing reviewers (deployment config review)
        "SCM-024":  ["5.2.1"],                      # env branch policy missing (deployment env separation)
        "SCM-025":  ["2.4.3", "1.3.4"],             # deploy keys write-enabled (long-lived push credential)
        "SCM-026":  ["2.4.3"],                      # webhook insecure = unauthenticated pipeline-exec trigger
        "SCM-027":  ["1.1.5"],                      # outside collaborator elevated (review trust boundary)
        "SCM-028":  ["4.2.1"],                      # private repo allows forking (source-leak surface)
        # ── Ruleset enforcement (modern variant of branch protection) ──
        "SCM-029":  ["1.1.17"],                     # ruleset not enforced
        "SCM-030":  ["1.1.17", "1.1.5", "1.1.6"],   # ruleset always-bypass (defeats signing too)
        "SCM-031":  ["1.1.5"],                      # auto-merge enabled
        "SCM-032":  ["1.1.5"],                      # ruleset lacks PR review
        "SCM-033":  ["1.1.5", "1.1.7"],             # ruleset lacks status_checks (CI gate)
        "SCM-034":  ["1.1.17"],                     # ruleset allows force_push
        "SCM-035":  ["1.1.17"],                     # ruleset allows deletion
        "SCM-036":  ["1.1.6"],                      # ruleset lacks signed_commits
        "SCM-037":  ["1.1.5"],                      # ruleset stale-review dismissal
        "SCM-038":  ["1.1.17"],                     # ruleset lacks linear_history (history protection)
        "SCM-039":  ["1.1.7", "1.1.8"],             # ruleset lacks required_workflows (SAST/SCA gate)
        "SCM-040":  ["1.1.7"],                      # ruleset lacks code_scanning gate (SAST gate)
        "SCM-041":  ["5.1.4", "5.2.1"],             # ruleset lacks deployment-env gate
        "SCM-042":  ["1.1.5"],                      # ruleset lacks merge queue (review-control)
        "SCM-043":  ["1.1.6", "1.1.17"],            # tag-ruleset lacks signed_commits
        "SCM-044":  ["1.1.6"],                      # required_signatures bypassed for admins
        "SCM-045":  ["1.1.7"],                      # default code scanning limited query suite
        "SCM-046":  ["1.1.7"],                      # default code scanning configured but paused
        "SCM-047":  ["1.1.7"],                      # repo language not covered by default scanning
    },
)
