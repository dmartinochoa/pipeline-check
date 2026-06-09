"""NIST Secure Software Development Framework (SP 800-218 v1.1).

Subset covering the practices and tasks this scanner can evidence from
CI/CD state. The SSDF is grouped into four practice areas:

- PO. Prepare the Organization
- PS. Protect the Software
- PW. Produce Well-Secured Software
- RV. Respond to Vulnerabilities

Only the tasks for which at least one check produces evidence are
included. A single task may be evidenced by multiple checks, and a
single check may evidence multiple tasks across different practices.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="nist_ssdf",
    title="NIST Secure Software Development Framework",
    version="SP 800-218 v1.1",
    url="https://csrc.nist.gov/pubs/sp/800/218/final",
    controls={
        # Prepare the Organization
        "PO.3.2": "Implement and maintain supporting toolchains with security controls",
        "PO.3.3": "Configure the toolchain to generate an audit trail of SDLC activities",
        "PO.5.1": "Separate and protect each environment involved in software development",
        "PO.5.2": "Secure and harden endpoints used for software development",
        # Protect the Software
        "PS.1.1": "Store all forms of code based on least-privilege and tamper-resistance",
        "PS.2.1": "Make software integrity verification information available to acquirers",
        "PS.3.1": "Securely archive the necessary files and data for each software release",
        "PS.3.2": "Collect, safeguard, maintain, and share provenance data for releases",
        # Produce Well-Secured Software
        "PW.4.1": "Acquire and maintain well-secured 3rd-party software components",
        "PW.4.4": "Verify that acquired components are what is expected and behave as expected",
        "PW.6.1": "Use compiler, interpreter, and build tool features to improve security",
        "PW.9.1": "Configure software to have secure settings by default",
        # Respond to Vulnerabilities
        "RV.1.1": "Gather information about potential vulnerabilities in released software",
    },
    mappings={
        # ── Degraded-mode findings (API access failures) ────────
        # When the scanner cannot enumerate a provider surface, the
        # visibility gap surfaces as an unobservable SDLC audit
        # trail — the same scope as PO.3.3 (configure the toolchain
        # to generate an audit trail of SDLC activities). Mirrors
        # the CIS SSCS 2.3.7 + OWASP CICD-SEC-10 + ESF-C-AUDIT
        # precedent across other standards.
        "CB-000":   ["PO.3.3"],
        "CP-000":   ["PO.3.3"],
        "CD-000":   ["PO.3.3"],
        "ECR-000":  ["PO.3.3"],
        "IAM-000":  ["PO.3.3"],
        "PBAC-000": ["PO.3.3"],
        "CT-000":   ["PO.3.3"],
        "CWL-000":  ["PO.3.3"],
        "EB-000":   ["PO.3.3"],
        "CA-000":   ["PO.3.3"],
        "CCM-000":  ["PO.3.3"],
        "LMB-000":  ["PO.3.3"],
        "KMS-000":  ["PO.3.3"],
        "SM-000":   ["PO.3.3"],
        "SSM-000":  ["PO.3.3"],
        # CodeBuild
        "CB-001":   ["PS.1.1"],                        # plaintext secrets
        "CB-002":   ["PO.5.1", "PW.9.1"],              # privileged mode
        "CB-003":   ["PO.3.3"],                        # build logging disabled
        "CB-004":   ["PO.5.2", "PW.9.1"],              # no build timeout
        "CB-005":   ["PW.4.1", "PW.4.4", "RV.1.1"],    # outdated managed image
        "CB-006":   ["PS.1.1"],                        # long-lived source token
        "CB-007":   ["PO.5.1", "PW.9.1"],              # webhook no filter group
        "CB-008":   ["PS.1.1"],                        # inline buildspec, not from protected repo
        "CB-009":   ["PW.4.1", "PW.4.4"],              # build image not digest-pinned
        "CB-010":   ["PO.5.1"],                        # webhook accepts fork-PR unfiltered
        "CB-011":   ["PW.4.4", "RV.1.1"],              # buildspec malicious-activity indicators
        # CodePipeline
        "CP-001":   ["PO.5.1"],                        # no manual approval
        "CP-002":   ["PS.1.1", "PS.3.1"],              # artifact store not CMK-encrypted
        "CP-003":   ["PO.3.2"],                        # polling source
        "CP-004":   ["PS.1.1"],                        # OAuth-token source
        "CP-005":   ["PO.5.1"],                        # prod Deploy stage no manual approval
        "CP-007":   ["PO.5.1"],                        # v2 PR trigger accepts all branches
        # CodeDeploy
        "CD-001":   ["PO.3.2"],                        # no auto rollback
        "CD-002":   ["PO.5.1"],                        # AllAtOnce deployment
        "CD-003":   ["PO.3.3", "RV.1.1"],              # no CloudWatch alarm
        # ECR
        "ECR-001":  ["PW.4.4", "RV.1.1"],              # no image scan on push
        "ECR-002":  ["PS.3.1", "PS.3.2"],              # mutable tags
        "ECR-003":  ["PO.5.1", "PS.1.1"],              # public repo policy
        "ECR-004":  ["PO.3.2"],                        # no lifecycle policy
        "ECR-005":  ["PS.1.1"],                        # AES256 not CMK
        "ECR-006":  ["PW.4.1", "PW.4.4"],              # pull-through untrusted upstream
        "ECR-007":  ["PW.4.4", "RV.1.1"],              # Inspector v2 enhanced scanning
        # IAM
        "IAM-001":  ["PO.5.1"],
        "IAM-002":  ["PO.5.1"],
        "IAM-003":  ["PO.5.1"],
        "IAM-004":  ["PO.5.1"],
        "IAM-005":  ["PO.5.1"],
        "IAM-006":  ["PO.5.1"],
        "IAM-007":  ["PS.1.1"],                        # access key > 90 days
        "IAM-008":  ["PO.5.1", "PS.1.1"],              # OIDC trust missing aud/sub pin
        "IAM-009":  ["PO.5.1", "PS.1.1"],              # Azure WIF broad subject
        "IAM-010":  ["PO.5.1", "PS.1.1"],              # GCP WIF no repo condition
        # PBAC
        "PBAC-001": ["PO.5.1", "PO.3.2"],              # no VPC for CodeBuild
        "PBAC-002": ["PO.5.1", "PO.3.2"],              # shared service role
        "PBAC-003": ["PO.5.1"],                        # SG 0.0.0.0/0 egress
        "PBAC-005": ["PO.5.1"],                        # stage roles mirror pipeline
        # CodeArtifact / CodeCommit / AWS Signer / Lambda / KMS / SM / SSM
        "CA-001":   ["PS.1.1", "PS.3.1"],              # CodeArtifact domain not CMK-encrypted
        "CA-002":   ["PW.4.1"],                        # CodeArtifact public upstream
        "CA-003":   ["PO.5.1", "PS.1.1"],              # CodeArtifact cross-account wildcard
        "CA-004":   ["PO.5.1", "PS.1.1"],              # CodeArtifact wildcard codeartifact:*
        "CCM-001":  ["PO.5.1", "PS.1.1"],              # CodeCommit no approval rule template
        "CCM-002":  ["PS.1.1", "PS.3.1"],              # CodeCommit not CMK-encrypted
        "CCM-003":  ["PO.5.1"],                        # CodeCommit cross-account trigger
        "SIGN-001": ["PS.2.1", "PS.3.2"],              # no AWS Signer profile for Lambda
        "SIGN-002": ["PS.2.1", "PS.3.2"],              # Signer profile revoked / inactive
        "LMB-001":  ["PS.2.1", "PS.3.2"],              # Lambda has no code-signing config
        "LMB-002":  ["PO.5.1", "PS.1.1"],              # Lambda function URL AuthType=NONE
        "LMB-003":  ["PS.1.1"],                        # Lambda plaintext env secrets
        "LMB-004":  ["PO.5.1", "PS.1.1"],              # Lambda resource policy wildcard principal
        "KMS-001":  ["PS.1.1"],                        # CMK rotation disabled
        "KMS-002":  ["PO.5.1", "PS.1.1"],              # KMS key policy wildcard
        "SM-001":   ["PS.1.1"],                        # Secrets Manager no rotation
        "SM-002":   ["PO.5.1", "PS.1.1"],              # Secrets Manager wildcard principal
        "SSM-001":  ["PS.1.1"],                        # secret-like Parameter not SecureString
        "SSM-002":  ["PS.1.1"],                        # SSM SecureString default key
        # CloudTrail / CloudWatch / EventBridge
        "CT-001":   ["PO.3.3"],                        # no active CloudTrail
        "CT-002":   ["PO.3.3"],                        # log-file validation disabled
        "CT-003":   ["PO.3.3"],                        # trail not multi-region
        "CWL-001":  ["PO.3.3"],                        # CodeBuild log group no retention
        "CWL-002":  ["PO.3.3", "PS.1.1"],              # CodeBuild log group not KMS-encrypted
        "CW-001":   ["PO.3.3", "RV.1.1"],              # no CloudWatch alarm on FailedBuilds
        "EB-001":   ["PO.3.3"],                        # no EventBridge rule for pipeline failure
        "EB-002":   ["PO.5.1"],                        # EventBridge wildcard target ARN
        # S3 artifact store
        "S3-001":   ["PS.1.1"],                        # public access block
        "S3-002":   ["PS.1.1", "PS.3.1"],              # server-side encryption
        "S3-003":   ["PS.3.1", "PS.3.2"],              # versioning (provenance history)
        "S3-004":   ["PO.3.3"],                        # access logging
        "S3-005":   ["PS.1.1"],                        # SecureTransport deny
        # GitHub Actions
        "GHA-001":  ["PW.4.1", "PW.4.4"],              # action not pinned to SHA
        "GHA-110": ["PW.4.4"],  # CI env disables Go module verification
        "GHA-002":  ["PO.5.1", "PW.9.1"],              # pull_request_target with PR head
        "RUN-001":  ["PO.5.1", "PW.9.1"],              # forensics: fork PR ran on a privileged trigger
        "RUN-002":  ["PO.5.1", "PW.9.1"],              # forensics: privileged trigger fired
        "RUN-003":  ["PO.5.1", "PW.9.1"],              # forensics: secret leaked in run logs
        "GHA-003":  ["PW.6.1", "PW.9.1"],              # script injection
        "GHA-119":  ["PW.6.1", "PW.9.1"],              # untrusted context into an agentic AI CLI
        "GHA-120":  ["PW.6.1", "PW.9.1"],              # trust_remote_code model load = code exec
        "GHA-122":  ["PW.6.1", "PW.9.1"],              # unsafe pickle deser of fetched artifact = code exec
        "GHA-121":  ["PW.4.1", "PW.4.4"],              # model pulled without a pinned revision
        "GHA-117":  ["PW.6.1", "PW.9.1"],              # IaC apply on untrusted PR trigger
        "GHA-118":  ["PW.6.1", "PW.9.1"],              # untrusted content into $GITHUB_ENV / $GITHUB_PATH
        "GHA-004":  ["PO.5.1"],                        # no explicit permissions
        "GHA-005":  ["PS.1.1"],                        # long-lived AWS keys
        "GHA-006":  ["PS.2.1", "PS.3.2"],              # unsigned artifacts
        "GHA-007":  ["PS.3.2"],                        # no SBOM
        "GHA-008":  ["PS.1.1"],                        # literal secrets in workflow
        "GHA-009":  ["PO.5.1", "PW.9.1"],              # workflow_run upstream artifact unverified
        "GHA-010":  ["PO.5.1", "PW.9.1"],              # local action on untrusted trigger
        "GHA-011":  ["PO.5.1", "PW.9.1"],              # cache key tainted
        "GHA-012":  ["PO.5.2", "PW.9.1"],              # self-hosted runner not ephemeral
        "GHA-105":  ["PO.5.2", "PW.9.1"],              # self-hosted runner on PR trigger
        "GHA-013":  ["PO.5.1", "PW.9.1"],              # issue_comment no author guard
        "GHA-014":  ["PO.5.1"],                        # deploy job missing environment
        "GHA-123":  ["PO.5.1"],                        # agentic CLI output lands without review
        "GHA-015":  ["PO.5.2", "PW.9.1"],              # job has no timeout-minutes
        "GHA-016":  ["PW.4.1", "PW.4.4"],              # remote script piped to shell
        "GHA-017":  ["PW.4.1", "PW.4.4"],              # package install insecure source
        "GHA-018":  ["PS.1.1"],                        # GITHUB_TOKEN persisted to storage
        "GHA-019":  ["PW.4.4"],                        # install without lockfile enforcement
        "GHA-020":  ["RV.1.1"],                        # no vulnerability scanning step
        "GHA-021":  ["PW.4.4"],                        # dep-update bypasses lockfile pins
        "GHA-022":  ["PW.4.4"],                        # TLS / certificate verification bypass
        "GHA-023":  ["PW.4.1", "PW.4.4"],              # reusable workflow not SHA-pinned
        "GHA-024":  ["PS.2.1", "PS.3.2"],              # no SLSA provenance attestation
        "GHA-025":  ["PW.4.1", "PW.4.4"],              # unpinned reusable workflow
        "GHA-026":  ["PO.5.1", "PW.9.1"],              # container job disables isolation
        "GHA-107":  ["PO.5.1"],                        # harden-runner in audit mode (egress not blocked)
        "GHA-108":  ["PO.5.1"],                        # no runtime egress control on OIDC/deploy workflow
        "GHA-109":  ["PO.5.1"],                        # harden-runner not the first step
        "GHA-027":  ["PW.6.1", "PW.9.1"],              # dangerous shell idiom
        "GHA-028":  ["PW.4.1", "PW.4.4"],              # install bypasses registry integrity
        "GHA-029":  ["PW.4.1", "PW.4.4"],              # package source bypasses lockfile
        "GHA-030":  ["PO.5.1", "PS.1.1"],              # OIDC w/o env-protected job
        "GHA-031":  ["PW.6.1", "PW.9.1"],              # retired set-output / save-state
        "GHA-032":  ["PO.5.1", "PW.9.1"],              # local script on untrusted trigger
        "GHA-033":  ["PS.1.1"],                        # secret echoed in run:
        "GHA-034":  ["PS.1.1"],                        # secrets: inherit
        "GHA-035":  ["PW.6.1", "PW.9.1"],              # github-script untrusted context
        "GHA-036":  ["PW.6.1", "PW.9.1"],              # runs-on untrusted context
        "GHA-037":  ["PS.1.1"],                        # checkout persists GITHUB_TOKEN
        "GHA-038":  ["PW.6.1", "PW.9.1"],              # ACTIONS_ALLOW_UNSECURE_COMMANDS
        "GHA-039":  ["PS.1.1"],                        # services / container creds literal
        "GHA-040":  ["PW.4.1", "PW.4.4", "RV.1.1"],    # known-compromised action ref
        "GHA-041":  ["PW.4.1", "PW.4.4"],              # single-maintainer action (reputation)
        "GHA-042":  ["PW.4.1", "PW.4.4"],              # very-young action repo
        "GHA-043":  ["PW.4.1", "PW.4.4"],              # low-star + sensitive perms
        "GHA-044":  ["PO.5.1", "PW.9.1"],              # build-tool PPE on untrusted trigger
        "GHA-045":  ["PO.5.1", "PW.9.1"],              # caller-ref input drives checkout
        "GHA-046":  ["PO.5.1", "PW.9.1"],              # manual PR-head fetch
        "GHA-047":  ["PW.4.1", "PW.4.4"],              # fresh-ref cooldown
        "GHA-048":  ["PS.1.1"],                        # workflow self-mutation
        "GHA-049":  ["PS.1.1"],                        # cross-repo push from CI
        "GHA-050":  ["PS.1.1"],                        # long-lived registry publish token
        "GHA-051":  ["PW.4.1", "PW.4.4"],              # services / container image unpinned
        "GHA-052":  ["PO.5.1", "PW.9.1"],              # cache key untrusted-input poisoning
        "GHA-053":  ["PW.9.1"],                        # if: predicate untrusted-context
        "GHA-054":  ["PS.1.1"],                        # checkout ssh-key persists
        "GHA-055":  ["PS.1.1"],                        # reusable outputs leak secret
        "GHA-056":  ["PW.4.4", "RV.1.1"],              # worm IOC strings
        "GHA-057":  ["PS.1.1"],                        # secret-scanner output → egress
        "GHA-058":  ["PW.6.1", "PW.9.1"],              # agentic CLI permission-bypass
        "GHA-059":  ["PW.4.4"],                        # npm install without audit signatures
        "GHA-060":  ["PW.4.4"],                        # pip install without --require-hashes
        "GHA-061":  ["PS.1.1"],                        # App token minted without permissions filter
        "GHA-106":  ["PS.1.1"],                        # AI agent with write-scoped token
        "GHA-111":  ["PS.1.1"],  # AI agent edits IaC applied in the same job
        "GHA-112":  ["PO.5.1", "PO.5.2"],  # self-hosted deploy with no environment gate
        "GHA-113":  ["PO.5.1", "PS.1.1"],  # OIDC trusted-publish w/o env gate
        "GHA-114":  ["PO.5.1", "PS.1.1"],  # publish workflow on an unrestricted push trigger
        "GHA-115":  ["PO.5.1"],                        # id-token granted workflow-wide, not job-scoped
        "GHA-116":  ["PS.1.1"],                        # bulk secrets serialization
        "GHA-062":  ["PO.5.1"],                        # OIDC trust subject in sibling IaC is overly broad
        "GHA-063":  ["PO.5.1"],                        # spoofable bot-actor if-predicate
        "GHA-064":  ["PO.5.1"],                        # unsound contains() with comma-string operand
        "GHA-065":  ["PW.6.1"],                        # zero-width / bidi unicode in workflow body
        "GHA-066":  ["PS.1.1"],                        # upload-artifact wildcard sweeps workspace
        "GHA-067":  ["PS.1.1"],                        # cache step publishes credential-shaped paths
        "GHA-068":  ["PW.4.1"],                        # runs-on targets a deprecated hosted runner
        "GHA-069":  ["PO.5.1"],                        # orphan id-token: write scope
        "GHA-070":  ["PW.4.4"],                        # ssh-keyscan / host-key check TOFU
        "GHA-071":  ["PW.6.1"],                        # powershell on Linux / macOS step
        "GHA-072":  ["PS.1.1"],                        # secret env: at wider scope than consumer
        "GHA-073":  ["PS.1.1"],                        # unused workflow_call.secrets declaration
        "GHA-086":  ["PO.5.1"],                        # wildcard branch trigger + environment binding
        "GHA-087":  ["PS.1.1"],                        # derived-value of secret printed to log
        "GHA-088":  ["PW.4.1", "PW.4.4", "RV.1.1"],    # typosquat uses: near-edit of top action
        "GHA-089":  ["PW.4.1", "PW.4.4"],              # archived upstream repo
        "GHA-090":  ["PW.4.1", "PW.4.4", "RV.1.1"],    # impostor-commit: SHA absent from repo
        "GHA-091":  ["PW.4.1", "PW.4.4"],              # repojacking: action upstream missing
        "GHA-092":  ["PO.5.1", "PW.9.1"],              # TOCTOU PR head SHA force-push race
        "GHA-093":  ["PS.1.1"],                        # LOTP indicators
        "GHA-094":  ["PW.4.1", "PW.4.4"],              # stale-action-refs
        "GHA-096":  ["PW.4.1", "PW.4.4", "RV.1.1"],    # known-vulnerable action ref (GHSA)
        # GitLab CI
        "GL-001":   ["PW.4.1", "PW.4.4"],
        "GL-037": ["PW.4.4"],  # CI env disables Go module verification
        "GL-002":   ["PW.6.1", "PW.9.1"],
        "GL-045":   ["PW.6.1", "PW.9.1"],   # trust_remote_code model load = code exec
        "GL-046":   ["PW.4.1", "PW.4.4"],   # model pulled without a pinned revision
        "GL-047":   ["PW.6.1", "PW.9.1"],   # unsafe pickle deser of fetched artifact = code exec
        "GL-048":   ["PW.6.1", "PW.9.1"],   # untrusted MR context into agentic CLI = prompt injection
        "GL-003":   ["PS.1.1"],
        "GL-004":   ["PO.5.1"],
        "GL-044":   ["PO.5.1"],                        # auto production deploy on an MR pipeline
        "GL-005":   ["PW.4.1", "PW.4.4"],
        "GL-042":   ["PW.4.1", "PW.4.4"],    # include: component unpinned
        "GL-006":   ["PS.2.1", "PS.3.2"],              # unsigned artifacts
        "GL-007":   ["PS.3.2"],                        # no SBOM
        "GL-008":   ["PS.1.1"],                        # literal secrets
        "GL-009":   ["PW.4.1", "PW.4.4"],              # image not digest-pinned
        "GL-010":   ["PO.5.1", "PW.9.1"],              # multi-project artifact unverified
        "GL-011":   ["PO.5.1", "PW.9.1"],              # include: local on MR pipeline
        "GL-012":   ["PO.5.1", "PW.9.1"],              # cache key tainted
        "GL-013":   ["PS.1.1"],                        # long-lived AWS keys
        "GL-014":   ["PO.5.2", "PW.9.1"],              # self-managed runner not ephemeral
        "GL-015":   ["PO.5.2", "PW.9.1"],              # no timeout
        "GL-016":   ["PW.4.1", "PW.4.4"],              # remote script piped to shell
        "GL-017":   ["PO.5.1", "PW.9.1"],              # docker privileged / host
        "GL-039":   ["PO.5.1", "PW.9.1"],              # dind daemon TLS disabled / exposed on 2375
        "GL-018":   ["PW.4.1", "PW.4.4"],              # package install insecure source
        "GL-019":   ["RV.1.1"],                        # no vulnerability scanning
        "GL-043":   ["RV.1.1"],                        # native security scanner disabled
        "GL-020":   ["PS.1.1"],                        # CI_JOB_TOKEN persisted
        "GL-021":   ["PW.4.4"],                        # install without lockfile
        "GL-022":   ["PW.4.4"],                        # dep-update bypasses lockfile pins
        "GL-023":   ["PW.4.4"],                        # TLS bypass
        "GL-024":   ["PS.2.1", "PS.3.2"],              # no SLSA provenance
        "GL-025":   ["PW.4.4", "RV.1.1"],              # malicious-activity indicators
        "GL-026":   ["PW.6.1", "PW.9.1"],              # dangerous shell idiom
        "GL-027":   ["PW.4.1", "PW.4.4"],              # install bypasses registry integrity
        "GL-028":   ["PW.4.1", "PW.4.4"],              # services: image not pinned
        "GL-029":   ["PO.5.1"],                        # manual deploy allow_failure
        "GL-030":   ["PW.4.1", "PW.4.4"],              # trigger: include w/o pinned ref
        "GL-031":   ["PO.5.1", "PS.1.1"],              # id_tokens missing audience pin
        "GL-040":   ["PO.5.1", "PS.1.1"],              # CI_JOB_TOKEN used for cross-project access
        "GL-041":   ["PW.6.1", "PW.9.1"],              # IaC apply on an untrusted MR trigger
        "BB-033":   ["PW.6.1", "PW.9.1"],              # IaC apply on a pull-request pipeline
        "BB-034":   ["PO.5.1"],                        # production deploy on a pull-request pipeline
        "GL-032":   ["PW.6.1", "PW.9.1"],              # tags interpolates untrusted
        "GL-033":   ["PO.5.1", "PW.9.1"],              # global before_script taint
        "GL-034":   ["PW.4.4"],                        # npm install without audit signatures
        "GL-035":   ["PW.4.4"],                        # pip install without --require-hashes
        # Bitbucket Pipelines
        "BB-001":   ["PW.4.1", "PW.4.4"],
        "BB-002":   ["PW.6.1", "PW.9.1"],
        "BB-003":   ["PS.1.1"],
        "BB-004":   ["PO.5.1"],
        "BB-005":   ["PO.5.2", "PW.9.1"],
        "BB-006":   ["PS.2.1", "PS.3.2"],              # unsigned artifacts
        "BB-007":   ["PS.3.2"],                        # no SBOM
        "BB-008":   ["PS.1.1"],                        # literal secrets
        "BB-009":   ["PW.4.1", "PW.4.4"],              # pipe not digest-pinned
        "BB-010":   ["PO.5.1", "PW.9.1"],              # deploy step PR artifact unverified
        "BB-011":   ["PS.1.1"],                        # long-lived AWS keys
        "BB-012":   ["PW.4.1", "PW.4.4"],              # remote script piped to shell
        "BB-013":   ["PO.5.1", "PW.9.1"],              # docker privileged
        "BB-014":   ["PW.4.1", "PW.4.4"],              # package install insecure source
        "BB-015":   ["RV.1.1"],                        # no vulnerability scanning
        "BB-016":   ["PO.5.2", "PW.9.1"],              # self-hosted runner not ephemeral
        "BB-017":   ["PS.1.1"],                        # repo token persisted to storage
        "BB-018":   ["PO.5.1", "PW.9.1"],              # cache key tainted
        "BB-019":   ["PS.1.1"],                        # after-script references secrets
        "BB-020":   ["PS.1.1"],                        # full clone depth exposes history
        "BB-021":   ["PW.4.4"],                        # install without lockfile
        "BB-022":   ["PW.4.4"],                        # dep-update bypasses lockfile pins
        "BB-023":   ["PW.4.4"],                        # TLS bypass
        "BB-024":   ["PS.2.1", "PS.3.2"],              # no SLSA provenance
        "BB-025":   ["PW.4.4", "RV.1.1"],              # malicious-activity indicators
        "BB-026":   ["PW.6.1", "PW.9.1"],              # dangerous shell idiom
        "BB-027":   ["PW.4.1", "PW.4.4"],              # install bypasses registry integrity
        "BB-028":   ["PO.5.1", "PS.1.1"],              # OIDC step w/o env-gated deployment
        "BB-029":   ["PW.4.1", "PW.4.4"],              # step + service image not pinned
        "BB-030":   ["PW.4.4"],                        # npm install without audit signatures
        "BB-031":   ["PW.4.4"],                        # pip install without --require-hashes
        # Azure DevOps Pipelines
        "ADO-001":  ["PW.4.1", "PW.4.4"],
        "ADO-002":  ["PW.6.1", "PW.9.1"],
        "ADO-003":  ["PS.1.1"],
        "ADO-004":  ["PO.5.1"],
        "ADO-005":  ["PW.4.1", "PW.4.4"],
        "ADO-006":  ["PS.2.1", "PS.3.2"],              # unsigned artifacts
        "ADO-007":  ["PS.3.2"],                        # no SBOM
        "ADO-008":  ["PS.1.1"],                        # literal secrets
        "ADO-009":  ["PW.4.1", "PW.4.4"],              # container image not digest-pinned
        "ADO-010":  ["PO.5.1", "PW.9.1"],              # cross-pipeline download unverified
        "ADO-011":  ["PO.5.1", "PW.9.1"],              # template: local on PR-validated
        "ADO-012":  ["PO.5.1", "PW.9.1"],              # Cache@2 PullRequest context
        "ADO-013":  ["PO.5.2", "PW.9.1"],              # self-hosted pool not ephemeral
        "ADO-014":  ["PS.1.1"],                        # long-lived AWS keys
        "ADO-015":  ["PO.5.2", "PW.9.1"],              # no timeoutInMinutes
        "ADO-016":  ["PW.4.1", "PW.4.4"],              # remote script piped to shell
        "ADO-017":  ["PO.5.1", "PW.9.1"],              # docker privileged
        "ADO-018":  ["PW.4.1", "PW.4.4"],              # package install insecure source
        "ADO-019":  ["PO.5.1", "PW.9.1"],              # extends template injection
        "ADO-020":  ["RV.1.1"],                        # no vulnerability scanning
        "ADO-021":  ["PW.4.4"],                        # install without lockfile
        "ADO-022":  ["PW.4.4"],                        # dep-update bypasses lockfile pins
        "ADO-023":  ["PW.4.4"],                        # TLS bypass
        "ADO-024":  ["PS.2.1", "PS.3.2"],              # no SLSA provenance
        "ADO-025":  ["PW.4.1", "PW.4.4"],              # unpinned cross-repo template
        "ADO-026":  ["PW.4.4", "RV.1.1"],              # malicious-activity indicators
        "ADO-027":  ["PW.6.1", "PW.9.1"],              # dangerous shell idiom
        "ADO-028":  ["PW.4.1", "PW.4.4"],              # install bypasses registry integrity
        "ADO-029":  ["PO.5.1"],                        # service-conn job w/o env gate
        "ADO-030":  ["PW.6.1", "PW.9.1"],              # pool interpolates untrusted
        # CircleCI
        "CC-001":   ["PW.4.1", "PW.4.4"],              # orb not pinned to SHA
        "CC-033": ["PW.4.4"],  # CI env disables Go module verification
        "CC-002":   ["PW.6.1", "PW.9.1"],              # script injection
        "CC-003":   ["PW.4.1", "PW.4.4"],              # image not pinned to digest
        "CC-004":   ["PS.1.1"],                        # unrestricted context
        "CC-005":   ["PS.1.1"],                        # long-lived AWS keys
        "CC-006":   ["PS.2.1", "PS.3.2"],              # unsigned artifacts
        "CC-007":   ["PS.3.2"],                        # no SBOM / provenance
        "CC-008":   ["PS.1.1"],                        # literal secrets in config
        "CC-009":   ["PO.5.1"],                        # no deployment approval
        "CC-010":   ["PO.5.2", "PW.9.1"],              # self-hosted runner
        "CC-011":   ["PO.3.3"],                        # no build retention
        "CC-012":   ["PW.6.1", "PW.9.1"],              # setup / dynamic config
        "CC-013":   ["PO.5.1"],                        # no branch filter
        "CC-014":   ["PO.5.1", "PO.5.2"],              # resource class isolation
        "CC-015":   ["PO.5.2", "PW.9.1"],              # no timeout
        "CC-016":   ["PW.4.1", "PW.4.4"],              # curl | bash
        "CC-017":   ["PO.5.2", "PW.9.1"],              # insecure Docker config
        "CC-018":   ["PW.4.1", "PW.4.4"],              # insecure package source
        "CC-019":   ["PS.1.1"],                        # SSH key in config
        "CC-020":   ["RV.1.1"],                        # no vulnerability scanning
        "CC-021":   ["PW.4.4"],                        # no lockfile
        "CC-022":   ["PW.4.1"],                        # no dependency updates
        "CC-023":   ["PW.4.4"],                        # TLS verification bypass
        "CC-024":   ["PS.2.1", "PS.3.2"],              # no SLSA provenance
        "CC-025":   ["PO.5.1", "PW.9.1"],              # cache key tainted
        "CC-026":   ["PW.4.4", "RV.1.1"],              # malicious-activity indicators
        "CC-027":   ["PW.6.1", "PW.9.1"],              # dangerous shell idiom
        "CC-028":   ["PW.4.1", "PW.4.4"],              # install bypasses registry integrity
        "CC-029":   ["PW.4.1", "PW.4.4"],              # machine executor image not pinned
        "CC-030":   ["PO.5.1"],                        # job w/o branch filter / approval gate
        "CC-031":   ["PO.5.1", "PS.1.1"],              # OIDC role w/o branch filter
        # Buildkite — same shape as the other CI providers, mapped to
        # the corresponding tasks. Plugin / curl-pipe / TLS-bypass land
        # under PW.4.* (acquire / verify components); secret / signing
        # land under PS.* (protect software, integrity, provenance).
        "BK-001":   ["PW.4.1", "PW.4.4"],              # plugin not pinned
        "BK-002":   ["PS.1.1"],                        # literal secret
        "BK-003":   ["PW.6.1", "PW.9.1"],              # untrusted variable interp
        "BK-004":   ["PW.4.1", "PW.4.4"],              # curl-pipe
        "BK-005":   ["PO.5.1", "PW.9.1"],              # privileged container
        "BK-006":   ["PO.5.2", "PW.9.1"],              # no timeout
        "BK-007":   ["PO.5.1"],                        # no manual deploy gate
        "BK-008":   ["PW.4.4"],                        # TLS bypass
        "BK-009":   ["PS.2.1", "PS.3.2"],              # no signing
        "BK-010":   ["PS.3.2"],                        # no SBOM
        "BK-011":   ["PS.3.2"],                        # no SLSA provenance
        "BK-012":   ["RV.1.1"],                        # no vuln scan
        "BK-013":   ["PO.5.1"],                        # no branches filter
        "BK-014":   ["PW.4.1", "PW.4.4"],              # unpinned package install
        "BK-015":   ["PW.6.1", "PW.9.1"],              # agents map untrusted interpolation
        "BK-016":   ["PW.6.1", "PW.9.1"],              # dangerous shell idiom
        # ── Jenkins ─────────────────────────────────────────────
        "JF-001":   ["PW.4.1", "PW.4.4"],              # shared library not pinned
        "JF-002":   ["PW.6.1", "PW.9.1"],              # script step untrusted env
        "JF-003":   ["PO.5.1"],                        # agent any (no executor isolation)
        "JF-004":   ["PS.1.1"],                        # AWS long-lived keys via withCredentials
        "JF-005":   ["PO.5.1"],                        # deploy stage missing manual input
        "JF-006":   ["PS.2.1", "PS.3.2"],              # artifacts not signed
        "JF-007":   ["PS.3.2"],                        # SBOM not produced
        "JF-008":   ["PS.1.1"],                        # credential-shaped literal
        "JF-009":   ["PW.4.1", "PW.4.4"],              # agent docker image not digest-pinned
        "JF-010":   ["PS.1.1"],                        # long-lived AWS keys in environment {}
        "JF-011":   ["PO.3.3"],                        # no buildDiscarder retention
        "JF-012":   ["PW.4.1", "PW.4.4"],              # load step pulls Groovy w/o integrity pin
        "JF-013":   ["PO.5.1", "PW.9.1"],              # copyArtifacts ingests upstream unverified
        "JF-014":   ["PO.5.2", "PW.9.1"],              # agent label missing ephemeral marker
        "JF-015":   ["PO.5.2", "PW.9.1"],              # pipeline has no timeout wrapper
        "JF-016":   ["PW.4.1", "PW.4.4"],              # remote script piped to shell
        "JF-017":   ["PO.5.1", "PW.9.1"],              # docker run privileged / host
        "JF-018":   ["PW.4.1", "PW.4.4"],              # package install insecure source
        "JF-019":   ["PO.5.1", "PW.9.1"],              # Groovy sandbox escape pattern
        "JF-020":   ["RV.1.1"],                        # no vulnerability scanning step
        "JF-021":   ["PW.4.4"],                        # install without lockfile
        "JF-022":   ["PW.4.4"],                        # dep-update bypasses lockfile pins
        "JF-023":   ["PW.4.4"],                        # TLS bypass
        "JF-024":   ["PO.5.1"],                        # input approval missing submitter restriction
        "JF-025":   ["PO.5.1", "PW.9.1"],              # K8s agent pod privileged / hostPath
        "JF-026":   ["PO.5.1", "PW.9.1"],              # build job: trigger ignores downstream failure
        "JF-027":   ["PS.3.2"],                        # archiveArtifacts no fingerprint
        "JF-028":   ["PS.2.1", "PS.3.2"],              # no SLSA provenance attestation
        "JF-029":   ["PW.4.4", "RV.1.1"],              # malicious-activity indicators
        "JF-030":   ["PW.6.1", "PW.9.1"],              # dangerous shell idiom
        "JF-031":   ["PW.4.1", "PW.4.4"],              # install bypasses registry integrity
        "JF-032":   ["PW.6.1", "PW.9.1"],              # agent label interpolates untrusted
        "JF-033":   ["PS.1.1"],                        # withCredentials leaked via Groovy ${}
        "JF-034":   ["PS.1.1"],                        # password() build parameter
        "JF-035":   ["PW.4.4"],                        # httpRequest SSL off
        "JF-036":   ["PW.6.1", "PW.9.1"],              # sh body interpolates params.*
        # ── Drone CI ────────────────────────────────────────────
        "DR-001":   ["PW.4.1", "PW.4.4"],              # step image not digest-pinned
        "DR-002":   ["PO.5.1", "PW.9.1"],              # privileged step
        "DR-003":   ["PW.6.1", "PW.9.1"],              # Drone variable injection
        "DR-004":   ["PS.1.1"],                        # literal credential
        "DR-005":   ["PW.4.1", "PW.4.4"],              # plugin floating tag
        "DR-006":   ["PW.4.4"],                        # TLS bypass in commands
        "DR-007":   ["PO.5.1", "PW.9.1"],              # sensitive host-path mount
        "DR-008":   ["PW.4.1", "PW.4.4"],              # pull: never (skips registry verify)
        "DR-009":   ["PO.5.1", "PW.9.1"],              # cache key tainted
        "DR-010":   ["PW.4.1", "PW.4.4"],              # unpinned package install
        "DR-011":   ["PW.6.1", "PW.9.1"],              # node map interpolates untrusted
        # ── Drone extended pack ──
        "DR-012":   ["PW.4.1", "PW.4.4"],              # service image not pinned
        "DR-013":   ["PO.5.1"],                        # no trigger event filter
        "DR-014":   ["PW.4.4"],                        # pipe-to-shell
        "DR-015":   ["PW.4.4"],                        # clone recursive
        "DR-016":   ["PW.4.4", "PW.6.1"],              # image field interpolation
        "DR-017":   ["PW.6.1", "PW.9.1"],              # dangerous shell idiom
        # ── Tekton ──────────────────────────────────────────────
        "TKN-001":  ["PW.4.1", "PW.4.4"],              # step image not digest-pinned
        "TKN-016": ["PW.4.1", "PW.4.4"],  # remote resolver / bundle task body not pinned
        "TKN-002":  ["PO.5.1", "PW.9.1"],              # step privileged / root
        "TKN-003":  ["PW.6.1", "PW.9.1"],              # param injection in script
        "TKN-004":  ["PO.5.1", "PW.9.1"],              # hostPath / host namespaces
        "TKN-005":  ["PS.1.1"],                        # leaked creds in env / param
        "TKN-006":  ["PO.5.2", "PW.9.1"],              # no explicit timeout
        "TKN-007":  ["PO.5.1"],                        # default ServiceAccount
        "TKN-008":  ["PW.4.1", "PW.4.4"],              # remote install / TLS bypass
        "TKN-009":  ["PS.2.1", "PS.3.2"],              # artifacts not signed
        "TKN-010":  ["PS.3.2"],                        # SBOM not generated
        "TKN-011":  ["PS.2.1", "PS.3.2"],              # SLSA provenance
        "TKN-012":  ["RV.1.1"],                        # no vulnerability scanning
        "TKN-013":  ["PO.5.1", "PW.9.1"],              # sidecar privileged / root
        "TKN-014":  ["PW.4.1", "PW.4.4"],              # unpinned package install
        "TKN-015":  ["PO.5.1", "PW.9.1"],              # workspace subPath param injection
        # ── Argo Workflows ──────────────────────────────────────
        "ARGO-001": ["PW.4.1", "PW.4.4"],              # template image not digest-pinned
        "ARGO-002": ["PO.5.1", "PW.9.1"],              # template privileged / root
        "ARGO-003": ["PO.5.1"],                        # default ServiceAccount
        "ARGO-016": ["PO.5.1"],                        # cluster-admin / over-privileged ServiceAccount
        "ARGO-004": ["PO.5.1", "PW.9.1"],              # hostPath / host namespaces
        "ARGO-005": ["PW.6.1", "PW.9.1"],              # parameter injection in script
        "ARGO-017": ["PW.6.1", "PW.9.1"],              # resource template manifest injection
        "ARGOCD-019": ["PW.9.1"],                      # drift detection disabled on a sensitive field
        "ARGO-006": ["PS.1.1"],                        # leaked creds in env / param
        "ARGO-007": ["PO.5.2", "PW.9.1"],              # missing activeDeadlineSeconds
        "ARGO-008": ["PW.4.1", "PW.4.4"],              # remote install / TLS bypass
        "ARGO-009": ["PS.2.1", "PS.3.2"],              # artifacts not signed
        "ARGO-010": ["PS.3.2"],                        # SBOM not generated
        "ARGO-011": ["PS.2.1", "PS.3.2"],              # SLSA provenance
        "ARGO-012": ["RV.1.1"],                        # no vulnerability scanning
        "ARGO-013": ["PO.5.1"],                        # SA token automount default
        "ARGO-014": ["PW.4.1", "PW.4.4"],              # unpinned package install
        "ARGO-015": ["PW.4.4", "PS.2.1"],              # insecure (non-HTTPS) artifact URL
        # Dockerfile — image-build supply chain. Pinning / verification
        # rules tie to PW.4.* (acquire and verify 3rd-party components);
        # privileged / root / sensitive-path rules tie to PO.5.1 +
        # PW.9.1 (env separation, secure defaults); credential-shape
        # rules tie to PS.1.1 (least-privilege code storage).
        "DF-001":   ["PW.4.1", "PW.4.4"],              # FROM not digest-pinned
        "DF-031":   ["PW.4.1", "PW.4.4"],              # COPY --from external image not digest-pinned
        "DF-002":   ["PO.5.1", "PW.9.1"],              # runs as root
        "DF-003":   ["PW.4.4", "PS.2.1"],              # ADD remote, no integrity
        "DF-004":   ["PW.4.1", "PW.4.4"],              # curl-pipe in RUN
        "DF-005":   ["PW.6.1", "PW.9.1"],              # shell-eval
        "DF-006":   ["PS.1.1"],                        # ENV credential literal
        "DF-007":   ["PO.3.3", "RV.1.1"],              # no HEALTHCHECK
        "DF-008":   ["PO.5.1", "PW.9.1"],              # docker --privileged
        "DF-009":   ["PW.6.1"],                        # ADD where COPY suffices
        "DF-010":   ["PW.4.1"],                        # apt dist-upgrade
        "DF-011":   ["PW.4.1"],                        # no cache cleanup
        "DF-012":   ["PO.5.1", "PW.9.1"],              # RUN sudo
        "DF-013":   ["PO.5.1", "PW.9.1"],              # sensitive EXPOSE
        "DF-014":   ["PW.9.1"],                        # WORKDIR /etc
        "DF-015":   ["PW.9.1"],                        # chmod 777
        "DF-016":   ["PS.3.2"],                        # no OCI provenance labels
        "DF-017":   ["PW.9.1"],                        # PATH world-writable
        "DF-018":   ["PW.9.1"],                        # chown system path
        "DF-019":   ["PS.1.1"],                        # COPY credential file
        "DF-020":   ["PS.1.1"],                        # credential-named ARG
        # Helm chart-supply-chain — every HELM-* rule scores a chart's
        # own posture (lockfile drift, transport, plaintext metadata),
        # so they ride mostly on PW.4.* (acquire / verify components)
        # and PS.3.* (provenance / archive). Hygiene fields (description,
        # maintainers, appVersion) tie to PO.3.3 audit trail.
        "HELM-001": ["PW.6.1"],                        # legacy apiVersion
        "HELM-002": ["PW.4.4", "PS.3.2"],              # no lockfile digests
        "HELM-003": ["PW.4.4", "PS.2.1"],              # non-HTTPS dep repo
        "HELM-004": ["PW.4.1", "PW.4.4"],              # dep version range
        "HELM-005": ["PO.3.3"],                        # missing maintainers
        "HELM-006": ["PO.5.1"],                        # missing kubeVersion
        "HELM-007": ["PO.3.3"],                        # missing description
        "HELM-008": ["PW.4.1"],                        # stale Chart.lock
        "HELM-009": ["PW.4.4"],                        # non-HTTPS home/sources
        "HELM-010": ["PO.3.3", "PS.3.2"],              # missing appVersion
        # ── Helm extended pack ──
        "HELM-011": ["PS.1.1"],                        # dependency URL embedded creds
        "HELM-012": ["PW.4.4"],                        # deprecated without successor
        "HELM-013": ["PW.4.4"],                        # invalid chart type
        "HELM-014": ["PW.4.4", "RV.1.1"],              # known-compromised dependency
        "HELM-015": ["PW.4.4"],  # oci:// dependency not digest-pinned
        "HELM-016": ["PS.1.1"],  # default secret in values.yaml
        "HELM-017": ["PW.4.4"],  # tpl of an untrusted .Values value
        # ── Cloud Build (GCB) ────────────────────────────────────
        "GCB-001": ["PW.4.1", "PW.4.4"],               # step image not pinned
        "GCB-002": ["PS.1.1"],                         # plaintext env secret
        "GCB-003": ["PS.1.1"],                         # plain script secret
        "GCB-004": ["PW.4.1", "PW.4.4"],               # community step not SHA-pinned
        "GCB-005": ["PS.1.1"],                         # secret-shaped substitution
        "GCB-006": ["PO.3.3"],                         # build logging disabled
        "GCB-007": ["PW.4.1"],                         # latest secret version
        "GCB-008": ["PS.2.1", "PS.3.2"],               # no signing
        "GCB-009": ["PS.3.2"],                         # no SBOM
        "GCB-010": ["PO.5.1"],                         # default network egress
        "GCB-011": ["PW.4.4"],                         # TLS bypass
        "GCB-012": ["RV.1.1"],                         # no vuln scan
        "GCB-013": ["PS.1.1"],                         # default service account
        "GCB-014": ["PW.6.1", "PW.9.1"],               # untrusted substitution
        "GCB-015": ["PS.3.2"],                         # no provenance
        "GCB-016": ["PO.5.2", "PW.9.1"],               # no timeout
        "GCB-017": ["PO.3.3"],                         # default logs
        "GCB-018": ["PW.4.1"],                         # legacy gcr.io
        "GCB-019": ["PO.5.1", "PW.9.1"],               # privileged step
        "GCB-020": ["PS.1.1"],                         # default SA email
        "GCB-021": ["PO.5.1"],                         # no private worker pool
        "GCB-022": ["PW.6.1", "PW.9.1"],               # ALLOW_LOOSE substitution
        "GCB-023": ["PS.2.1", "PS.3.2"],               # build artifacts not signed
        "GCB-024": ["PS.3.2"],                         # missing provenance labels
        "GCB-025": ["PW.4.1"],                         # outdated runner image
        "GCB-026": ["PS.1.1"],                         # public storage bucket
        "GCB-027": ["PW.4.4", "RV.1.1"],               # malicious-activity indicators
        # ── NPM / PyPI / Maven dep supply-chain ─────────────────
        # PW.4.* (acquire / verify components) is the natural home
        # for pinning + integrity + non-registry sources.
        # Compromised packages also evidence RV.1.1 (vuln gather).
        # Lifecycle / ignore-scripts evidence PO.5.1 + PW.9.1.
        "NPM-001":  ["PW.4.1", "PW.4.4"],              # floating range
        "NPM-002":  ["PW.4.4"],                        # lock entry missing integrity
        "NPM-003":  ["PW.4.1", "PW.4.4"],              # non-registry source
        "NPM-004":  ["PO.5.1", "PW.9.1"],              # install-time lifecycle script
        "NPM-005":  ["PW.4.1", "PW.4.4"],              # git dep mutable ref
        "NPM-006":  ["PW.4.1", "PW.4.4", "RV.1.1"],    # compromised npm version
        "NPM-007":  ["PO.5.1", "PW.9.1"],              # .npmrc ignore-scripts
        "NPM-011":  ["PS.1.1"],                        # secret-shaped paths in files field
        "NPM-013":  ["PS.1.1"],                        # broad files-field publishes everything
        "PYPI-001": ["PW.4.1", "PW.4.4"],              # missing ==pin
        "PYPI-002": ["PW.4.4"],                        # hash pinning missing
        "PYPI-003": ["PW.4.1", "PW.4.4"],              # http index / --trusted-host
        "PYPI-018": ["PW.4.1", "PW.4.4"],  # --no-binary forces sdist build
        "PYPI-004": ["PW.4.1", "PW.4.4"],              # VCS dep without commit SHA
        "PYPI-015": ["PW.4.1", "PW.4.4"],  # direct artifact URL
        "PYPI-005": ["PW.4.1", "PW.4.4"],              # --extra-index-url (dep confusion)
        "PYPI-017": ["PW.4.1", "PW.4.4"],  # remote --find-links
        "PYPI-016": ["PW.4.1", "PW.4.4"],  # primary index repointed
        "PYPI-006": ["PW.4.1", "PW.4.4", "RV.1.1"],    # compromised PyPI version
        "MVN-001":  ["PW.4.1", "PW.4.4"],              # floating Maven range
        "MVN-002":  ["PW.4.1", "PW.4.4"],              # mutable SNAPSHOT dep
        "MVN-003":  ["PW.4.1", "PW.4.4"],              # plaintext-HTTP repository
        "MVN-004":  ["PW.4.1", "PW.4.4"],              # missing <version>
        "MVN-005":  ["PW.4.4"],                        # lax checksumPolicy
        "MVN-006":  ["PW.4.1", "PW.4.4", "RV.1.1"],    # compromised Maven version
        "MVN-007":  ["PW.4.1", "PW.4.4"],              # settings.xml wildcard mirror
        "MVN-008":  ["PW.4.1", "PW.4.4", "RV.1.1"],    # cooldown gate (--resolve-remote)
        "MVN-009":  ["PW.4.1", "PW.4.4", "RV.1.1"],    # OSV advisory (--resolve-remote)
        # ── Maven extended pack ──
        "MVN-010":  ["PS.1.1"],                        # plaintext server password
        "MVN-011":  ["PS.1.1"],                        # repo URL credentials
        "MVN-012":  ["PW.4.4"],                        # build plugin floating
        "MVN-013":  ["PW.4.4"],                        # build extension floating
        "MVN-014":  ["PS.1.1", "PW.4.4"],              # wrapper sha256 missing
        "MVN-015": ["PW.4.4"],  # build-time plugin exec bound to lifecycle
        "MVN-016": ["PW.4.4"],  # gradle allowInsecureProtocol
        "MVN-017": ["PS.1.1"],  # settings.xml privateKey + plaintext passphrase
        "MVN-018": ["PW.4.4"],  # distributionManagement release accepts snapshots
        "NPM-008":  ["PW.4.1", "PW.4.4", "RV.1.1"],    # cooldown gate (--resolve-remote)
        "NPM-009":  ["PW.4.1", "PW.4.4"],              # new-transitive-dep diff gate
        "NPM-010":  ["PW.4.1", "PW.4.4", "RV.1.1"],    # OSV advisory (--resolve-remote)
        "PYPI-008": ["PW.4.1", "PW.4.4", "RV.1.1"],    # cooldown gate (--resolve-remote)
        "PYPI-009": ["PW.4.1", "PW.4.4", "RV.1.1"],    # OSV advisory (--resolve-remote)
        # ── PyPI extended pack (PYPI-010..014) ──
        "PYPI-010": ["PS.1.1"],                        # index URL with embedded credentials
        "PYPI-011": ["PW.4.4"],                        # --trusted-host disables TLS
        "PYPI-012": ["PW.4.4"],                        # build-system requires floating
        "PYPI-013": ["PW.4.4"],                        # pyproject dynamic dependencies
        "PYPI-014": ["PW.4.4"],                        # custom source HTTP
        # ── nuget (dep supply-chain) ─────────────────────────────
        "NUGET-001": ["PW.4.1", "PW.4.4"],             # floating NuGet version range
        "NUGET-002": ["PW.4.1", "PW.4.4"],             # wildcard prerelease version
        "NUGET-003": ["PW.4.1", "PW.4.4"],             # missing explicit version
        "NUGET-004": ["PW.4.1", "PW.4.4"],             # HTTP-only package source
        "NUGET-005": ["PW.4.1", "PW.4.4", "RV.1.1"],   # known-compromised package version
        "NUGET-006": ["PW.4.4"],                        # no lock file for reproducible restores
        "NUGET-007": ["PW.4.1", "PW.4.4"],             # multiple sources without packageSourceMapping
        "NUGET-008": ["PW.4.1", "PW.4.4", "RV.1.1"],   # cooldown gate (--resolve-remote)
        "NUGET-009": ["PW.4.1", "PW.4.4", "RV.1.1"],   # OSV advisory (--resolve-remote)
        "NUGET-010": ["PS.1.1"],                       # NuGet.config cleartext feed credential
        # ── NuGet extended pack ──
        "NUGET-011": ["PW.4.4"],                       # source mapping wildcard
        "NUGET-012": ["PW.4.4", "PS.3.2"],             # signature validation off
        "NUGET-013": ["PW.4.4"],                       # dotnet-tools unpinned
        "NUGET-014": ["PS.1.1"],                       # source URL credentials
        "NUGET-015": ["PO.5.1", "PW.4.4"],             # VersionOverride breaks CPM
        "NUGET-016": ["PW.4.1", "PW.4.4"],             # missing <clear/> inherits public gallery
        "NUGET-017": ["PW.4.1", "PW.4.4"],  # public gallery active alongside private feed, not disabled
        "NUGET-018": ["PW.4.4"],                       # build-time MSBuild execution
        "NUGET-019": ["PW.4.4", "PS.3.2"],             # require mode, no trusted signers
        # ── Go modules (GOMOD-001..006) ──
        "GOMOD-001": ["PS.1.1", "PW.4.4"],             # go.sum integrity manifest missing
        "GOMOD-002": ["PO.5.1", "PW.4.4"],             # replace directive to local path
        "GOMOD-003": ["PO.5.1", "PW.4.4"],             # replace directive to different module
        "GOMOD-004": ["PW.4.4"],                       # +incompatible direct require
        "GOMOD-005": ["PO.5.1"],                       # missing go toolchain directive
        "GOMOD-006": ["PW.4.4", "RV.1.1"],             # known-compromised module version
        # ── Go modules extended pack ──
        "GOMOD-007": ["PS.1.1", "PW.4.4"],             # vendor/modules.txt stale
        "GOMOD-008": ["PO.5.1", "PW.4.4"],             # replace without version pin
        "GOMOD-009": ["PW.4.4"],                       # pre-release direct require
        "GOMOD-010": ["PO.5.1"],                       # stale exclude directive
        "GOMOD-011": ["PW.4.4"],  # tool directive build-time exec
        "GOMOD-012": ["PW.4.4"],  # insecure / non-canonical module host
        # ── Cargo / Rust (CARGO-001..006) ──
        "CARGO-001": ["PW.4.4"],                       # floating Cargo.toml version spec
        "CARGO-002": ["PO.5.1", "PW.4.4"],             # git dep with mutable ref (no rev)
        "CARGO-003": ["PS.1.1", "PW.4.4"],             # missing Cargo.lock
        "CARGO-004": ["PO.5.1", "PW.4.4"],             # local-path Cargo dependency
        "CARGO-005": ["PO.5.1", "PW.4.4"],             # alternate-registry Cargo dependency
        "CARGO-006": ["PW.4.4", "RV.1.1"],             # known-compromised crate version
        # ── Cargo extended pack ──
        "CARGO-007": ["PW.4.4", "RV.1.1"],             # build-deps floating
        "CARGO-008": ["PO.5.1", "PW.4.4"],             # patch.crates-io substitution
        "CARGO-009": ["PW.4.4"],                       # workspace deps floating
        "CARGO-010": ["PO.5.1"],                       # missing rust-version
        "CARGO-011": ["PW.4.4"],  # build.rs compile-time egress / exec
        "CARGO-012": ["PW.4.4"],  # .cargo/config.toml source override / build flags
        "CARGO-013": ["PW.4.4"],  # Cargo.lock off-crates.io source
        "CARGO-014": ["PW.4.4"],  # no supply-chain audit-gate config
        # ── Composer / PHP ──
        "COMPOSER-001": ["PW.4.4", "RV.1.1"],
        "COMPOSER-002": ["PW.4.4", "RV.1.1"],
        "COMPOSER-003": ["PW.4.4", "PO.5.1"],
        "COMPOSER-012": ["PW.4.4", "PO.5.1"],  # disables Packagist / marks custom repo canonical
        "COMPOSER-011": ["PW.4.4", "PO.5.1"],  # external VCS repository re-points a package
        "COMPOSER-004": ["PS.1.1", "PO.5.1"],
        "COMPOSER-005": ["PW.4.4"],
        "COMPOSER-014": ["PW.4.4"],  # minimum-stability without prefer-stable
        "COMPOSER-006": ["PW.4.4", "PO.5.1"],
        "COMPOSER-007": ["PW.4.4", "RV.1.1"],
        "COMPOSER-008": ["PW.4.4"],
        "COMPOSER-009": ["PS.1.1", "PO.5.1"],
        "COMPOSER-010": ["PW.4.4", "PO.5.1"],
        "COMPOSER-013": ["PW.4.4", "PO.5.1"],  # config.disable-tls
        # ── RubyGems / Bundler ──
        "GEM-001": ["PW.4.4", "RV.1.1"],
        "GEM-002": ["PW.4.4", "RV.1.1"],
        "GEM-003": ["PW.4.4", "PO.5.1"],
        "GEM-004": ["PS.1.1", "PO.5.1"],
        "GEM-005": ["PW.4.4"],
        "GEM-006": ["PW.4.4", "RV.1.1"],
        "GEM-007": ["PW.4.4"],
        "GEM-008": ["PW.4.4"],
        "GEM-009": ["PS.1.1", "PO.5.1"],
        "GEM-010": ["PW.4.4"],
        "GEM-011": ["PW.4.4"],  # Bundler plugin install-time exec
        "GEM-012": ["PW.4.4"],  # per-gem :source override
        "GEM-013": ["PW.4.4"],  # insecure git transport
        # ── Pulumi (PULUMI-001..006) ──
        "PULUMI-001": ["PS.1.1", "PO.5.1"],             # passphrase secretsprovider
        "PULUMI-002": ["PS.1.1"],                       # secret-shaped config plaintext
        "PULUMI-003": ["PS.1.1", "PO.5.1"],             # hardcoded credentials in source
        "PULUMI-011": ["PS.1.1", "PO.5.1"],  # plugin from custom download server
        "PULUMI-004": ["PO.5.1", "PW.4.4"],             # insecure state backend
        "PULUMI-005": ["PO.5.1"],                       # wildcard IAM policy in source
        "PULUMI-006": ["PO.5.1", "PW.4.4"],             # StackReference unguarded
        # ── Pulumi extended pack ──
        "PULUMI-007": ["PO.5.1"],                       # public-access cloud resource
        "PULUMI-008": ["PW.4.4", "PO.5.1"],             # shell-exec with non-constant input
        "PULUMI-013": ["PW.4.4", "PO.5.1"],  # dynamic provider deploy-time code
        "PULUMI-014": ["PW.4.4", "PO.5.1"],  # ESC environment imported without a qualifier
        "PULUMI-009": ["PO.3.3"],                       # runtime / source mismatch
        "PULUMI-012": ["PO.3.3"],  # plugin version unpinned
        "PULUMI-010": ["PS.1.1"],                       # stack orphaned encryption salt
        # ── Dockerfile env-bypass pack (DF-021..030) ────────────
        # Each setting disables the trusted-source channel for any
        # in-image install (PW.4.4 verify failure) and tampers
        # with secure defaults (PW.9.1).
        "DF-021": ["PW.4.4", "PW.9.1"],                # pip TLS bypass / http index
        "DF-022": ["PW.4.4"],                          # npm install (not npm ci)
        "DF-023": ["PO.5.1", "PW.9.1"],                # LD_PRELOAD / LD_LIBRARY_PATH
        "DF-024": ["PO.5.1", "PW.9.1"],                # npm install runs lifecycle scripts
        "DF-025": ["PS.1.1"],                          # registry token in image layer
        "DF-026": ["PW.4.4", "PW.9.1"],                # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027": ["PW.4.4", "PW.9.1"],                # PYTHONHTTPSVERIFY=0
        "DF-028": ["PW.4.4", "PW.9.1"],                # GIT_SSL_NO_VERIFY=1
        "DF-029": ["PW.4.4", "PW.9.1"],                # REQUESTS_CA_BUNDLE neutered
        "DF-030": ["PO.5.1", "PW.9.1"],                # NODE_OPTIONS --require / --inspect
        # ── OCI image manifest + attestation content ────────────
        # OCI-001..005 carry the image-side provenance metadata
        # (PS.3.2); OCI-002 add signing (PS.2.1). OCI-004/007/008
        # are integrity / pin failures (PW.4.4 verify + PS.3.2
        # provenance).
        "OCI-001":  ["PS.3.2"],                        # provenance annotations missing
        "OCI-002":  ["PS.2.1", "PS.3.2"],              # build attestation missing
        "OCI-003":  ["PS.3.2"],                        # missing image.created
        "OCI-004":  ["PW.4.4", "PS.3.2"],              # foreign-layer URL reference
        "OCI-005":  ["PS.3.2"],                        # missing image.licenses
        "OCI-007":  ["PW.4.4", "PS.3.2"],              # legacy schemaVersion 1
        "OCI-008":  ["PW.4.4", "PS.2.1"],              # weak digest algorithm
        "OCI-009":  ["PS.3.2"],                        # missing base-image annotations
        # ── SLSA / in-toto attestation content ──────────────────
        # The ATTEST-NNN family is the provenance document itself
        # (PS.2.1 integrity verification + PS.3.2 provenance data).
        "ATTEST-001": ["PS.2.1", "PS.3.2"],            # untrusted SLSA builder identity
        "ATTEST-002": ["PS.2.1", "PS.3.2"],            # source-repo claim unverifiable
        "ATTEST-003": ["PS.3.2"],                      # SBOM floating versions
        "ATTEST-004": ["PS.3.2"],                      # provenance lacks resolved materials
        "ATTEST-005": ["PS.2.1", "PS.3.2"],            # in-toto subject digest unpinned
        "ATTEST-006": ["PS.3.2"],                      # buildType missing / placeholder
        "ATTEST-007": ["PS.3.2"],                      # SBOM missing supplier
        # ── Cross-cutting dataflow / taint engine ───────────────
        # Cross-step / cross-job untrusted-data flow into privileged
        # sinks is an environment-separation failure (PO.5.1) and a
        # secure-defaults break (PW.9.1).
        "TAINT-001": ["PO.5.1", "PW.9.1"],
        "TAINT-002": ["PO.5.1", "PW.9.1"],
        "TAINT-003": ["PO.5.1", "PW.9.1"],
        "TAINT-004": ["PO.5.1", "PW.9.1"],
        "TAINT-005": ["PO.5.1", "PW.9.1"],
        "TAINT-006": ["PO.5.1", "PW.9.1"],
        "TAINT-007": ["PO.5.1", "PW.9.1"],
        "TAINT-008": ["PO.5.1", "PW.9.1"],
        "TAINT-009": ["PS.1.1"],                       # env-protected secret flows to unprotected job
        # ── SCM posture (governance via the platform REST API) ──────
        # The PS.1 family ("Protect all forms of code from
        # unauthorized access and tampering") is purpose-built for
        # SCM governance: branch protection, review gates, and
        # ruleset enforcement all evidence "store all forms of code
        # based on least-privilege and tamper-resistance". PS.2.1
        # carries integrity-verification surfaces (signed commits).
        # PW.4.x carries third-party action governance. PO.5.1
        # carries environment separation. RV.1.1 carries
        # vulnerability gathering.
        "SCM-001":  ["PS.1.1"],                        # default branch unprotected
        "SCM-002":  ["PS.1.1"],                        # required reviews missing
        "SCM-003":  ["RV.1.1"],                        # default code scanning disabled
        "SCM-004":  ["PS.1.1"],                        # secret scanning disabled
        "SCM-005":  ["PW.4.4", "RV.1.1"],              # Dependabot security updates off
        "SCM-006":  ["PS.2.1"],                        # signed commits not required
        "SCM-007":  ["PS.1.1"],                        # force-push allowed
        "SCM-008":  ["PS.1.1"],                        # required status checks missing
        "SCM-009":  ["PS.1.1"],                        # branch deletions allowed
        "SCM-010":  ["PS.1.1"],                        # admin bypass allowed
        "SCM-011":  ["PS.1.1"],                        # CODEOWNERS reviews not required
        "SCM-012":  ["PS.1.1"],                        # stale reviews not dismissed
        "SCM-013":  ["PS.1.1"],                        # conversation resolution not required
        "SCM-014":  ["PS.1.1"],                        # last-push approval not required
        "SCM-015":  ["PS.1.1"],                        # secret scanning push protection off
        "SCM-016":  ["RV.1.1"],                        # private vulnerability reporting off
        "SCM-017":  ["PS.1.1"],                        # CODEOWNERS file missing
        "SCM-018":  ["PS.1.1"],                        # PR review bypass allowed
        "SCM-019":  ["PS.1.1"],                        # push-restriction allowlist names users
        # Actions governance + environments + deploy keys
        "SCM-020":  ["PO.5.1", "PS.1.1"],              # workflow_token default write
        "SCM-021":  ["PS.1.1"],                        # Actions can approve PRs
        "SCM-022":  ["PW.4.1", "PW.4.4"],              # allowed_actions unrestricted
        "SCM-023":  ["PO.5.1"],                        # env missing reviewers
        "SCM-024":  ["PO.5.1"],                        # env branch policy missing
        "SCM-025":  ["PS.1.1"],                        # deploy keys write-enabled
        "SCM-026":  ["PO.3.2"],                        # webhook insecure / no HMAC
        "SCM-027":  ["PS.1.1"],                        # outside collaborator elevated
        "SCM-028":  ["PS.1.1"],                        # private repo allows forking
        # Ruleset enforcement
        "SCM-029":  ["PS.1.1"],                        # ruleset not enforced
        "SCM-030":  ["PS.1.1"],                        # ruleset always-bypass
        "SCM-031":  ["PS.1.1"],                        # auto-merge enabled
        "SCM-032":  ["PS.1.1"],                        # ruleset lacks PR review
        "SCM-033":  ["PS.1.1"],                        # ruleset lacks status_checks
        "SCM-034":  ["PS.1.1"],                        # ruleset allows force_push
        "SCM-035":  ["PS.1.1"],                        # ruleset allows deletion
        "SCM-036":  ["PS.2.1"],                        # ruleset lacks signed_commits
        "SCM-037":  ["PS.1.1"],                        # ruleset stale-review dismissal
        "SCM-038":  ["PS.1.1"],                        # ruleset lacks linear_history
        "SCM-039":  ["PS.1.1", "PW.6.1"],              # ruleset lacks required_workflows
        "SCM-040":  ["RV.1.1", "PS.1.1"],              # ruleset lacks code_scanning gate
        "SCM-041":  ["PO.5.1"],                        # ruleset lacks deployment-env gate
        "SCM-042":  ["PS.1.1"],                        # ruleset lacks merge queue
        "SCM-043":  ["PS.2.1"],                        # tag-ruleset lacks signed_commits
        "SCM-044":  ["PS.2.1"],                        # required_signatures bypassed for admins
        "SCM-045":  ["RV.1.1"],                        # default code scanning limited query suite
        "SCM-046":  ["RV.1.1"],                        # default code scanning paused
        "SCM-047":  ["RV.1.1"],                        # repo language not covered
        # ── Terraform / CloudFormation (IaC-native) ─────────────
        "TF-001":   ["PS.1.1"],                        # aws_iam_access_key declared as code
        "TF-002":   ["PS.1.1"],                        # hard-coded secret in resource attr
        "TF-003":   ["PO.5.1"],                        # CodeBuild VPC shares public subnet
        "CF-001":   ["PS.1.1"],                        # AWS::IAM::AccessKey declared as code
        "CF-002":   ["PS.1.1"],                        # hard-coded secret in resource property
        "CF-003":   ["PO.5.1"],                        # CodeBuild VPC shares public subnet
        # ── Kubernetes manifests (deployment payload) ───────────
        # K8s workload manifests are the build's deployment output.
        # Image-pinning → PW.4.1 + PW.4.4 (acquire/verify components);
        # privileged / runtime hardening → PO.5.1 (env separation) +
        # PW.9.1 (secure defaults); RBAC / SA → PO.5.1; secret
        # exposure → PS.1.1; network policy → PO.5.1.
        "K8S-001":  ["PW.4.1", "PW.4.4"],              # image not digest-pinned
        "K8S-002":  ["PO.5.1", "PW.9.1"],              # hostNetwork
        "K8S-003":  ["PO.5.1", "PW.9.1"],              # hostPID
        "K8S-004":  ["PO.5.1", "PW.9.1"],              # hostIPC
        "K8S-005":  ["PO.5.1", "PW.9.1"],              # privileged container
        "K8S-006":  ["PO.5.1", "PW.9.1"],              # allowPrivilegeEscalation
        "K8S-007":  ["PO.5.1", "PW.9.1"],              # runAsNonRoot missing
        "K8S-008":  ["PW.9.1"],                        # readOnlyRootFilesystem missing
        "K8S-009":  ["PO.5.1", "PW.9.1"],              # added capabilities
        "K8S-010":  ["PW.9.1"],                        # seccompProfile missing
        "K8S-011":  ["PO.5.1"],                        # default ServiceAccount
        "K8S-012":  ["PS.1.1"],                        # automountServiceAccountToken default
        "K8S-013":  ["PO.5.1", "PW.9.1"],              # hostPath volume
        "K8S-014":  ["PO.5.1", "PW.9.1"],              # sensitive hostPath
        "K8S-015":  ["PW.9.1"],                        # no memory limit
        "K8S-016":  ["PW.9.1"],                        # no CPU limit
        "K8S-017":  ["PS.1.1"],                        # credential literal in env
        "K8S-018":  ["PS.1.1"],                        # Secret data plaintext
        "K8S-019":  ["PO.5.1"],                        # default namespace
        "K8S-020":  ["PO.5.1"],                        # cluster-admin RoleBinding
        "K8S-021":  ["PO.5.1"],                        # wildcard RBAC verbs
        "K8S-022":  ["PO.5.1", "PW.9.1"],              # Service exposes SSH
        "K8S-023":  ["PW.9.1"],                        # PSA enforce label missing
        "K8S-044":  ["PW.9.1"],                        # admission webhook fail-open / unscoped mutating
        "K8S-024":  ["PO.3.3"],                        # missing readiness / liveness probes
        "K8S-025":  ["PO.5.1"],                        # system priority class
        "K8S-026":  ["PO.5.1"],                        # LB without source ranges
        "K8S-027":  ["PS.1.1", "PW.9.1"],              # Ingress without TLS
        "K8S-028":  ["PO.5.1", "PW.9.1"],              # container hostPort
        "K8S-029":  ["PO.5.1"],                        # default-SA RoleBinding
        "K8S-030":  ["PO.5.1"],                        # control-plane scheduling
        "K8S-031":  ["PW.9.1"],                        # PSA warn missing
        "K8S-032":  ["PO.5.1"],                        # NetworkPolicy default-deny missing
        "K8S-033":  ["PW.9.1"],                        # ResourceQuota / LimitRange missing
        "K8S-034":  ["PS.1.1"],                        # SA token automount default
        "K8S-035":  ["PO.5.1", "PW.9.1"],              # runAsUser: 0
        "K8S-036":  ["PW.4.1"],                        # SA imagePullSecret missing
        "K8S-037":  ["PS.1.1"],                        # ConfigMap credential
        "K8S-038":  ["PO.5.1"],                        # NetworkPolicy allow-all
        "K8S-039":  ["PO.5.1", "PW.9.1"],              # shareProcessNamespace
        "K8S-040":  ["PO.5.1", "PW.9.1"],              # procMount: Unmasked
        "K8S-041":  ["PO.5.1"],                        # Service externalIPs (MITM)
        "K8S-042":  ["PO.5.1"],                        # anonymous RoleBinding
        "K8S-043":  ["PO.5.1"],                        # Ingress wildcard host
        # S3-000 (discovery failure) — visibility gap, same precedent
        # as the other -000 family entries above.
        "S3-000":   ["PO.3.3"],
        # supply-chain posture pack
        "GHA-097":  ["PO.5.1", "PW.9.1"],              # recursive PR auto-merge loop
        "GHA-098":  ["RV.1.1"],                        # deploy without security scan gate
        "GHA-099":  ["PS.1.1"],                        # deploy env plaintext secret
        "GHA-100":  ["PW.4.4", "PS.2.1"],              # cosign verify no identity binding
        "GHA-102":  ["PO.5.1", "PW.9.1"],              # submodule checkout on PR trigger
        "GHA-103":  ["PW.6.1", "PW.9.1"],              # AI review bot on untrusted trigger
        "GHA-104":  ["PW.6.1", "PW.9.1"],              # AI agent auto-push without PR review
        "GL-036":   ["PS.1.1"],                        # secret echoed to GitLab CI log
        "GL-038":   ["PS.1.1"],                        # CI_DEBUG_TRACE dumps secrets to GitLab CI log
        "BB-032":   ["PS.1.1"],                        # secret echoed to Bitbucket log
        "ADO-031":  ["PS.1.1"],                        # secret echoed to Azure DevOps log
        "ADO-032":  ["PS.1.1"],                        # checkout persistCredentials leaks token to .git/config
        "ADO-033":  ["PW.6.1", "PW.9.1"],              # IaC apply on a PR-validated pipeline
        "CC-032":   ["PS.1.1"],                        # secret echoed to CircleCI log
        "SCM-048":  ["PO.5.1"],                        # org codespace secrets scoped to all repos
        "SCM-049":  ["PS.1.1"],                        # classic PAT where fine-grained suffices
        # GitLab-specific platform posture (SCM-050..053)
        "SCM-050":  ["PS.1.1"],                        # GitLab push rules: prevent_secrets
        "SCM-051":  ["PO.5.1", "PS.1.1"],              # GitLab push rules: committer-email check
        "SCM-052":  ["PO.5.1"],                        # GitLab MR: discussions-resolved gate
        "SCM-053":  ["PO.5.1"],                        # GitLab MR: author self-approval allowed
        # Bitbucket-specific platform posture (SCM-054..055)
        "SCM-054":  ["PO.5.1", "PS.3.1"],              # Bitbucket private repo allows public forks
        "SCM-055":  ["PO.5.1"],                        # Bitbucket no write-side branch-restriction kinds
        "NPM-012":  ["PS.1.1"],                        # publish token missing restrictions
        # ── Azure Cloud (Entra ID / Storage / Key Vault / ACR / Monitor) ──
        "ENTRA-001": ["PO.5.1"],                       # SP assigned Global Administrator
        "ENTRA-002": ["PS.1.1"],                       # app credential beyond 180 days
        "ENTRA-003": ["PS.1.1"],                       # SP uses password credential
        "AZST-001":  ["PO.5.1", "PS.1.1"],             # public blob access
        "AZST-002":  ["PW.4.4"],                       # non-HTTPS traffic
        "AZST-003":  ["PS.1.1"],                       # no CMK encryption
        "AKV-001":   ["PS.1.1", "PS.3.1"],             # soft delete not enabled
        "AKV-002":   ["PS.1.1", "PS.3.1"],             # purge protection not enabled
        "AKV-003":   ["PO.5.1", "PS.1.1"],             # network ACLs allow all
        "ACR-001":   ["PO.5.1"],                       # admin user enabled
        "ACR-002":   ["PO.5.1", "PS.1.1"],             # public network access
        "ACR-003":   ["PS.2.1", "PS.3.2"],             # content trust not enabled
        "AZMON-001": ["PO.3.3"],                       # no diagnostic setting
        "AZMON-002": ["PO.3.3"],                       # log retention < 365 days
        "AZMON-003": ["PO.3.3", "RV.1.1"],             # no alert rule
        # ── GCP (IAM / GCS / KMS / Artifact Registry / Cloud Logging) ────
        "GCIAM-001": ["PO.5.1"],                       # SA has Owner/Editor role
        "GCIAM-002": ["PS.1.1"],                       # user-managed SA key
        "GCIAM-003": ["PO.5.1"],                       # token creator without condition
        "GCS-001":   ["PO.5.1", "PS.1.1"],             # public bucket
        "GCS-002":   ["PO.5.1"],                       # no uniform access
        "GCS-003":   ["PS.3.1"],                       # versioning not enabled
        "GCKMS-001": ["PS.1.1"],                       # key rotation > 365 days
        "GCKMS-002": ["PO.5.1", "PS.1.1"],             # public KMS key access
        "GCKMS-003": ["PS.1.1"],                       # no HSM protection
        "GAR-001":   ["RV.1.1"],                       # no vulnerability scanning
        "GAR-002":   ["PO.5.1", "PS.1.1"],             # publicly readable repo
        "GAR-003":   ["PO.3.2"],                       # no cleanup policy
        "GCLOG-001": ["PO.3.3"],                       # audit logs not enabled
        "GCLOG-002": ["PO.3.3"],                       # no log sink
        "GCLOG-003": ["PO.3.3"],                       # log retention < 365 days
        # ── Azure Cloud phase-2 ──────────────────────────────────────
        "ENTRA-004": ["PO.5.1"],                       # cond access MFA
        "ENTRA-005": ["PO.5.1"],                       # ext user restrict
        "ENTRA-006": ["PO.3.3", "RV.1.1"],             # risky signin
        "AZST-004":  ["PW.4.4"],                       # min TLS
        "AZST-005":  ["PO.3.2"],                       # lifecycle
        "AZST-006":  ["PS.1.1"],                       # key rotation
        "AKV-004":   ["PS.1.1"],                       # key expiry
        "AKV-005":   ["PS.1.1"],                       # secret expiry
        "AKV-006":   ["PO.5.1"],                       # RBAC
        "ACR-004":   ["RV.1.1"],                       # defender scan
        "ACR-005":   ["PS.3.1"],                       # tag immutability
        "AZMON-004": ["PO.3.3"],                       # KV diagnostics
        "AZMON-005": ["PO.3.3"],                       # NSG flow retention
        "AZMON-006": ["PO.3.3"],                       # LAW retention
        "AZMON-007": ["PO.3.3", "RV.1.1"],             # svc health alert
        "AZNW-001":  ["PO.5.1"],                       # SSH/RDP internet (CRITICAL)
        "AZNW-002":  ["PO.3.3"],                       # flow logs
        "AZNW-003":  ["PO.5.1"],                       # WAF
        "AZNW-004":  ["PO.5.1"],                       # deny-all
        "AZNW-005":  ["PO.5.1"],                       # public IP VM
        "AZAPP-001": ["PW.4.4"],                       # HTTPS
        "AZAPP-002": ["PW.4.4"],                       # TLS
        "AZAPP-003": ["PS.1.1"],                       # managed identity
        "AZAPP-004": ["PO.5.2", "PW.9.1"],             # remote debug
        "AZAPP-005": ["PO.5.2", "PW.9.1"],             # FTP
        "AZSQL-001": ["PS.1.1"],                       # TDE CMK
        "AZSQL-002": ["PO.3.3"],                       # auditing
        "AZSQL-003": ["PO.5.1"],                       # public access
        "AZSQL-004": ["PO.5.1"],                       # AAD admin
        "AZSQL-005": ["RV.1.1"],                       # threat detect
        "AZVM-001":  ["PS.1.1"],                       # disk encrypt
        "AZVM-002":  ["PO.5.1"],                       # public IP
        "AZVM-003":  ["PO.5.1"],                       # JIT
        "AZVM-004":  ["PW.4.1", "RV.1.1"],             # OS patch
        "AZVM-005":  ["PS.1.1"],                       # managed identity
        # ── GCP phase-2 ──────────────────────────────────────────────
        "GCIAM-004": ["PO.5.1"],                       # default SA
        "GCIAM-005": ["PO.5.1"],                       # domain restrict
        "GCIAM-006": ["PS.1.1"],                       # SA key age
        "GCS-004":   ["PS.1.1"],                       # CMEK
        "GCS-005":   ["PO.3.3"],                       # access logging
        "GCLOG-004": ["PO.3.3"],                       # VPC flow logs
        "GCLOG-005": ["PO.3.3"],                       # firewall logging
        "GCLOG-006": ["PO.3.3"],                       # data access
        "GCLOG-007": ["PO.3.3"],                       # metric filter IAM
        "GCLOG-008": ["PO.3.3"],                       # metric filter firewall
        "GCLOG-009": ["PO.3.3"],                       # metric filter route
        "GCLOG-010": ["PO.3.3"],                       # metric filter SQL
        "GCLOG-011": ["PO.3.3"],                       # metric filter custom role
        "GCNET-001": ["PO.5.1"],                       # default network
        "GCNET-002": ["PO.5.1"],                       # deny-all
        "GCNET-003": ["PO.5.1"],                       # SSH/RDP (CRITICAL)
        "GCNET-004": ["PO.5.1"],                       # private access
        "GCNET-005": ["PO.5.1"],                       # Cloud NAT
        "GCCE-001":  ["PW.9.1"],                       # shielded VM
        "GCCE-002":  ["PO.5.1"],                       # OS Login
        "GCCE-003":  ["PO.5.2", "PW.9.1"],             # serial port
        "GCCE-004":  ["PO.5.1"],                       # public IP
        "GCCE-005":  ["PO.5.2", "PW.9.1"],             # project SSH keys
        "GCSQL-001": ["PO.5.1"],                       # public IP
        "GCSQL-002": ["PO.3.2"],                       # backups
        "GCSQL-003": ["PW.4.4"],                       # SSL
        "GCSQL-004": ["PO.5.1"],                       # IAM auth
        "GCSQL-005": ["PO.3.2"],                       # PITR
        "GCRUN-001": ["PO.5.1"],                       # unauth
        "GCRUN-002": ["PO.5.1"],                       # custom SA
        "GCRUN-003": ["PO.3.2"],                       # min instances
        "GCRUN-004": ["PO.5.1"],                       # VPC connector
        "GCKMS-004": ["PO.5.1"],                       # keyring IAM
        "GCKMS-005": ["PS.1.1"],                       # destroy sched
        "GCKMS-006": ["PS.1.1"],                       # imported key
        # Developer-environment auto-execution
        "DEV-001":   ["PW.6.1", "PW.9.1"],
        "DEV-006":   ["PW.6.1", "PW.9.1"],
        "DEV-002":   ["PW.6.1", "PW.9.1"],
        "DEV-003":   ["PW.6.1", "PW.9.1"],
        "DEV-004":   ["PW.4.1", "PW.4.4"],
        "DEV-005":   ["PW.6.1", "PW.9.1"],
    },
)
