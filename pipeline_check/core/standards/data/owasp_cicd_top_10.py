"""OWASP Top 10 CI/CD Security Risks (2022)."""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="owasp_cicd_top_10",
    title="OWASP Top 10 CI/CD Security Risks",
    version="2022",
    url="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
    controls={
        "CICD-SEC-1":  "Insufficient Flow Control Mechanisms",
        "CICD-SEC-2":  "Inadequate Identity and Access Management",
        "CICD-SEC-3":  "Dependency Chain Abuse",
        "CICD-SEC-4":  "Poisoned Pipeline Execution",
        "CICD-SEC-5":  "Insufficient PBAC",
        "CICD-SEC-6":  "Insufficient Credential Hygiene",
        "CICD-SEC-7":  "Insecure System Configuration",
        "CICD-SEC-8":  "Ungoverned Usage of 3rd-Party Services",
        "CICD-SEC-9":  "Improper Artifact Integrity Validation",
        "CICD-SEC-10": "Insufficient Logging and Visibility",
    },
    mappings={
        # Degraded-mode findings (API access failures).
        "CB-000":   ["CICD-SEC-10"],
        "CP-000":   ["CICD-SEC-10"],
        "CD-000":   ["CICD-SEC-10"],
        "ECR-000":  ["CICD-SEC-10"],
        "IAM-000":  ["CICD-SEC-10"],
        "PBAC-000": ["CICD-SEC-10"],
        "S3-000":   ["CICD-SEC-10"],
        # CodeBuild
        "CB-001":   ["CICD-SEC-6"],
        "CB-002":   ["CICD-SEC-7"],
        "CB-003":   ["CICD-SEC-10"],
        "CB-004":   ["CICD-SEC-7"],
        "CB-005":   ["CICD-SEC-7"],
        "CB-006":   ["CICD-SEC-6"],
        "CB-007":   ["CICD-SEC-1"],
        "CB-008":   ["CICD-SEC-4"],
        "CB-009":   ["CICD-SEC-3"],
        "CB-010":   ["CICD-SEC-4"],
        "CB-011":   ["CICD-SEC-4", "CICD-SEC-7"],
        # CodePipeline
        "CP-001":   ["CICD-SEC-1"],
        "CP-002":   ["CICD-SEC-9"],
        "CP-003":   ["CICD-SEC-4"],
        "CP-004":   ["CICD-SEC-6"],
        # CodeDeploy
        "CD-001":   ["CICD-SEC-1"],
        "CD-002":   ["CICD-SEC-1"],
        "CD-003":   ["CICD-SEC-10"],
        # ECR
        "ECR-001":  ["CICD-SEC-3"],
        "ECR-002":  ["CICD-SEC-9"],
        "ECR-003":  ["CICD-SEC-8"],
        "ECR-004":  ["CICD-SEC-7"],
        "ECR-005":  ["CICD-SEC-9"],
        # IAM
        "IAM-001":  ["CICD-SEC-2"],
        "IAM-002":  ["CICD-SEC-2"],
        "IAM-003":  ["CICD-SEC-2"],
        "IAM-004":  ["CICD-SEC-2"],
        "IAM-005":  ["CICD-SEC-2"],
        "IAM-006":  ["CICD-SEC-2"],
        "IAM-007":  ["CICD-SEC-6"],
        "IAM-008":  ["CICD-SEC-2"],
        "IAM-009":  ["CICD-SEC-2"],
        "IAM-010":  ["CICD-SEC-2"],
        # CloudTrail
        "CT-000":   ["CICD-SEC-10"],
        "CT-001":   ["CICD-SEC-10"],
        "CT-002":   ["CICD-SEC-10"],
        "CT-003":   ["CICD-SEC-10"],
        # CloudWatch Logs
        "CWL-000":  ["CICD-SEC-10"],
        "CWL-001":  ["CICD-SEC-10"],
        "CWL-002":  ["CICD-SEC-9"],
        # Secrets Manager
        "SM-000":   ["CICD-SEC-10"],
        "SM-001":   ["CICD-SEC-6"],
        "SM-002":   ["CICD-SEC-8"],
        # CodeArtifact
        "CA-000":   ["CICD-SEC-10"],
        "CA-001":   ["CICD-SEC-9"],
        "CA-002":   ["CICD-SEC-3"],
        "CA-003":   ["CICD-SEC-8"],
        "CA-004":   ["CICD-SEC-2"],
        # CodeCommit (CCM- prefix, avoids CC-* collision with CircleCI)
        "CCM-000":  ["CICD-SEC-10"],
        "CCM-001":  ["CICD-SEC-1"],
        "CCM-002":  ["CICD-SEC-9"],
        "CCM-003":  ["CICD-SEC-8"],
        # Lambda
        "LMB-000":  ["CICD-SEC-10"],
        "LMB-001":  ["CICD-SEC-9"],
        "LMB-002":  ["CICD-SEC-8"],
        "LMB-003":  ["CICD-SEC-6"],
        "LMB-004":  ["CICD-SEC-8"],
        # KMS
        "KMS-000":  ["CICD-SEC-10"],
        "KMS-001":  ["CICD-SEC-6"],
        "KMS-002":  ["CICD-SEC-2"],
        # SSM Parameter Store
        "SSM-000":  ["CICD-SEC-10"],
        "SSM-001":  ["CICD-SEC-6"],
        "SSM-002":  ["CICD-SEC-9"],
        # Phase-3 deeper detections
        "CP-005":   ["CICD-SEC-1"],
        "CP-007":   ["CICD-SEC-4"],
        "PBAC-003": ["CICD-SEC-5"],
        "PBAC-005": ["CICD-SEC-5"],
        "ECR-006":  ["CICD-SEC-3"],
        "ECR-007":  ["CICD-SEC-3"],
        "SIGN-001": ["CICD-SEC-9"],
        "SIGN-002": ["CICD-SEC-9"],
        "EB-000":   ["CICD-SEC-10"],
        "EB-001":   ["CICD-SEC-10"],
        "EB-002":   ["CICD-SEC-8"],
        "CW-001":   ["CICD-SEC-10"],
        # Terraform-native (no AWS runtime analogue)
        "TF-001":   ["CICD-SEC-6"],
        "TF-002":   ["CICD-SEC-6"],
        "TF-003":   ["CICD-SEC-7"],
        # CloudFormation-native (no AWS runtime analogue)
        "CF-001":   ["CICD-SEC-6"],
        "CF-002":   ["CICD-SEC-6"],
        "CF-003":   ["CICD-SEC-7"],
        # PBAC
        "PBAC-001": ["CICD-SEC-5"],
        "PBAC-002": ["CICD-SEC-5"],
        # S3
        "S3-001":   ["CICD-SEC-9"],
        "S3-002":   ["CICD-SEC-9"],
        "S3-003":   ["CICD-SEC-9"],
        "S3-004":   ["CICD-SEC-10"],
        "S3-005":   ["CICD-SEC-9"],
        # GitHub Actions
        "GHA-001":  ["CICD-SEC-3", "CICD-SEC-8"],
        "GHA-110": ["CICD-SEC-3", "CICD-SEC-5"],  # CI env disables Go module verification
        "GHA-002":  ["CICD-SEC-4"],
        "RUN-001":  ["CICD-SEC-4"],
        "RUN-002":  ["CICD-SEC-4"],
        "GLRUN-001": ["CICD-SEC-4"],  # gitlab forensics: merge-request pipeline executed
        "GLRUN-002": ["CICD-SEC-4"],  # gitlab forensics: fork merge-request pipeline executed
        "GLRUN-003": ["CICD-SEC-4"],  # gitlab forensics: secret leaked in fork pipeline trace
        "GLRUN-004": ["CICD-SEC-4"],  # gitlab forensics: fork pipeline minted a cloud OIDC token
        "GLRUN-005": ["CICD-SEC-4"],  # gitlab forensics: fork pipeline ran on a self-managed runner
        "RUN-003":  ["CICD-SEC-4"],
        "RUN-004":  ["CICD-SEC-4"],
        "RUN-005":  ["CICD-SEC-4"],
        "RUN-006":  ["CICD-SEC-3", "CICD-SEC-4"],  # forensics: known-compromised action executed
        "RUN-007":  ["CICD-SEC-3", "CICD-SEC-4"],  # forensics: unpinned third-party action ran with secrets
        "GHA-003":  ["CICD-SEC-4"],
        "GHA-119":  ["CICD-SEC-4"],# untrusted context into an agentic AI CLI
        "GHA-120":  ["CICD-SEC-4"],# trust_remote_code model load = code exec
        "GHA-122":  ["CICD-SEC-4"],# unsafe pickle deser of fetched artifact = code exec
        "GHA-121":  ["CICD-SEC-3"],# model pulled without a pinned revision
        "GHA-117":  ["CICD-SEC-4"],# IaC apply on untrusted PR trigger
        "GHA-118":  ["CICD-SEC-4"],# untrusted content into $GITHUB_ENV / $GITHUB_PATH
        "GHA-004":  ["CICD-SEC-5"],
        "GHA-005":  ["CICD-SEC-6"],
        "GHA-006":  ["CICD-SEC-9"],
        "GHA-007":  ["CICD-SEC-9"],
        "GHA-008":  ["CICD-SEC-6"],
        "GHA-009":  ["CICD-SEC-4"],
        "GHA-010":  ["CICD-SEC-4"],
        "GHA-011":  ["CICD-SEC-4"],
        "GHA-012":  ["CICD-SEC-7"],
        "GHA-105":  ["CICD-SEC-4", "CICD-SEC-7"],        # self-hosted runner on PR trigger
        "GHA-013":  ["CICD-SEC-4"],
        "GHA-014":  ["CICD-SEC-1"],
        "GHA-123":  ["CICD-SEC-1"],# agentic CLI output lands without review
        "GHA-015":  ["CICD-SEC-7"],
        "GHA-016":  ["CICD-SEC-3"],
        "GHA-017":  ["CICD-SEC-7"],
        "GHA-018":  ["CICD-SEC-3"],
        "GHA-019":  ["CICD-SEC-6"],
        "GHA-020":  ["CICD-SEC-3"],
        "GHA-021":  ["CICD-SEC-3"],
        "GHA-022":  ["CICD-SEC-3"],
        "GHA-023":  ["CICD-SEC-3"],
        "GHA-024":  ["CICD-SEC-9"],
        "GHA-025":  ["CICD-SEC-3", "CICD-SEC-8"],
        "GHA-026":  ["CICD-SEC-7"],
        "GHA-027":  ["CICD-SEC-4", "CICD-SEC-7"],
        "GHA-028":  ["CICD-SEC-4"],
        "GHA-029":  ["CICD-SEC-3"],
        "GHA-030":  ["CICD-SEC-2"],   # OIDC without environment gate
        "GHA-031":  ["CICD-SEC-4"],   # retired set-output / save-state
        "GHA-032":  ["CICD-SEC-4"],   # local-script invocation on untrusted trigger
        "GHA-033":  ["CICD-SEC-6"],   # secret echoed in run:
        "GHA-034":  ["CICD-SEC-2", "CICD-SEC-6"],  # secrets: inherit
        "GHA-035":  ["CICD-SEC-4"],   # github-script injection
        "GHA-036":  ["CICD-SEC-7"],   # runs-on interpolates untrusted context
        "GHA-037":  ["CICD-SEC-6", "CICD-SEC-4"],  # checkout persists token (Artipacked)
        "GHA-038":  ["CICD-SEC-4", "CICD-SEC-7"],  # ACTIONS_ALLOW_UNSECURE_COMMANDS
        "GHA-039":  ["CICD-SEC-6"],   # services / container creds literal
        "GHA-040":  ["CICD-SEC-3", "CICD-SEC-8"],   # known-compromised action ref
        "GHA-041":  ["CICD-SEC-3", "CICD-SEC-8"],   # single-maintainer action
        "GHA-042":  ["CICD-SEC-3", "CICD-SEC-8"],   # very-young action repo
        "GHA-043":  ["CICD-SEC-3", "CICD-SEC-5", "CICD-SEC-8"],  # low-star + sensitive perms
        "GHA-044":  ["CICD-SEC-4"],   # build-tool PPE on untrusted trigger
        "GHA-045":  ["CICD-SEC-4"],   # caller-ref input drives checkout
        "GHA-046":  ["CICD-SEC-4"],   # manual PR-head fetch on untrusted trigger
        "GHA-047":  ["CICD-SEC-3", "CICD-SEC-8"],  # fresh-ref cooldown
        "GHA-048":  ["CICD-SEC-1", "CICD-SEC-4"],  # workflow self-mutation
        "GHA-049":  ["CICD-SEC-1", "CICD-SEC-4"],  # cross-repo push from CI
        "GHA-050":  ["CICD-SEC-2", "CICD-SEC-6"],  # publish without OIDC
        "GHA-051":  ["CICD-SEC-3", "CICD-SEC-8"],  # services/container image unpinned
        "GHA-052":  ["CICD-SEC-3", "CICD-SEC-4"],  # cache key untrusted-input poisoning
        "GHA-053":  ["CICD-SEC-4"],                # if: predicate untrusted-context
        "GHA-054":  ["CICD-SEC-6"],                # checkout ssh-key persists
        "GHA-055":  ["CICD-SEC-6"],                # reusable outputs leak secret
        "GHA-056":  ["CICD-SEC-1", "CICD-SEC-4"],  # known supply-chain worm IOC strings
        "GHA-057":  ["CICD-SEC-4", "CICD-SEC-6"],  # secret-scanner output piped to egress
        "GHA-058":  ["CICD-SEC-4", "CICD-SEC-7"],  # agentic CLI with permission-bypass flags
        "GHA-059":  ["CICD-SEC-3"],                # npm install without audit signatures
        "GHA-060":  ["CICD-SEC-3"],                # pip install without --require-hashes
        "GHA-061":  ["CICD-SEC-5", "CICD-SEC-2"],  # App token minted without permissions filter
        "GHA-106":  ["CICD-SEC-5", "CICD-SEC-2"],  # AI agent with write-scoped token
        "GHA-111":  ["CICD-SEC-5", "CICD-SEC-4"],  # AI agent edits IaC applied in the same job
        "GHA-112":  ["CICD-SEC-1", "CICD-SEC-7"],  # self-hosted deploy with no environment gate
        "GHA-113":  ["CICD-SEC-2", "CICD-SEC-1"],  # OIDC trusted-publish w/o env gate
        "GHA-114": ["CICD-SEC-1", "CICD-SEC-2"],  # publish workflow on an unrestricted push trigger
        "GHA-115":  ["CICD-SEC-5"],                # id-token granted workflow-wide, not job-scoped
        "GHA-116":  ["CICD-SEC-6"],                # bulk secrets serialization
        "GHA-107":  ["CICD-SEC-7", "CICD-SEC-10"],  # harden-runner in audit mode (egress not blocked)
        "GHA-108":  ["CICD-SEC-7", "CICD-SEC-10"],  # no runtime egress control on OIDC/deploy workflow
        "GHA-109":  ["CICD-SEC-7", "CICD-SEC-10"],  # harden-runner not the first step
        "GHA-062":  ["CICD-SEC-2", "CICD-SEC-7"],  # OIDC trust subject in sibling IaC is overly broad
        "GHA-063":  ["CICD-SEC-1", "CICD-SEC-4"],  # spoofable bot-actor if-predicate
        "GHA-064":  ["CICD-SEC-1", "CICD-SEC-4"],  # unsound contains() with comma-string operand
        "GHA-065":  ["CICD-SEC-4", "CICD-SEC-6"],  # zero-width / bidi unicode in workflow body
        "GHA-066":  ["CICD-SEC-6", "CICD-SEC-9"],  # upload-artifact wildcard sweeps workspace
        "GHA-067":  ["CICD-SEC-6"],                # cache step publishes credential-shaped paths
        "GHA-068":  ["CICD-SEC-7"],                # runs-on targets a deprecated hosted runner
        "GHA-069":  ["CICD-SEC-5"],                # orphan id-token: write scope
        "GHA-070":  ["CICD-SEC-3", "CICD-SEC-7"],  # ssh-keyscan / host-key check TOFU
        "GHA-071":  ["CICD-SEC-4"],                # powershell on Linux / macOS step
        "GHA-072":  ["CICD-SEC-6", "CICD-SEC-5"],  # secret env: at wider scope than consumer
        "GHA-073":  ["CICD-SEC-6"],                # unused workflow_call.secrets declaration
        "GHA-086":  ["CICD-SEC-1", "CICD-SEC-5"],  # wildcard branch trigger + environment binding
        "GHA-087":  ["CICD-SEC-10", "CICD-SEC-6"],  # derived-value of secret printed to log
        "GHA-088":  ["CICD-SEC-3"],                # typosquat uses: near-edit of top action
        "GHA-089":  ["CICD-SEC-3"],                # archived upstream repo
        "GHA-090":  ["CICD-SEC-3", "CICD-SEC-8"],  # impostor-commit: SHA absent from repo
        "GHA-091":  ["CICD-SEC-3", "CICD-SEC-8"],  # repojacking: action upstream missing
        "GHA-092":  ["CICD-SEC-1", "CICD-SEC-7"],  # TOCTOU PR head SHA force-push race
        "GHA-093":  ["CICD-SEC-10", "CICD-SEC-6"], # LOTP indicators (workflow-command abuse)
        "GHA-094":  ["CICD-SEC-3"],                # stale-action-refs: SHA = branch tip
        "GHA-095":  ["CICD-SEC-3", "CICD-SEC-8"],  # ref-version-mismatch: SHA vs # vX.Y.Z
        "GHA-096":  ["CICD-SEC-3", "CICD-SEC-8"],  # known-vulnerable action ref (GHSA)
        # GitLab CI
        "GL-001":   ["CICD-SEC-3"],
        "GL-037": ["CICD-SEC-3", "CICD-SEC-5"],  # CI env disables Go module verification
        "GL-002":   ["CICD-SEC-4"],
        "GL-045":   ["CICD-SEC-4"],   # trust_remote_code model load = code exec
        "GL-046":   ["CICD-SEC-3"],   # model pulled without a pinned revision
        "GL-047":   ["CICD-SEC-4"],   # unsafe pickle deser of fetched artifact = code exec
        "GL-048":   ["CICD-SEC-4"],   # untrusted MR context into agentic CLI = prompt injection
        "GL-049":   ["CICD-SEC-1"],   # agentic CLI output lands without review
        "GL-003":   ["CICD-SEC-6"],
        "GL-004":   ["CICD-SEC-1"],
        "GL-044":   ["CICD-SEC-1"],   # auto production deploy on an MR pipeline
        "GL-005":   ["CICD-SEC-3"],
        "GL-042":   ["CICD-SEC-3"],   # include: component unpinned
        "GL-006":   ["CICD-SEC-9"],
        "GL-007":   ["CICD-SEC-9"],
        "GL-008":   ["CICD-SEC-6"],
        "DEV-008":   ["CICD-SEC-6"],   # literal secret in a devenv config
        "GL-009":   ["CICD-SEC-3"],
        "GL-010":   ["CICD-SEC-4"],
        "GL-011":   ["CICD-SEC-4"],
        "GL-012":   ["CICD-SEC-4"],
        "GL-013":   ["CICD-SEC-6"],
        "GL-014":   ["CICD-SEC-7"],
        "GL-015":   ["CICD-SEC-7"],
        "GL-016":   ["CICD-SEC-3"],
        "GL-017":   ["CICD-SEC-7"],
        "GL-039":   ["CICD-SEC-7"],# dind daemon TLS disabled / exposed on 2375
        "GL-018":   ["CICD-SEC-3"],
        "GL-019":   ["CICD-SEC-3"],
        "GL-020":   ["CICD-SEC-6"],
        "GL-021":   ["CICD-SEC-3"],
        "GL-022":   ["CICD-SEC-3"],
        "GL-023":   ["CICD-SEC-3"],
        "GL-024":   ["CICD-SEC-9"],
        "GL-025":   ["CICD-SEC-4", "CICD-SEC-7"],
        "GL-026":   ["CICD-SEC-4"],
        "GL-027":   ["CICD-SEC-3"],
        "GL-028":   ["CICD-SEC-3"],
        "GL-029":   ["CICD-SEC-1"],
        "GL-030":   ["CICD-SEC-3"],
        "GL-031":   ["CICD-SEC-2"],   # id_tokens missing audience pin / env binding
        "GL-040":   ["CICD-SEC-2"],   # CI_JOB_TOKEN used for cross-project access
        "GL-041":   ["CICD-SEC-4"],   # IaC apply on an untrusted MR trigger
        "GL-050":   ["CICD-SEC-2", "CICD-SEC-6"],  # publish job long-lived registry token (GHA-050 analog)
        "GL-043":   ["CICD-SEC-7"],   # native security scanner disabled
        "BB-033":   ["CICD-SEC-4"],   # IaC apply on a pull-request pipeline
        "BB-034":   ["CICD-SEC-1"],   # production deploy on a pull-request pipeline
        "GL-032":   ["CICD-SEC-7"],   # tags interpolates untrusted CI variable
        "GL-033":   ["CICD-SEC-4", "CICD-SEC-1"],  # global before_script taint
        "GL-034":   ["CICD-SEC-3"],                # npm install without audit signatures
        "GL-035":   ["CICD-SEC-3"],                # pip install without --require-hashes
        # Bitbucket Pipelines
        "BB-001":   ["CICD-SEC-3", "CICD-SEC-8"],
        "BB-002":   ["CICD-SEC-4"],
        "BB-035":   ["CICD-SEC-4"],   # trust_remote_code model load = code exec
        "BB-036":   ["CICD-SEC-4"],   # untrusted PR context into agentic CLI = prompt injection
        "BB-037":   ["CICD-SEC-4"],   # unsafe pickle deser of fetched artifact = code exec
        "BB-038":   ["CICD-SEC-3"],   # model pulled without a pinned revision
        "BB-039":   ["CICD-SEC-1"],   # agentic CLI output lands without review
        "JF-038":   ["CICD-SEC-1"],   # agentic CLI output lands without review
        "JF-039":   ["CICD-SEC-4"],   # trust_remote_code model load = code exec
        "JF-040":   ["CICD-SEC-3"],   # model pulled without a pinned revision
        "JF-041":   ["CICD-SEC-4"],   # unsafe pickle deser of fetched artifact = code exec
        "BB-003":   ["CICD-SEC-6"],
        "BB-004":   ["CICD-SEC-1"],
        "BB-005":   ["CICD-SEC-7"],
        "BB-006":   ["CICD-SEC-9"],
        "BB-007":   ["CICD-SEC-9"],
        "BB-008":   ["CICD-SEC-6"],
        "BB-009":   ["CICD-SEC-3"],
        "BB-010":   ["CICD-SEC-4"],
        "BB-011":   ["CICD-SEC-6"],
        "BB-012":   ["CICD-SEC-3"],
        "BB-013":   ["CICD-SEC-7"],
        "BB-014":   ["CICD-SEC-3"],
        "BB-015":   ["CICD-SEC-3"],
        "BB-016":   ["CICD-SEC-7"],
        "BB-017":   ["CICD-SEC-6"],
        "BB-018":   ["CICD-SEC-4"],
        "BB-019":   ["CICD-SEC-6"],
        "BB-020":   ["CICD-SEC-7"],
        "BB-021":   ["CICD-SEC-3"],
        "BB-022":   ["CICD-SEC-3"],
        "BB-023":   ["CICD-SEC-3"],
        "BB-024":   ["CICD-SEC-9"],
        "BB-025":   ["CICD-SEC-4", "CICD-SEC-7"],
        "BB-026":   ["CICD-SEC-4"],
        "BB-027":   ["CICD-SEC-3"],
        "BB-028":   ["CICD-SEC-2"],   # OIDC without deployment-gated environment
        "BB-029":   ["CICD-SEC-3"],   # step+service image pinning
        "BB-030":   ["CICD-SEC-3"],   # npm install without audit signatures
        "BB-031":   ["CICD-SEC-3"],   # pip install without --require-hashes
        # Azure DevOps Pipelines
        "ADO-001":  ["CICD-SEC-3", "CICD-SEC-8"],
        "ADO-002":  ["CICD-SEC-4"],
        "ADO-034":  ["CICD-SEC-4"],   # trust_remote_code model load = code exec
        "ADO-035":  ["CICD-SEC-4"],   # untrusted PR context into agentic CLI = prompt injection
        "ADO-036":  ["CICD-SEC-4"],   # unsafe pickle deser of fetched artifact = code exec
        "ADO-037":  ["CICD-SEC-3"],   # model pulled without a pinned revision
        "ADO-038":  ["CICD-SEC-1"],   # agentic CLI output lands without review
        "ADO-003":  ["CICD-SEC-6"],
        "ADO-004":  ["CICD-SEC-1"],
        "ADO-005":  ["CICD-SEC-3"],
        "ADO-006":  ["CICD-SEC-9"],
        "ADO-007":  ["CICD-SEC-9"],
        "ADO-008":  ["CICD-SEC-6"],
        "ADO-009":  ["CICD-SEC-3"],
        "ADO-010":  ["CICD-SEC-4"],
        "ADO-011":  ["CICD-SEC-4"],
        "ADO-012":  ["CICD-SEC-4"],
        "ADO-013":  ["CICD-SEC-7"],
        "ADO-014":  ["CICD-SEC-6"],
        "ADO-015":  ["CICD-SEC-7"],
        "ADO-016":  ["CICD-SEC-3"],
        "ADO-017":  ["CICD-SEC-7"],
        "ADO-018":  ["CICD-SEC-3"],
        "ADO-019":  ["CICD-SEC-4"],
        "ADO-020":  ["CICD-SEC-3"],
        "ADO-021":  ["CICD-SEC-3"],
        "ADO-022":  ["CICD-SEC-3"],
        "ADO-023":  ["CICD-SEC-3"],
        "ADO-024":  ["CICD-SEC-9"],
        "ADO-025":  ["CICD-SEC-3"],
        "ADO-026":  ["CICD-SEC-4", "CICD-SEC-7"],
        "ADO-027":  ["CICD-SEC-4"],
        "ADO-028":  ["CICD-SEC-3"],
        "ADO-029":  ["CICD-SEC-2"],   # service-connection job without env gate
        "ADO-030":  ["CICD-SEC-7"],   # pool interpolates attacker-controllable value
        # Jenkins
        "JF-001":   ["CICD-SEC-3"],
        "JF-002":   ["CICD-SEC-4"],
        "JF-037":   ["CICD-SEC-4"],   # agentic CLI ingests untrusted context (prompt injection)
        "JF-003":   ["CICD-SEC-5"],
        "JF-004":   ["CICD-SEC-6"],
        "JF-005":   ["CICD-SEC-1"],
        "JF-006":   ["CICD-SEC-9"],
        "JF-007":   ["CICD-SEC-9"],
        "JF-008":   ["CICD-SEC-6"],
        "JF-009":   ["CICD-SEC-3"],
        "JF-010":   ["CICD-SEC-6"],
        "JF-011":   ["CICD-SEC-10"],
        "JF-012":   ["CICD-SEC-3"],
        "JF-013":   ["CICD-SEC-4"],
        "JF-014":   ["CICD-SEC-7"],
        "JF-015":   ["CICD-SEC-7"],
        "JF-016":   ["CICD-SEC-3"],
        "JF-017":   ["CICD-SEC-7"],
        "JF-018":   ["CICD-SEC-3"],
        "JF-019":   ["CICD-SEC-4"],
        "JF-020":   ["CICD-SEC-3"],
        "JF-021":   ["CICD-SEC-3"],
        "JF-022":   ["CICD-SEC-3"],
        "JF-023":   ["CICD-SEC-3"],
        "JF-024":   ["CICD-SEC-1"],
        "JF-025":   ["CICD-SEC-7"],
        "JF-026":   ["CICD-SEC-4"],
        "JF-027":   ["CICD-SEC-9"],
        "JF-028":   ["CICD-SEC-9"],
        "JF-029":   ["CICD-SEC-4", "CICD-SEC-7"],
        "JF-030":   ["CICD-SEC-4"],
        "JF-031":   ["CICD-SEC-3"],
        "JF-032":   ["CICD-SEC-7"],   # agent label interpolates untrusted ref
        "JF-033":   ["CICD-SEC-6"],   # withCredentials leaked via Groovy ${} in sh
        "JF-034":   ["CICD-SEC-6"],   # password() build parameter declared
        "JF-035":   ["CICD-SEC-3"],   # httpRequest ignoreSslErrors: true
        "JF-036":   ["CICD-SEC-4"],   # sh body interpolates params.* (injection)
        # CircleCI
        "CC-001":   ["CICD-SEC-3", "CICD-SEC-8"],
        "CC-033": ["CICD-SEC-3", "CICD-SEC-5"],  # CI env disables Go module verification
        "CC-002":   ["CICD-SEC-4"],
        "CC-003":   ["CICD-SEC-3"],
        "CC-004":   ["CICD-SEC-6"],
        "CC-005":   ["CICD-SEC-6"],
        "CC-006":   ["CICD-SEC-9"],
        "CC-007":   ["CICD-SEC-9"],
        "CC-008":   ["CICD-SEC-6"],
        "CC-009":   ["CICD-SEC-1"],
        "CC-010":   ["CICD-SEC-7"],
        "CC-011":   ["CICD-SEC-10"],
        "CC-012":   ["CICD-SEC-4"],
        "CC-013":   ["CICD-SEC-1"],
        "CC-014":   ["CICD-SEC-5"],
        "CC-015":   ["CICD-SEC-7"],
        "CC-016":   ["CICD-SEC-3"],
        "CC-017":   ["CICD-SEC-7"],
        "CC-018":   ["CICD-SEC-3"],
        "CC-019":   ["CICD-SEC-6"],
        "CC-020":   ["CICD-SEC-3"],
        "CC-021":   ["CICD-SEC-3"],
        "CC-022":   ["CICD-SEC-3"],
        "CC-023":   ["CICD-SEC-3"],
        "CC-024":   ["CICD-SEC-9"],
        "CC-025":   ["CICD-SEC-4"],
        "CC-026":   ["CICD-SEC-4", "CICD-SEC-7"],
        "CC-027":   ["CICD-SEC-4"],
        "CC-028":   ["CICD-SEC-3"],
        "CC-029":   ["CICD-SEC-3"],
        "CC-030":   ["CICD-SEC-6"],
        "CC-031":   ["CICD-SEC-2"],   # OIDC role assumption without branch / approval gate
        # Google Cloud Build
        "GCB-001":  ["CICD-SEC-3"],
        "GCB-002":  ["CICD-SEC-2"],
        "GCB-003":  ["CICD-SEC-6"],
        "GCB-004":  ["CICD-SEC-4"],
        "GCB-005":  ["CICD-SEC-7"],
        "GCB-006":  ["CICD-SEC-4"],
        "GCB-007":  ["CICD-SEC-6"],
        "GCB-008":  ["CICD-SEC-3"],
        "GCB-009":  ["CICD-SEC-9"],
        "GCB-010":  ["CICD-SEC-3"],   # remote script via curl-pipe
        "GCB-011":  ["CICD-SEC-3"],   # TLS bypass
        "GCB-012":  ["CICD-SEC-6"],   # literal secret in YAML
        "GCB-013":  ["CICD-SEC-3"],   # package source integrity
        "GCB-014":  ["CICD-SEC-10"],  # logging disabled
        "GCB-015":  ["CICD-SEC-9"],   # no SBOM
        "GCB-016":  ["CICD-SEC-4", "CICD-SEC-7"],   # dir path escape
        "GCB-017":  ["CICD-SEC-3", "CICD-SEC-9", "CICD-SEC-10"],  # no SLSA provenance
        "GCB-018":  ["CICD-SEC-6"],   # legacy KMS secrets block
        "GCB-019":  ["CICD-SEC-4"],   # shell entrypoint + user substitution
        "GCB-020":  ["CICD-SEC-2"],   # default Cloud Build SA email
        "GCB-021":  ["CICD-SEC-7"],   # no private worker pool
        "GCB-022":  ["CICD-SEC-4"],   # substitutionOption ALLOW_LOOSE
        "GCB-023":  ["CICD-SEC-4"],   # undeclared user substitution
        "GCB-024":  ["CICD-SEC-9"],   # images: missing despite docker push
        "GCB-025":  ["CICD-SEC-10"],  # tags: empty (audit/discoverability)
        "GCB-026":  ["CICD-SEC-4"],   # waitFor references unknown id
        "GCB-027":  ["CICD-SEC-4", "CICD-SEC-7"],  # malicious-activity indicators
        # Kubernetes manifests
        "K8S-001":  ["CICD-SEC-3"],
        "K8S-002":  ["CICD-SEC-7"],
        "K8S-003":  ["CICD-SEC-7"],
        "K8S-004":  ["CICD-SEC-7"],
        "K8S-005":  ["CICD-SEC-7"],
        "K8S-006":  ["CICD-SEC-7"],
        "K8S-007":  ["CICD-SEC-7"],
        "K8S-008":  ["CICD-SEC-7"],
        "K8S-009":  ["CICD-SEC-7"],
        "K8S-010":  ["CICD-SEC-7"],
        "K8S-011":  ["CICD-SEC-2"],
        "K8S-012":  ["CICD-SEC-2", "CICD-SEC-6"],
        "K8S-013":  ["CICD-SEC-7"],
        "K8S-014":  ["CICD-SEC-7"],
        "K8S-015":  ["CICD-SEC-7"],
        "K8S-016":  ["CICD-SEC-7"],
        "K8S-017":  ["CICD-SEC-6"],
        "K8S-018":  ["CICD-SEC-6"],
        "K8S-019":  ["CICD-SEC-2"],
        "K8S-020":  ["CICD-SEC-2", "CICD-SEC-5"],
        "K8S-021":  ["CICD-SEC-2", "CICD-SEC-5"],
        "K8S-022":  ["CICD-SEC-7"],
        "K8S-023":  ["CICD-SEC-7"],   # PSA enforce label missing
        "K8S-044":  ["CICD-SEC-7"],   # admission webhook fail-open / unscoped mutating
        "K8S-024":  ["CICD-SEC-7", "CICD-SEC-10"],  # missing health probes
        "K8S-025":  ["CICD-SEC-2", "CICD-SEC-5", "CICD-SEC-7"],  # system-* priority class
        "K8S-026":  ["CICD-SEC-7"],   # LB without source ranges
        "K8S-027":  ["CICD-SEC-7"],   # Ingress without TLS
        "K8S-028":  ["CICD-SEC-7"],   # container hostPort
        "K8S-029":  ["CICD-SEC-2", "CICD-SEC-5"],  # default-SA binding
        "K8S-030":  ["CICD-SEC-7"],   # control-plane scheduling
        "K8S-031":  ["CICD-SEC-7"],   # PSA warn label missing
        "K8S-032":  ["CICD-SEC-7"],   # NetworkPolicy default-deny missing
        "K8S-033":  ["CICD-SEC-7"],   # ResourceQuota / LimitRange missing
        "K8S-034":  ["CICD-SEC-2"],   # ServiceAccount automount default
        "K8S-035":  ["CICD-SEC-7"],   # container runAsUser: 0
        "K8S-036":  ["CICD-SEC-3"],   # SA imagePullSecret missing
        "K8S-037":  ["CICD-SEC-6"],   # ConfigMap credential literal
        "K8S-038":  ["CICD-SEC-7"],   # NetworkPolicy allow-all
        "K8S-039":  ["CICD-SEC-7"],   # shareProcessNamespace: true
        "K8S-040":  ["CICD-SEC-7"],   # procMount: Unmasked
        "K8S-041":  ["CICD-SEC-7"],   # Service externalIPs (CVE-2020-8554)
        "K8S-042":  ["CICD-SEC-2", "CICD-SEC-5"],  # anonymous RoleBinding
        "K8S-043":  ["CICD-SEC-7"],   # Ingress wildcard / missing host
        # Helm chart-supply-chain
        "HELM-001": ["CICD-SEC-3"],   # legacy apiVersion: v1
        "HELM-002": ["CICD-SEC-3"],   # Chart.lock missing digests
        "HELM-003": ["CICD-SEC-3"],   # non-HTTPS dep repository
        "HELM-004": ["CICD-SEC-3"],   # dep version not exact-pinned
        "HELM-005": ["CICD-SEC-3"],   # maintainers chain-of-custody
        "HELM-006": ["CICD-SEC-3"],   # kubeVersion compat range
        "HELM-007": ["CICD-SEC-3"],   # description empty
        "HELM-008": ["CICD-SEC-3"],   # Chart.lock stale > 90 days
        "HELM-009": ["CICD-SEC-3"],   # home / sources non-HTTPS
        "HELM-010": ["CICD-SEC-3"],   # appVersion empty
        # ── Helm extended pack (HELM-011..014) ──
        "HELM-011": ["CICD-SEC-6", "CICD-SEC-10"], # dependency URL embedded credentials
        "HELM-012": ["CICD-SEC-3"],                 # deprecated without successor
        "HELM-013": ["CICD-SEC-3"],                 # invalid chart type
        "HELM-014": ["CICD-SEC-3", "CICD-SEC-7"],  # known-compromised dependency
        "HELM-015": ["CICD-SEC-3"],  # oci:// dependency not digest-pinned
        "HELM-016": ["CICD-SEC-6"],  # default secret in values.yaml
        "HELM-017": ["CICD-SEC-4"],  # tpl of an untrusted .Values value
        # Dockerfile
        "DF-001":   ["CICD-SEC-3"],   # FROM not digest-pinned
        "MODEL-001": ["CICD-SEC-3"],   # unpinned base model
        "MODEL-002": ["CICD-SEC-3"],   # base model from a third-party hub
        "MODEL-003": ["CICD-SEC-3"],   # local unverified weights blob
        "MODEL-004": ["CICD-SEC-3"],   # remote LoRA adapter
        "MODEL-005": ["CICD-SEC-3"],   # config auto_map = custom loader code
        "DF-031":   ["CICD-SEC-3"],   # COPY --from external image not digest-pinned
        "DF-002":   ["CICD-SEC-7"],   # no USER
        "DF-003":   ["CICD-SEC-3", "CICD-SEC-9"],   # ADD URL no checksum
        "DF-004":   ["CICD-SEC-3"],   # curl-pipe in RUN
        "DF-005":   ["CICD-SEC-4"],   # shell-eval idiom
        "DF-006":   ["CICD-SEC-6"],   # secret in ENV/ARG
        "DF-007":   ["CICD-SEC-10"],  # no HEALTHCHECK
        "DF-008":   ["CICD-SEC-7"],   # docker --privileged in RUN
        "DF-009":   ["CICD-SEC-3"],   # ADD where COPY suffices
        "DF-010":   ["CICD-SEC-3"],   # apt-get dist-upgrade
        "DF-011":   ["CICD-SEC-7"],   # apt cache not cleaned
        "DF-012":   ["CICD-SEC-7"],   # sudo in RUN
        "DF-013":   ["CICD-SEC-7"],   # EXPOSE 22 / remote-access port
        "DF-014":   ["CICD-SEC-7"],   # WORKDIR system path
        "DF-015":   ["CICD-SEC-7"],   # chmod 777 / world-writable
        "DF-016":   ["CICD-SEC-3", "CICD-SEC-9", "CICD-SEC-10"],   # missing OCI provenance labels
        "DF-017":   ["CICD-SEC-7"],   # ENV PATH prepends a writable dir
        "DF-018":   ["CICD-SEC-7"],   # RUN chown rewrites a system path
        "DF-019":   ["CICD-SEC-6"],   # COPY/ADD credential-shaped file
        "DF-020":   ["CICD-SEC-6"],   # ARG credential-shaped name
        "DF-021":   ["CICD-SEC-3"],   # pip install TLS bypass / http index
        "DF-022":   ["CICD-SEC-3"],   # npm install (not npm ci)
        "DF-023":   ["CICD-SEC-7"],   # ENV LD_PRELOAD / LD_LIBRARY_PATH
        "DF-024":   ["CICD-SEC-3", "CICD-SEC-7"],  # npm install runs lifecycle scripts
        "DF-025":   ["CICD-SEC-6", "CICD-SEC-3"],  # registry token in image layer
        "DF-026":   ["CICD-SEC-3", "CICD-SEC-7"],  # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027":   ["CICD-SEC-3", "CICD-SEC-7"],  # PYTHONHTTPSVERIFY=0
        "DF-028":   ["CICD-SEC-3", "CICD-SEC-7"],  # GIT_SSL_NO_VERIFY=1
        "DF-029":   ["CICD-SEC-3", "CICD-SEC-7"],  # REQUESTS_CA_BUNDLE neutered
        "DF-030":   ["CICD-SEC-3", "CICD-SEC-7"],  # NODE_OPTIONS --require / --inspect
        # npm (lockfile + manifest static analysis)
        "NPM-001":  ["CICD-SEC-3"],   # floating range in package.json
        "NPM-002":  ["CICD-SEC-3", "CICD-SEC-9"],  # lock entry missing integrity
        "NPM-003":  ["CICD-SEC-3", "CICD-SEC-8"],  # non-registry source
        "NPM-004":  ["CICD-SEC-3", "CICD-SEC-7"],  # install-time lifecycle script
        "NPM-005":  ["CICD-SEC-3", "CICD-SEC-9"],  # git dep with mutable ref
        "NPM-006":  ["CICD-SEC-3", "CICD-SEC-8"],  # compromised-package registry
        "NPM-007":  ["CICD-SEC-3", "CICD-SEC-7"],  # .npmrc ignore-scripts enforcement
        "NPM-008":  ["CICD-SEC-3", "CICD-SEC-8"],  # cooldown gate (--resolve-remote)
        "NPM-009":  ["CICD-SEC-3", "CICD-SEC-8"],  # new-transitive-dep diff gate
        "NPM-010":  ["CICD-SEC-3", "CICD-SEC-8"],  # OSV advisory (--resolve-remote)
        "NPM-011":  ["CICD-SEC-6", "CICD-SEC-3"],  # secret-shaped paths in files field
        "NPM-014":  ["CICD-SEC-3"],   # single-publisher supply-chain risk
        "NPM-015":  ["CICD-SEC-4"],   # missing build provenance
        "NPM-017":  ["CICD-SEC-4"],   # provenance built from a non-release ref
        "NPM-018":  ["CICD-SEC-3"],   # latest release from a new publisher (takeover)
        "NPM-019":  ["CICD-SEC-3"],   # overrides / resolutions redirect to non-registry source
        "NPM-020":  ["CICD-SEC-3"],   # .npmrc registry repoint off canonical npm
        "NPM-016":  ["CICD-SEC-3"],   # low OpenSSF Scorecard upstream
        # pypi (requirements file static analysis)
        "PYPI-001": ["CICD-SEC-3"],   # requirements line lacks ==pin
        "PYPI-002": ["CICD-SEC-3", "CICD-SEC-9"],  # hash pinning missing
        "PYPI-003": ["CICD-SEC-3", "CICD-SEC-7"],  # http index / --trusted-host
        "PYPI-018": ["CICD-SEC-3"],  # --no-binary forces sdist build
        "PYPI-019": ["CICD-SEC-4"],  # missing PEP 740 build provenance
        "PYPI-020": ["CICD-SEC-3"],  # low OpenSSF Scorecard upstream
        "PYPI-021": ["CICD-SEC-4"],  # provenance built from a non-release ref
        "PYPI-004": ["CICD-SEC-3", "CICD-SEC-9"],  # VCS dep without commit SHA
        "PYPI-015": ["CICD-SEC-3"],  # direct artifact URL
        "PYPI-005": ["CICD-SEC-3"],   # --extra-index-url (dep confusion)
        "PYPI-017": ["CICD-SEC-3"],  # remote --find-links
        "PYPI-016": ["CICD-SEC-3"],  # primary index repointed
        "PYPI-006": ["CICD-SEC-3", "CICD-SEC-8"],  # compromised-package registry
        "PYPI-008": ["CICD-SEC-3", "CICD-SEC-8"],  # cooldown gate (--resolve-remote)
        "PYPI-009": ["CICD-SEC-3", "CICD-SEC-8"],  # OSV advisory (--resolve-remote)
        # ── PyPI (PYPI-010..014) ──
        "PYPI-010": ["CICD-SEC-6", "CICD-SEC-10"],  # index URL with embedded credentials
        "PYPI-011": ["CICD-SEC-3", "CICD-SEC-6"],   # --trusted-host disables TLS
        "PYPI-012": ["CICD-SEC-3", "CICD-SEC-7"],   # build-system requires floating
        "PYPI-013": ["CICD-SEC-3"],                 # pyproject dynamic dependencies
        "PYPI-014": ["CICD-SEC-3", "CICD-SEC-6"],   # custom source HTTP
        # maven (pom.xml + settings.xml static analysis)
        "MVN-001":  ["CICD-SEC-3"],                # floating Maven version range
        "MVN-002":  ["CICD-SEC-3"],                # mutable SNAPSHOT dependency
        "MVN-003":  ["CICD-SEC-8", "CICD-SEC-3"],  # plaintext-HTTP repository
        "MVN-004":  ["CICD-SEC-3"],                # missing <version> element
        "MVN-005":  ["CICD-SEC-3", "CICD-SEC-8"],  # lax repository checksumPolicy
        "MVN-006":  ["CICD-SEC-3", "CICD-SEC-8"],  # compromised-package registry
        "MVN-007":  ["CICD-SEC-8", "CICD-SEC-3"],  # settings.xml wildcard mirror
        "MVN-008":  ["CICD-SEC-3", "CICD-SEC-8"],  # cooldown gate (--resolve-remote)
        "MVN-009":  ["CICD-SEC-3", "CICD-SEC-8"],  # OSV advisory (--resolve-remote)
        # ── Maven extended pack (MVN-010..014) ──
        "MVN-010":  ["CICD-SEC-6", "CICD-SEC-10"], # settings.xml plaintext password
        "MVN-011":  ["CICD-SEC-6", "CICD-SEC-10"], # repo URL embedded credentials
        "MVN-012":  ["CICD-SEC-3", "CICD-SEC-7"],  # build plugin floating
        "MVN-013":  ["CICD-SEC-3", "CICD-SEC-7"],  # build extension floating
        "MVN-014":  ["CICD-SEC-3"],                # Maven Wrapper sha256 missing
        "MVN-015": ["CICD-SEC-1", "CICD-SEC-3"],  # build-time plugin exec bound to lifecycle
        "MVN-016": ["CICD-SEC-3", "CICD-SEC-5"],  # gradle allowInsecureProtocol
        "MVN-017": ["CICD-SEC-6", "CICD-SEC-10"],  # settings.xml privateKey + plaintext passphrase
        "MVN-018": ["CICD-SEC-3"],  # distributionManagement release accepts snapshots
        # nuget (csproj + NuGet.config static analysis)
        "NUGET-001": ["CICD-SEC-3"],                # floating NuGet version range
        "NUGET-002": ["CICD-SEC-3"],                # wildcard prerelease version
        "NUGET-003": ["CICD-SEC-3"],                # missing explicit version
        "NUGET-004": ["CICD-SEC-3", "CICD-SEC-8"],  # HTTP-only package source
        "NUGET-005": ["CICD-SEC-3", "CICD-SEC-8"],  # known-compromised package version
        "NUGET-006": ["CICD-SEC-3", "CICD-SEC-9"],  # no lock file for reproducible restores
        "NUGET-007": ["CICD-SEC-3"],                # multiple sources without packageSourceMapping
        "NUGET-008": ["CICD-SEC-3", "CICD-SEC-8"],  # cooldown gate (--resolve-remote)
        "NUGET-009": ["CICD-SEC-3", "CICD-SEC-8"],  # OSV advisory (--resolve-remote)
        "NUGET-010": ["CICD-SEC-6", "CICD-SEC-7"],  # NuGet.config cleartext feed credential
        # ── NuGet extended pack (NUGET-011..015) ──
        "NUGET-011": ["CICD-SEC-3", "CICD-SEC-5"],  # source mapping wildcard
        "NUGET-012": ["CICD-SEC-3"],                # signature validation off
        "NUGET-013": ["CICD-SEC-3", "CICD-SEC-5"],  # dotnet-tools unpinned
        "NUGET-014": ["CICD-SEC-6", "CICD-SEC-10"], # source URL credentials
        "NUGET-015": ["CICD-SEC-3"],                # VersionOverride breaks CPM
        "NUGET-016": ["CICD-SEC-3"],                # missing <clear/> inherits public gallery
        "NUGET-017": ["CICD-SEC-3"],  # public gallery active alongside private feed, not disabled
        "NUGET-018": ["CICD-SEC-4", "CICD-SEC-3"],  # build-time MSBuild execution
        "NUGET-019": ["CICD-SEC-3"],                # require mode, no trusted signers
        # ── Go modules (GOMOD-001..006) ──
        "GOMOD-001": ["CICD-SEC-3"],               # go.sum integrity manifest missing
        "GOMOD-002": ["CICD-SEC-3", "CICD-SEC-5"], # replace directive to local path
        "GOMOD-003": ["CICD-SEC-3", "CICD-SEC-5"], # replace directive to different module
        "GOMOD-004": ["CICD-SEC-3"],               # +incompatible direct require
        "GOMOD-005": ["CICD-SEC-3"],               # missing go toolchain directive
        "GOMOD-006": ["CICD-SEC-3", "CICD-SEC-7"], # known-compromised module version
        # ── Go modules extended pack (GOMOD-007..010) ──
        "GOMOD-007": ["CICD-SEC-3"],               # vendor/modules.txt stale
        "GOMOD-008": ["CICD-SEC-3", "CICD-SEC-5"], # replace directive without version pin
        "GOMOD-009": ["CICD-SEC-3"],               # pre-release direct require
        "GOMOD-010": ["CICD-SEC-3"],               # stale exclude directive
        "GOMOD-011": ["CICD-SEC-3", "CICD-SEC-4"],  # tool directive build-time exec
        "GOMOD-012": ["CICD-SEC-3", "CICD-SEC-5"],  # insecure / non-canonical module host
        # ── Cargo / Rust (CARGO-001..006) ──
        "CARGO-001": ["CICD-SEC-3"],               # floating Cargo.toml version spec
        "CARGO-002": ["CICD-SEC-3", "CICD-SEC-5"], # git dep with mutable ref (no rev)
        "CARGO-003": ["CICD-SEC-3"],               # missing Cargo.lock
        "CARGO-004": ["CICD-SEC-3", "CICD-SEC-5"], # local-path Cargo dependency
        "CARGO-005": ["CICD-SEC-3", "CICD-SEC-5"], # alternate-registry Cargo dependency
        "CARGO-006": ["CICD-SEC-3", "CICD-SEC-7"], # known-compromised crate version
        # ── Cargo extended pack (CARGO-007..010) ──
        "CARGO-007": ["CICD-SEC-3", "CICD-SEC-7"], # build-dependencies floating
        "CARGO-008": ["CICD-SEC-3", "CICD-SEC-5"], # [patch.crates-io] substitution
        "CARGO-009": ["CICD-SEC-3"],               # workspace deps floating
        "CARGO-010": ["CICD-SEC-3"],               # missing rust-version
        "CARGO-011": ["CICD-SEC-1", "CICD-SEC-3"],  # build.rs compile-time egress / exec
        "CARGO-012": ["CICD-SEC-3", "CICD-SEC-4"],  # .cargo/config.toml source override / build flags
        "CARGO-013": ["CICD-SEC-3", "CICD-SEC-5"],  # Cargo.lock off-crates.io source
        "CARGO-014": ["CICD-SEC-3"],  # no supply-chain audit-gate config
        # ── Composer / PHP (COMPOSER-001..008) ──
        "COMPOSER-001": ["CICD-SEC-3"],               # missing composer.lock
        "COMPOSER-002": ["CICD-SEC-3"],               # floating constraint
        "COMPOSER-003": ["CICD-SEC-3", "CICD-SEC-5"], # HTTP repository
        "COMPOSER-012": ["CICD-SEC-3", "CICD-SEC-5"],  # disables Packagist / marks custom repo canonical
        "COMPOSER-011": ["CICD-SEC-3", "CICD-SEC-5"],  # external VCS repository re-points a package
        "COMPOSER-004": ["CICD-SEC-6", "CICD-SEC-10"], # repo URL credentials
        "COMPOSER-005": ["CICD-SEC-3"],               # minimum-stability dev/alpha/beta
        "COMPOSER-014": ["CICD-SEC-3"],  # minimum-stability without prefer-stable
        "COMPOSER-006": ["CICD-SEC-3", "CICD-SEC-1"], # scripts curl-pipe-shell
        "COMPOSER-007": ["CICD-SEC-3", "CICD-SEC-7"], # compromised package
        "COMPOSER-008": ["CICD-SEC-3", "CICD-SEC-5"], # allow-plugins wildcard
        "COMPOSER-009": ["CICD-SEC-6", "CICD-SEC-10"], # auth.json credentials
        "COMPOSER-010": ["CICD-SEC-3", "CICD-SEC-5"], # secure-http false
        "COMPOSER-013": ["CICD-SEC-3", "CICD-SEC-5"],  # config.disable-tls
        # ── RubyGems / Bundler (GEM-001..008) ──
        "GEM-001": ["CICD-SEC-3"],               # missing Gemfile.lock
        "GEM-002": ["CICD-SEC-3"],               # floating gem constraint
        "GEM-003": ["CICD-SEC-3", "CICD-SEC-5"], # HTTP source
        "GEM-004": ["CICD-SEC-6", "CICD-SEC-10"], # source URL credentials
        "GEM-005": ["CICD-SEC-3", "CICD-SEC-5"], # git/github source mutable ref
        "GEM-006": ["CICD-SEC-3", "CICD-SEC-7"], # compromised gem
        "GEM-007": ["CICD-SEC-3", "CICD-SEC-5"], # multiple top-level sources
        "GEM-008": ["CICD-SEC-3", "CICD-SEC-5"], # path: source in prod
        "GEM-009": ["CICD-SEC-6", "CICD-SEC-10"], # .bundle/config credentials
        "GEM-010": ["CICD-SEC-3"],               # dynamic Gemfile
        "GEM-011": ["CICD-SEC-3", "CICD-SEC-1"],  # Bundler plugin install-time exec
        "GEM-012": ["CICD-SEC-3", "CICD-SEC-5"],  # per-gem :source override
        "GEM-013": ["CICD-SEC-3", "CICD-SEC-5"],  # insecure git transport
        # ── Pulumi (PULUMI-001..006) ──
        "PULUMI-001": ["CICD-SEC-6", "CICD-SEC-7"], # passphrase secretsprovider
        "PULUMI-002": ["CICD-SEC-6"],               # secret-shaped config plaintext
        "PULUMI-003": ["CICD-SEC-6", "CICD-SEC-7"], # hardcoded credentials in source
        "PULUMI-011": ["CICD-SEC-3", "CICD-SEC-4"],  # plugin from custom download server
        "PULUMI-004": ["CICD-SEC-2", "CICD-SEC-6"], # insecure state backend
        "PULUMI-005": ["CICD-SEC-1", "CICD-SEC-2"], # wildcard IAM policy in source
        "PULUMI-006": ["CICD-SEC-1", "CICD-SEC-6"], # StackReference unguarded
        # ── Pulumi extended pack (PULUMI-007..010) ──
        "PULUMI-007": ["CICD-SEC-2", "CICD-SEC-6"], # public-access cloud resource
        "PULUMI-008": ["CICD-SEC-5", "CICD-SEC-3"], # shell-exec with non-constant input
        "PULUMI-013": ["CICD-SEC-3", "CICD-SEC-5"],  # dynamic provider deploy-time code
        "PULUMI-014": ["CICD-SEC-3", "CICD-SEC-6"],  # ESC environment imported without a qualifier
        "PULUMI-009": ["CICD-SEC-3"],               # runtime / source mismatch
        "PULUMI-012": ["CICD-SEC-3", "CICD-SEC-4"],  # plugin version unpinned
        "PULUMI-010": ["CICD-SEC-6"],               # stack orphaned encryption salt
        # Buildkite
        "BK-001":   ["CICD-SEC-3"],   # plugin not pinned to exact version
        "BK-002":   ["CICD-SEC-6", "CICD-SEC-7"],  # literal secret in env
        "BK-003":   ["CICD-SEC-4"],   # untrusted variable interpolated
        "BK-004":   ["CICD-SEC-3", "CICD-SEC-1"],  # remote curl-pipe to shell
        "BK-005":   ["CICD-SEC-5"],   # docker --privileged / host bind
        "BK-006":   ["CICD-SEC-9"],   # missing timeout_in_minutes
        "BK-007":   ["CICD-SEC-2", "CICD-SEC-7"],  # deploy step not gated
        "BK-008":   ["CICD-SEC-3"],   # TLS verification disabled
        "BK-009":   ["CICD-SEC-9"],   # artifacts not signed
        "BK-010":   ["CICD-SEC-9"],   # SBOM not generated
        "BK-011":   ["CICD-SEC-9"],   # SLSA provenance not produced
        "BK-012":   ["CICD-SEC-9"],   # no vulnerability scanning
        "BK-013":   ["CICD-SEC-1"],   # deploy step has no branches filter
        "BK-014":   ["CICD-SEC-3"],   # unpinned package install
        "BK-015":   ["CICD-SEC-7", "CICD-SEC-1"],  # agents map interpolation
        "BK-016":   ["CICD-SEC-4"],                # dangerous shell idiom
        # Tekton
        "TKN-001":  ["CICD-SEC-3"],   # step image not pinned to digest
        "TKN-016": ["CICD-SEC-3"],  # remote resolver / bundle task body not pinned
        "TKN-002":  ["CICD-SEC-5"],   # step runs privileged / as root
        "TKN-003":  ["CICD-SEC-4", "CICD-SEC-1"],  # param injection in script
        "TKN-004":  ["CICD-SEC-5"],   # hostPath / host namespaces
        "TKN-005":  ["CICD-SEC-6", "CICD-SEC-7"],  # literal secret in env / param
        "TKN-006":  ["CICD-SEC-9"],   # no explicit timeout
        "TKN-007":  ["CICD-SEC-2"],   # default ServiceAccount
        "TKN-008":  ["CICD-SEC-3"],   # remote install / TLS bypass
        "TKN-009":  ["CICD-SEC-9"],   # artifacts not signed
        "TKN-010":  ["CICD-SEC-9"],   # SBOM not generated
        "TKN-011":  ["CICD-SEC-9"],   # SLSA provenance not produced
        "TKN-012":  ["CICD-SEC-9"],   # no vulnerability scanning
        "TKN-013":  ["CICD-SEC-5"],   # sidecar privileged / root
        "TKN-014":  ["CICD-SEC-3"],   # unpinned package install
        "TKN-015":  ["CICD-SEC-4", "CICD-SEC-5"],  # workspace subPath param injection
        # Argo Workflows
        "ARGO-001": ["CICD-SEC-3"],   # template image not digest-pinned
        "ARGO-002": ["CICD-SEC-5"],   # template privileged / root
        "ARGO-003": ["CICD-SEC-2"],   # default ServiceAccount
        "ARGO-016": ["CICD-SEC-2"],   # cluster-admin / over-privileged ServiceAccount
        "ARGO-004": ["CICD-SEC-5"],   # hostPath / host namespaces
        "ARGO-005": ["CICD-SEC-4", "CICD-SEC-1"],  # parameter injection in script
        "ARGO-017": ["CICD-SEC-4", "CICD-SEC-2"],  # resource template manifest injection
        "ARGO-006": ["CICD-SEC-6", "CICD-SEC-7"],  # literal secret in env / param
        "ARGO-007": ["CICD-SEC-9"],   # missing activeDeadlineSeconds
        "ARGO-008": ["CICD-SEC-3"],   # remote install / TLS bypass
        "ARGO-009": ["CICD-SEC-9"],   # artifacts not signed
        "ARGO-010": ["CICD-SEC-9"],   # SBOM not generated
        "ARGO-011": ["CICD-SEC-9"],   # SLSA provenance not produced
        "ARGO-012": ["CICD-SEC-9"],   # no vulnerability scanning
        "ARGO-013": ["CICD-SEC-2", "CICD-SEC-7"],  # SA token automount
        "ARGO-014": ["CICD-SEC-3"],   # unpinned package install
        "ARGO-015": ["CICD-SEC-3", "CICD-SEC-9"],  # insecure artifact URL
        # Argo CD
        "ARGOCD-001": ["CICD-SEC-5", "CICD-SEC-1"],  # AppProject sourceRepos wildcard
        "ARGOCD-002": ["CICD-SEC-5"],                # AppProject destinations wildcard
        "ARGOCD-003": ["CICD-SEC-7"],                # auto-sync prune without selfHeal
        "ARGOCD-004": ["CICD-SEC-2"],                # RBAC wildcard policy
        "ARGOCD-005": ["CICD-SEC-6"],                # repo plaintext credentials
        "ARGOCD-006": ["CICD-SEC-1", "CICD-SEC-4"],  # ApplicationSet PR/SCM no allowlist
        "ARGOCD-007": ["CICD-SEC-4", "CICD-SEC-1"],  # Helm generator interpolation
        "ARGOCD-008": ["CICD-SEC-3", "CICD-SEC-4"],  # CMP plugin invocation
        "ARGOCD-015": ["CICD-SEC-4"],  # kustomize --enable-helm
        "ARGOCD-009": ["CICD-SEC-2"],                # anonymous access enabled
        "ARGOCD-014": ["CICD-SEC-2"],  # web terminal exec.enabled
        # ── ArgoCD extended pack (ARGOCD-010..013) ──
        "ARGOCD-010": ["CICD-SEC-3", "CICD-SEC-5"], # mutable targetRevision
        "ARGOCD-017": ["CICD-SEC-3", "CICD-SEC-5"],  # in-cluster mutable source
        "ARGOCD-019": ["CICD-SEC-5"],  # drift detection disabled on a sensitive field
        "ARGOCD-016": ["CICD-SEC-4", "CICD-SEC-3"],  # Helm valueFiles from a remote URL
        "ARGOCD-018": ["CICD-SEC-4"],  # custom resource health / action Lua
        "ARGOCD-011": ["CICD-SEC-1", "CICD-SEC-5"], # cluster-resource wildcard
        "ARGOCD-012": ["CICD-SEC-4", "CICD-SEC-1"], # no sync windows on prod
        "ARGOCD-013": ["CICD-SEC-7"],               # no revision history cap
        # Cross-cutting dataflow / taint engine (provider-spanning,
        # currently GHA-only in v1)
        "TAINT-001": ["CICD-SEC-4", "CICD-SEC-1"],  # cross-step taint via $GITHUB_OUTPUT
        "TAINT-002": ["CICD-SEC-4", "CICD-SEC-1"],  # cross-job taint via jobs.<id>.outputs:
        "TAINT-003": ["CICD-SEC-4", "CICD-SEC-1"],  # tainted with: forward into reusable workflow
        "TAINT-004": ["CICD-SEC-4", "CICD-SEC-1"],  # GitLab dotenv cross-job taint flow
        "TAINT-005": ["CICD-SEC-4", "CICD-SEC-1"],  # Buildkite meta-data cross-step taint flow
        "TAINT-006": ["CICD-SEC-4", "CICD-SEC-1"],  # Tekton results cross-task taint flow
        "TAINT-007": ["CICD-SEC-4", "CICD-SEC-1"],  # Argo outputs.parameters cross-template
        "TAINT-008": ["CICD-SEC-4", "CICD-SEC-1"],  # GitLab extends-chain inheritance
        "TAINT-009": ["CICD-SEC-5", "CICD-SEC-2"],  # env-protected secret flows to unprotected job
        # Drone CI
        "DR-001":   ["CICD-SEC-3"],                 # step image not digest-pinned
        "HARNESS-001":   ["CICD-SEC-3"],  # Harness step image not digest-pinned
        "HARNESS-002":   ["CICD-SEC-4"],  # Harness expression injection in step command
        "HARNESS-003":   ["CICD-SEC-5"],  # Harness privileged step
        "HARNESS-004":   ["CICD-SEC-6", "CICD-SEC-7"],  # Harness literal credential in variable
        "HARNESS-005":   ["CICD-SEC-3", "CICD-SEC-5"],  # Harness pipe-to-shell
        "HARNESS-006":   ["CICD-SEC-3", "CICD-SEC-1"],  # Harness TLS bypass in commands
        "HARNESS-007":   ["CICD-SEC-5"],  # Harness sensitive host-path mount
        "HARNESS-008":   ["CICD-SEC-4"],  # Harness agentic-CLI prompt injection
        "HARNESS-010":   ["CICD-SEC-4"],  # Harness model trust_remote_code (code exec)
        "HARNESS-011":   ["CICD-SEC-4"],  # Harness unsafe model deser (pickle RCE)
        "HARNESS-012":   ["CICD-SEC-3"],  # Harness model pulled without a pinned revision
        "HARNESS-009":   ["CICD-SEC-1"],  # Harness agentic-CLI output autolands without review
        "DR-002":   ["CICD-SEC-5"],                 # step privileged
        "DR-003":   ["CICD-SEC-4", "CICD-SEC-1"],   # Drone variable injection
        "DR-004":   ["CICD-SEC-6", "CICD-SEC-7"],   # literal secret
        "DR-005":   ["CICD-SEC-3"],                 # plugin floating tag
        "DR-006":   ["CICD-SEC-3", "CICD-SEC-1"],   # TLS bypass in commands
        "DR-007":   ["CICD-SEC-5"],                 # sensitive host-path mount
        "DR-008":   ["CICD-SEC-3"],                 # pull: never policy
        "DR-009":   ["CICD-SEC-1", "CICD-SEC-3"],   # cache key tainted
        "DR-010":   ["CICD-SEC-3"],                 # unpinned package install
        "DR-011":   ["CICD-SEC-7", "CICD-SEC-1"],   # node map interpolation
        # ── Drone extended pack (DR-012..016) ──
        "DR-012":   ["CICD-SEC-3"],                 # service image not pinned
        "DR-013":   ["CICD-SEC-1", "CICD-SEC-4"],   # no trigger event filter
        "DR-014":   ["CICD-SEC-3", "CICD-SEC-5"],   # pipe-to-shell
        "DR-015":   ["CICD-SEC-3", "CICD-SEC-5"],   # clone recursive
        "DR-016":   ["CICD-SEC-3", "CICD-SEC-5"],   # image field interpolation
        "DR-017":   ["CICD-SEC-4"],                 # dangerous shell idiom
        # OCI image manifests
        "OCI-001":  ["CICD-SEC-3", "CICD-SEC-10"],  # missing provenance annotations
        "OCI-002":  ["CICD-SEC-3", "CICD-SEC-9", "CICD-SEC-10"],  # missing build attestation
        "OCI-003":  ["CICD-SEC-3", "CICD-SEC-10"],  # missing image.created
        "OCI-004":  ["CICD-SEC-3", "CICD-SEC-9"],   # foreign-layer URL reference
        "OCI-005":  ["CICD-SEC-3", "CICD-SEC-10"],  # missing image.licenses annotation
        "OCI-006":  ["CICD-SEC-3"],                 # excessive layer count
        "OCI-007":  ["CICD-SEC-3", "CICD-SEC-9"],   # legacy schemaVersion 1
        "OCI-008":  ["CICD-SEC-3", "CICD-SEC-9"],   # weak digest algorithm
        "OCI-009":  ["CICD-SEC-3", "CICD-SEC-10"],  # missing base-image annotations
        "ATTEST-001": ["CICD-SEC-2", "CICD-SEC-3", "CICD-SEC-9"],   # untrusted SLSA builder
        "ATTEST-002": ["CICD-SEC-3", "CICD-SEC-9"],                 # source-repo claim missing/unverifiable
        "ATTEST-003": ["CICD-SEC-3", "CICD-SEC-9", "CICD-SEC-10"],  # SBOM floating versions
        "ATTEST-004": ["CICD-SEC-3", "CICD-SEC-9"],                 # provenance lacks materials
        "ATTEST-005": ["CICD-SEC-3", "CICD-SEC-9"],                 # subject digest unpinned
        "ATTEST-006": ["CICD-SEC-3", "CICD-SEC-9"],                 # buildType missing / placeholder
        "ATTEST-007": ["CICD-SEC-3", "CICD-SEC-9", "CICD-SEC-10"],  # SBOM supplier attribution
        # SCM posture (governance scanned via the GitHub REST API)
        "SCM-001":  ["CICD-SEC-1"],                # default branch unprotected
        "SCM-002":  ["CICD-SEC-1"],                # required reviews missing
        "SCM-003":  ["CICD-SEC-10"],               # default code scanning disabled
        "SCM-004":  ["CICD-SEC-6"],                # secret scanning disabled
        "SCM-005":  ["CICD-SEC-3", "CICD-SEC-10"], # Dependabot security updates off
        "SCM-006":  ["CICD-SEC-1", "CICD-SEC-6"],  # signed commits not required
        "SCM-007":  ["CICD-SEC-1"],                # force-push allowed
        "SCM-008":  ["CICD-SEC-1", "CICD-SEC-10"], # required status checks missing
        "SCM-009":  ["CICD-SEC-1"],                # branch deletions allowed
        "SCM-010":  ["CICD-SEC-1"],                # admin bypass allowed
        "SCM-011":  ["CICD-SEC-1"],                # CODEOWNERS reviews not required
        "SCM-012":  ["CICD-SEC-1"],                # stale reviews not dismissed
        "SCM-013":  ["CICD-SEC-1"],                # conversation resolution not required
        "SCM-014":  ["CICD-SEC-1"],                # last-push approval not required
        "SCM-015":  ["CICD-SEC-6"],                # secret scanning push protection off
        "SCM-016":  ["CICD-SEC-10"],               # private vulnerability reporting off
        "SCM-017":  ["CICD-SEC-1"],                # CODEOWNERS file missing
        "SCM-018":  ["CICD-SEC-1"],                # PR review bypass allowed
        "SCM-019":  ["CICD-SEC-1"],                # push-restriction allowlist names users
        "SCM-020":  ["CICD-SEC-2", "CICD-SEC-5"],  # default workflow token write
        "SCM-021":  ["CICD-SEC-1", "CICD-SEC-4"],  # actions can self-approve PRs
        "SCM-022":  ["CICD-SEC-3", "CICD-SEC-8"],  # allowed_actions = all
        "SCM-023":  ["CICD-SEC-1", "CICD-SEC-5"],  # environment without required reviewers
        "SCM-024":  ["CICD-SEC-1", "CICD-SEC-4"],  # environment deploys from any branch
        "SCM-025":  ["CICD-SEC-2", "CICD-SEC-6"],  # write-enabled deploy keys (push backdoor)
        "SCM-026":  ["CICD-SEC-6", "CICD-SEC-10"], # webhook insecure (HTTP / no-TLS / no-secret)
        "SCM-027":  ["CICD-SEC-2", "CICD-SEC-5"],  # outside collaborator with elevated perms
        "SCM-028":  ["CICD-SEC-3", "CICD-SEC-5"],  # private repo allows forking
        "SCM-029":  ["CICD-SEC-1", "CICD-SEC-5"],  # ruleset in evaluate / disabled mode
        "SCM-030":  ["CICD-SEC-1", "CICD-SEC-2", "CICD-SEC-5"],  # ruleset always-bypass
        "SCM-031":  ["CICD-SEC-1", "CICD-SEC-4"],  # auto-merge enabled
        "SCM-032":  ["CICD-SEC-1", "CICD-SEC-5"],  # active ruleset lacks PR review
        "SCM-033":  ["CICD-SEC-1", "CICD-SEC-4"],  # active ruleset lacks status checks
        "SCM-034":  ["CICD-SEC-1"],                # active ruleset doesn't block force-push
        "SCM-035":  ["CICD-SEC-1"],                # active ruleset doesn't block deletion
        "SCM-036":  ["CICD-SEC-1", "CICD-SEC-9"],  # active ruleset lacks signed commits
        "SCM-037":  ["CICD-SEC-1", "CICD-SEC-4"],  # active ruleset PR rule lacks stale-review dismissal
        "SCM-038":  ["CICD-SEC-1"],                # active ruleset doesn't require linear history
        "SCM-039":  ["CICD-SEC-1", "CICD-SEC-3"],  # active ruleset doesn't pin a required workflow
        "SCM-040":  ["CICD-SEC-1", "CICD-SEC-4"],  # active ruleset doesn't gate on code scanning
        "SCM-041":  ["CICD-SEC-1", "CICD-SEC-4"],  # active ruleset doesn't gate on a deployment env
        "SCM-042":  ["CICD-SEC-1", "CICD-SEC-4"],  # active ruleset doesn't require merge queue
        "SCM-043":  ["CICD-SEC-1", "CICD-SEC-9"],  # tag-ruleset lacks signed_commits
        "SCM-044":  ["CICD-SEC-1", "CICD-SEC-6"],  # required_signatures bypassed for admins
        "SCM-045":  ["CICD-SEC-10"],               # default code scanning limited query suite
        "SCM-046":  ["CICD-SEC-10"],               # default code scanning configured but paused
        "SCM-047":  ["CICD-SEC-10"],               # repo language not covered by default scanning
        "SCM-048":  ["CICD-SEC-2"],                # org codespace secret scoped to all repos
        "SCM-049":  ["CICD-SEC-2"],                # classic PAT used where fine-grained suffices
        "ORG-001":  ["CICD-SEC-2"],                # org: 2FA not required org-wide
        "ORG-002":  ["CICD-SEC-2"],                # org: default member permission too broad
        "ORG-003":  ["CICD-SEC-3"],                # org: no Actions allow-list (any action runs)
        "ORG-004":  ["CICD-SEC-2"],                # org: default workflow token is write
        "ORG-005":  ["CICD-SEC-1"],                # org: Actions can approve PRs (review bypass)
        "ORG-006":  ["CICD-SEC-2"],                # org: Actions secret scoped to all repos
        "ORG-007":  ["CICD-SEC-2"],                # org: private-repo forking allowed (code exfiltration)
        "GLGRP-001":  ["CICD-SEC-2"],  # gitlab group: 2FA not required
        "GLGRP-002":  ["CICD-SEC-2"],  # gitlab group: forking outside group allowed
        "GLGRP-003":  ["CICD-SEC-2"],  # gitlab group: sharing projects outside the hierarchy
        "GLGRP-004":  ["CICD-SEC-1"],  # gitlab group: default branch protection disabled for new projects
        "GLGRP-005":  ["CICD-SEC-6", "CICD-SEC-10"],  # gitlab group: group webhook over insecure transport
        "GLGRP-006":  ["CICD-SEC-6"],  # gitlab group: group CI/CD variable holds a secret with a weak control
        "ORG-008":  ["CICD-SEC-2"],                # org: members can create public repos (code exposure)
        "ORG-009":  ["CICD-SEC-4", "CICD-SEC-7"],   # org: self-hosted runner group exposed to public repos
        "ORG-010":  ["CICD-SEC-6"],                # org: new-repo secret-scanning push-protection default off
        "ORG-011":  ["CICD-SEC-6", "CICD-SEC-10"],  # org: org webhook over insecure transport
        "ORG-012":  ["CICD-SEC-3", "CICD-SEC-10"],  # org: new-repo Dependabot security-updates default off
        "ORG-013":  ["CICD-SEC-1", "CICD-SEC-5"],   # org: org ruleset not enforced (evaluate/disabled)
        # GitLab-specific platform posture (SCM-050..053)
        "SCM-050":  ["CICD-SEC-6"],                # GitLab push rules: prevent_secrets
        "SCM-051":  ["CICD-SEC-1", "CICD-SEC-6"],  # GitLab push rules: committer-email check
        "SCM-052":  ["CICD-SEC-1"],                # GitLab MR: discussions-resolved gate
        "SCM-053":  ["CICD-SEC-1", "CICD-SEC-4"],  # GitLab MR: author self-approval allowed
        # Bitbucket-specific platform posture (SCM-054..055)
        "SCM-054":  ["CICD-SEC-1", "CICD-SEC-6"],  # Bitbucket private repo allows public forks
        "SCM-055":  ["CICD-SEC-1"],                # Bitbucket no write-side branch-restriction kinds
        # GHA supply-chain posture pack
        "GHA-097":  ["CICD-SEC-1"],                # recursive PR auto-merge loop
        "GHA-098":  ["CICD-SEC-7"],                # deploy without security scan gate
        "GHA-099":  ["CICD-SEC-6", "CICD-SEC-2"],  # deploy env plaintext secret
        "GHA-100":  ["CICD-SEC-3", "CICD-SEC-9"],  # cosign verify no identity binding
        "GHA-102":  ["CICD-SEC-3", "CICD-SEC-4"],  # submodule checkout on PR trigger
        "GHA-103":  ["CICD-SEC-1", "CICD-SEC-4"],  # AI review bot on untrusted trigger
        "GHA-104":  ["CICD-SEC-4", "CICD-SEC-9"],  # AI agent auto-push without PR review
        # Secrets-in-logs (cross-provider)
        "GL-036":   ["CICD-SEC-6"],               # secret echoed to GitLab CI log
        "GL-038":   ["CICD-SEC-6"],               # CI_DEBUG_TRACE dumps secrets to GitLab CI log
        "BB-032":   ["CICD-SEC-6"],               # secret echoed to Bitbucket log
        "ADO-031":  ["CICD-SEC-6"],               # secret echoed to Azure DevOps log
        "ADO-032":  ["CICD-SEC-6"],               # checkout persistCredentials leaks token to .git/config
        "ADO-033":  ["CICD-SEC-4"],               # IaC apply on a PR-validated pipeline
        "CC-032":   ["CICD-SEC-6"],               # secret echoed to CircleCI log
        "CC-034":   ["CICD-SEC-4"],               # trust_remote_code model load = code exec
        "CC-035":   ["CICD-SEC-3"],               # model pulled without a pinned revision
        "CC-036":   ["CICD-SEC-4"],               # unsafe pickle deser of fetched artifact = code exec
        # npm supply-chain posture
        "NPM-012":  ["CICD-SEC-3", "CICD-SEC-6"],  # publish token missing restrictions
        "NPM-013":  ["CICD-SEC-6", "CICD-SEC-3"],  # broad files-field publishes everything
        # Azure Cloud posture
        "ENTRA-001": ["CICD-SEC-2"],                # SP assigned Global Administrator
        "ENTRA-002": ["CICD-SEC-2"],                # app credential beyond 180 days
        "ENTRA-003": ["CICD-SEC-2"],                # SP uses password credential
        "AZST-001":  ["CICD-SEC-9"],                # public blob access
        "AZST-002":  ["CICD-SEC-9"],                # non-HTTPS traffic
        "AZST-003":  ["CICD-SEC-9"],                # no CMK encryption
        "AKV-001":   ["CICD-SEC-9"],                # soft delete not enabled
        "AKV-002":   ["CICD-SEC-9"],                # purge protection not enabled
        "AKV-003":   ["CICD-SEC-9"],                # network ACLs allow all
        "ACR-001":   ["CICD-SEC-2"],                # admin user enabled
        "ACR-002":   ["CICD-SEC-9"],                # public network access
        "ACR-003":   ["CICD-SEC-9"],                # content trust not enabled
        "AZMON-001": ["CICD-SEC-10"],               # no diagnostic setting
        "AZMON-002": ["CICD-SEC-10"],               # log retention < 365 days
        "AZMON-003": ["CICD-SEC-10"],               # no alert rule
        # GCP cloud posture
        "GCIAM-001": ["CICD-SEC-2"],                # SA has Owner/Editor role
        "GCIAM-002": ["CICD-SEC-2"],                # user-managed SA key
        "GCIAM-003": ["CICD-SEC-2"],                # token creator without condition
        "GCS-001":   ["CICD-SEC-9"],                # public bucket
        "GCS-002":   ["CICD-SEC-9"],                # no uniform access
        "GCS-003":   ["CICD-SEC-9"],                # versioning not enabled
        "GCKMS-001": ["CICD-SEC-9"],                # key rotation > 365 days
        "GCKMS-002": ["CICD-SEC-9"],                # public KMS key access
        "GCKMS-003": ["CICD-SEC-9"],                # no HSM protection
        "GAR-001":   ["CICD-SEC-9"],                # no vulnerability scanning
        "GAR-002":   ["CICD-SEC-9"],                # publicly readable repo
        "GAR-003":   ["CICD-SEC-9"],                # no cleanup policy
        "GCLOG-001": ["CICD-SEC-10"],               # audit logs not enabled
        "GCLOG-002": ["CICD-SEC-10"],               # no log sink
        "GCLOG-003": ["CICD-SEC-10"],               # log retention < 365 days
        # ── Azure Cloud phase-2 (network / app service / SQL / compute) ──
        "ENTRA-004": ["CICD-SEC-2"],                # cond access MFA
        "ENTRA-005": ["CICD-SEC-2"],                # ext user restrict
        "ENTRA-006": ["CICD-SEC-2"],                # risky signin
        "AZST-004":  ["CICD-SEC-9"],                # min TLS
        "AZST-005":  ["CICD-SEC-9"],                # lifecycle
        "AZST-006":  ["CICD-SEC-6", "CICD-SEC-2"],    # key rotation
        "AKV-004":   ["CICD-SEC-6", "CICD-SEC-9"],  # key expiry
        "AKV-005":   ["CICD-SEC-6", "CICD-SEC-9"],  # secret expiry
        "AKV-006":   ["CICD-SEC-2"],                # RBAC
        "ACR-004":   ["CICD-SEC-10", "CICD-SEC-9"],   # defender scan
        "ACR-005":   ["CICD-SEC-9"],                # tag immutability
        "AZMON-004": ["CICD-SEC-10"],               # KV diagnostics
        "AZMON-005": ["CICD-SEC-10"],               # NSG flow retention
        "AZMON-006": ["CICD-SEC-10"],               # LAW retention
        "AZMON-007": ["CICD-SEC-10"],               # svc health alert
        "AZNW-001":  ["CICD-SEC-7", "CICD-SEC-9"],    # SSH/RDP internet (CRITICAL)
        "AZNW-002":  ["CICD-SEC-10"],               # flow logs
        "AZNW-003":  ["CICD-SEC-7", "CICD-SEC-9"],    # WAF
        "AZNW-004":  ["CICD-SEC-7", "CICD-SEC-9"],  # deny-all
        "AZNW-005":  ["CICD-SEC-7", "CICD-SEC-9"],  # public IP VM
        "AZAPP-001": ["CICD-SEC-9"],                # HTTPS
        "AZAPP-002": ["CICD-SEC-9"],                # TLS
        "AZAPP-003": ["CICD-SEC-2"],                # managed identity
        "AZAPP-004": ["CICD-SEC-7", "CICD-SEC-9"],    # remote debug
        "AZAPP-005": ["CICD-SEC-7", "CICD-SEC-9"],  # FTP
        "AZSQL-001": ["CICD-SEC-9"],                # TDE CMK
        "AZSQL-002": ["CICD-SEC-10"],               # auditing
        "AZSQL-003": ["CICD-SEC-7", "CICD-SEC-9"],    # public access
        "AZSQL-004": ["CICD-SEC-2"],                # AAD admin
        "AZSQL-005": ["CICD-SEC-10"],               # threat detect
        "AZVM-001":  ["CICD-SEC-9"],                # disk encrypt
        "AZVM-002":  ["CICD-SEC-7", "CICD-SEC-9"],    # public IP
        "AZVM-003":  ["CICD-SEC-7", "CICD-SEC-9"],  # JIT
        "AZVM-004":  ["CICD-SEC-9"],                # OS patch
        "AZVM-005":  ["CICD-SEC-2"],                # managed identity
        # ── GCP phase-2 (network / compute / SQL / Cloud Run / KMS) ──
        "GCIAM-004": ["CICD-SEC-2"],                # default SA
        "GCIAM-005": ["CICD-SEC-2"],                # domain restrict
        "GCIAM-006": ["CICD-SEC-6", "CICD-SEC-2"],    # SA key age
        "GCS-004":   ["CICD-SEC-9"],                # CMEK
        "GCS-005":   ["CICD-SEC-10"],               # access logging
        "GCLOG-004": ["CICD-SEC-10"],               # VPC flow logs
        "GCLOG-005": ["CICD-SEC-10"],               # firewall logging
        "GCLOG-006": ["CICD-SEC-10"],               # data access
        "GCLOG-007": ["CICD-SEC-10"],               # metric filter IAM
        "GCLOG-008": ["CICD-SEC-10"],               # metric filter firewall
        "GCLOG-009": ["CICD-SEC-10"],               # metric filter route
        "GCLOG-010": ["CICD-SEC-10"],               # metric filter SQL
        "GCLOG-011": ["CICD-SEC-10"],               # metric filter custom role
        "GCNET-001": ["CICD-SEC-7", "CICD-SEC-9"],    # default network
        "GCNET-002": ["CICD-SEC-7", "CICD-SEC-9"],  # deny-all
        "GCNET-003": ["CICD-SEC-7", "CICD-SEC-9"],  # SSH/RDP (CRITICAL)
        "GCNET-004": ["CICD-SEC-7", "CICD-SEC-9"],  # private access
        "GCNET-005": ["CICD-SEC-7", "CICD-SEC-9"],  # Cloud NAT
        "GCCE-001":  ["CICD-SEC-9"],                # shielded VM
        "GCCE-002":  ["CICD-SEC-2"],                # OS Login
        "GCCE-003":  ["CICD-SEC-7", "CICD-SEC-9"],    # serial port
        "GCCE-004":  ["CICD-SEC-7", "CICD-SEC-9"],  # public IP
        "GCCE-005":  ["CICD-SEC-7", "CICD-SEC-2"],  # project SSH keys
        "GCSQL-001": ["CICD-SEC-7", "CICD-SEC-9"],  # public IP
        "GCSQL-002": ["CICD-SEC-9"],                # backups
        "GCSQL-003": ["CICD-SEC-9"],                # SSL
        "GCSQL-004": ["CICD-SEC-2"],                # IAM auth
        "GCSQL-005": ["CICD-SEC-9"],                # PITR
        "GCRUN-001": ["CICD-SEC-7", "CICD-SEC-9"],    # unauth
        "GCRUN-002": ["CICD-SEC-2"],                # custom SA
        "GCRUN-003": ["CICD-SEC-9"],                # min instances
        "GCRUN-004": ["CICD-SEC-7", "CICD-SEC-9"],    # VPC connector
        "GCKMS-004": ["CICD-SEC-2", "CICD-SEC-9"],  # keyring IAM
        "GCKMS-005": ["CICD-SEC-9"],                # destroy sched
        "GCKMS-006": ["CICD-SEC-9"],                # imported key
        # Developer-environment auto-execution
        "DEV-001":   ["CICD-SEC-4"],                # vscode folderOpen task
        "DEV-006":   ["CICD-SEC-4"],                # vscode settings exec-path / env injection
        "DEV-007":   ["CICD-SEC-4"],                # committed MCP config auto-launches a command server
        "DEV-002":   ["CICD-SEC-4"],                # devcontainer lifecycle
        "DEV-003":   ["CICD-SEC-4"],                # committed claude hook
        "DEV-004":   ["CICD-SEC-3", "CICD-SEC-4"],  # auto-run remote fetch+exec
        "DEV-005":   ["CICD-SEC-4", "CICD-SEC-7"],  # initializeCommand on host
    },
)
