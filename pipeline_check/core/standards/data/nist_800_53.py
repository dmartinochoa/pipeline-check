"""NIST SP 800-53 Rev. 5. CI/CD-relevant control subset.

800-53 is the federal security and privacy control catalog. This module
covers the controls whose evidence can be collected from CI/CD state,
spanning the AC (Access Control), AU (Audit & Accountability), CM
(Configuration Management), IA (Identification & Authentication), RA
(Risk Assessment), SA (System & Services Acquisition), SC (System &
Comm Protection), SI (System & Information Integrity), and SR (Supply
Chain Risk Management) families.

Controls for privacy (PT, PM), incident response (IR), personnel
security (PS), physical security (PE), and maintenance (MA) are out of
scope.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="nist_800_53",
    title="NIST SP 800-53 Rev. 5",
    version="Rev. 5",
    url="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    controls={
        # Access Control
        "AC-2":  "Account Management",
        "AC-3":  "Access Enforcement",
        "AC-6":  "Least Privilege",
        # Audit and Accountability
        "AU-2":  "Event Logging",
        "AU-9":  "Protection of Audit Information",
        "AU-11": "Audit Record Retention",
        "AU-12": "Audit Record Generation",
        # Configuration Management
        "CM-2":  "Baseline Configuration",
        "CM-6":  "Configuration Settings",
        "CM-7":  "Least Functionality",
        "CM-8":  "System Component Inventory",
        # Identification and Authentication
        "IA-5":  "Authenticator Management",
        # Risk Assessment
        "RA-5":  "Vulnerability Monitoring and Scanning",
        # System and Services Acquisition
        "SA-10": "Developer Configuration Management",
        "SA-11": "Developer Testing and Evaluation",
        "SA-15": "Development Process, Standards, and Tools",
        # System and Communications Protection
        "SC-7":  "Boundary Protection",
        "SC-8":  "Transmission Confidentiality and Integrity",
        "SC-12": "Cryptographic Key Establishment and Management",
        "SC-13": "Cryptographic Protection",
        "SC-28": "Protection of Information at Rest",
        # System and Information Integrity
        "SI-2":  "Flaw Remediation",
        "SI-7":  "Software, Firmware, and Information Integrity",
        # Supply Chain Risk Management
        "SR-3":  "Supply Chain Controls and Processes",
        "SR-4":  "Provenance",
        "SR-11": "Component Authenticity",
    },
    mappings={
        # ── Degraded-mode findings (API access failures) ────────
        # When the scanner cannot enumerate a provider surface, the
        # visibility gap surfaces as an audit-event gap — AU-2
        # (event logging) + AU-12 (audit-record generation) is the
        # natural home, mirroring the CIS SSCS / SSDF / OWASP /
        # ESF visibility-gap precedent.
        "CB-000":   ["AU-2", "AU-12"],
        "CP-000":   ["AU-2", "AU-12"],
        "CD-000":   ["AU-2", "AU-12"],
        "ECR-000":  ["AU-2", "AU-12"],
        "IAM-000":  ["AU-2", "AU-12"],
        "PBAC-000": ["AU-2", "AU-12"],
        "CT-000":   ["AU-2", "AU-12"],
        "CWL-000":  ["AU-2", "AU-12"],
        "EB-000":   ["AU-2", "AU-12"],
        "CA-000":   ["AU-2", "AU-12"],
        "CCM-000":  ["AU-2", "AU-12"],
        "LMB-000":  ["AU-2", "AU-12"],
        "KMS-000":  ["AU-2", "AU-12"],
        "SM-000":   ["AU-2", "AU-12"],
        "SSM-000":  ["AU-2", "AU-12"],
        "S3-000":   ["AU-2", "AU-12"],
        # CodeBuild
        "CB-001":   ["IA-5"],                            # plaintext secrets
        "CB-002":   ["CM-6", "CM-7"],                    # privileged mode
        "CB-003":   ["AU-2", "AU-12"],                   # no build logs
        "CB-004":   ["CM-6"],                            # no build timeout
        "CB-005":   ["CM-2", "SI-2", "RA-5"],            # outdated managed image
        "CB-006":   ["IA-5"],                            # long-lived source token
        "CB-007":   ["CM-6", "CM-7"],                    # webhook no filter
        "CB-008":   ["CM-2", "IA-5"],                    # inline buildspec, not from protected repo
        "CB-009":   ["SR-3", "SR-11", "SI-2"],           # build image not digest-pinned
        "CB-010":   ["CM-6", "AC-3"],                    # webhook accepts fork-PR unfiltered
        "CB-011":   ["SR-3", "RA-5"],                    # buildspec malicious-activity indicators
        # CodePipeline
        "CP-001":   ["SA-10", "SA-15"],                  # no manual approval
        "CP-002":   ["SC-12", "SC-13", "SC-28", "SI-7", "SR-4"], # artifact store not CMK
        "CP-003":   ["CM-6"],                            # polling source
        "CP-004":   ["IA-5"],                            # OAuth token source
        "CP-005":   ["SA-10", "SA-15"],                  # prod Deploy stage no manual approval
        "CP-007":   ["CM-6", "AC-3"],                    # v2 PR trigger accepts all branches
        # CodeDeploy
        "CD-001":   ["SA-10"],                           # no auto rollback
        "CD-002":   ["SA-10"],                           # AllAtOnce
        "CD-003":   ["AU-2", "AU-12"],                   # no CloudWatch alarm
        # ECR
        "ECR-001":  ["RA-5", "SI-2", "SA-11"],           # no scan on push
        "ECR-002":  ["CM-8", "SI-7", "SR-4", "SR-11"],   # mutable tags
        "ECR-003":  ["AC-3", "SC-7", "SR-3"],            # public repo policy
        "ECR-004":  ["CM-2", "CM-8"],                    # no lifecycle
        "ECR-005":  ["SC-12", "SC-13", "SC-28", "SR-4"], # AES256 not CMK
        "ECR-006":  ["SR-3", "SR-11"],                   # pull-through untrusted upstream
        "ECR-007":  ["RA-5", "SI-2", "SA-11"],           # Inspector v2 enhanced scanning
        # IAM
        "IAM-001":  ["AC-3", "AC-6"],
        "IAM-002":  ["AC-3", "AC-6"],
        "IAM-003":  ["AC-2", "AC-6"],
        "IAM-004":  ["AC-3", "AC-6"],
        "IAM-005":  ["AC-2", "AC-3"],                    # sts:ExternalId (confused deputy)
        "IAM-006":  ["AC-3", "AC-6"],
        "IAM-007":  ["IA-5"],                            # access key > 90 days
        "IAM-008":  ["AC-3", "IA-5"],                    # OIDC trust missing aud/sub pin
        "IAM-009":  ["AC-3", "IA-5"],                    # Azure WIF broad subject
        "IAM-010":  ["AC-3", "IA-5"],                    # GCP WIF no repo condition
        # PBAC
        "PBAC-001": ["SC-7"],                            # no VPC boundary
        "PBAC-002": ["AC-2", "AC-6"],                    # shared service role
        "PBAC-003": ["SC-7"],                            # SG 0.0.0.0/0 egress
        "PBAC-005": ["AC-6"],                            # stage roles mirror pipeline
        # S3 artifact bucket
        "S3-001":   ["AC-3", "SC-7", "AU-9"],
        "S3-002":   ["SC-12", "SC-13", "SC-28", "AU-9"],
        "S3-003":   ["SI-7", "AU-9"],
        "S3-004":   ["AU-2", "AU-12"],
        "S3-005":   ["SC-8", "AU-9"],
        # GitHub Actions
        "GHA-001":  ["SR-3", "SR-11", "SI-2", "RA-5"],   # unpinned action
        "GHA-110": ["CM-7", "SR-3"],  # CI env disables Go module verification
        "GHA-002":  ["CM-6", "SI-7", "SA-11"],           # pull_request_target + PR head
        "RUN-001":  ["CM-6", "SI-7", "SA-11"],           # forensics: fork PR ran on privileged trigger
        "RUN-002":  ["CM-6", "SI-7", "SA-11"],           # forensics: privileged trigger fired
        "RUN-003":  ["CM-6", "SI-7", "SA-11"],           # forensics: secret leaked in run logs
        "GHA-003":  ["CM-6", "SA-11", "SA-15"],          # script injection
        "GHA-117":  ["CM-6", "SA-11", "SA-15"],          # IaC apply on untrusted PR trigger
        "GHA-118":  ["CM-6", "SA-11", "SA-15"],          # untrusted content into $GITHUB_ENV / $GITHUB_PATH
        "GHA-004":  ["AC-6", "CM-6", "CM-7"],            # unrestricted GITHUB_TOKEN
        "GHA-005":  ["IA-5"],                            # long-lived AWS keys
        "GHA-006":  ["SI-7", "SR-4"],                    # unsigned artifacts
        "GHA-007":  ["SR-4", "CM-8"],                    # no SBOM
        "GHA-008":  ["IA-5"],                            # literal secrets in workflow
        "GHA-009":  ["SI-7", "SA-11"],                   # workflow_run upstream artifact unverified
        "GHA-010":  ["CM-6", "SA-11"],                   # local action on untrusted trigger
        "GHA-011":  ["CM-6", "SA-11"],                   # cache key tainted
        "GHA-012":  ["CM-6", "CM-7"],                    # self-hosted runner not ephemeral
        "GHA-105":  ["CM-6", "CM-7"],                    # self-hosted runner on PR trigger
        "GHA-013":  ["CM-6", "SA-11"],                   # issue_comment no author guard
        "GHA-014":  ["SA-10", "AC-3"],                   # deploy job missing environment
        "GHA-015":  ["CM-6"],                            # job has no timeout-minutes
        "GHA-016":  ["SR-3", "SR-11"],                   # remote script piped to shell
        "GHA-017":  ["SR-3", "SR-11"],                   # package install insecure source
        "GHA-018":  ["IA-5"],                            # GITHUB_TOKEN persisted to storage
        "GHA-019":  ["SR-3", "SR-11"],                   # install without lockfile
        "GHA-020":  ["RA-5", "SI-2"],                    # no vulnerability scanning
        "GHA-021":  ["SR-3", "SR-11", "SI-2"],           # dep-update bypasses lockfile pins
        "GHA-022":  ["SC-8", "SC-13"],                   # TLS / certificate verification bypass
        "GHA-023":  ["SR-3", "SR-11", "SI-2"],           # reusable workflow not SHA-pinned
        "GHA-024":  ["SI-7", "SR-4", "CM-2"],            # no SLSA provenance attestation
        "GHA-025":  ["SR-3", "SR-11", "SI-2"],           # unpinned reusable workflow
        "GHA-026":  ["CM-6", "CM-7"],                    # container job disables isolation
        "GHA-107":  ["CM-6", "CM-7"],                    # harden-runner in audit mode (egress not blocked)
        "GHA-108":  ["CM-6", "CM-7"],                    # no runtime egress control on OIDC/deploy workflow
        "GHA-109":  ["CM-6", "CM-7"],                    # harden-runner not the first step
        "GHA-027":  ["CM-6", "SA-11"],                   # dangerous shell idiom
        "GHA-028":  ["SR-3", "SR-11"],                   # install bypasses registry integrity
        "GHA-029":  ["SR-3", "SR-11"],                   # package source bypasses lockfile
        "GHA-030":  ["AC-3", "IA-5"],                    # OIDC w/o env-protected job
        "GHA-031":  ["CM-6", "SA-11"],                   # retired set-output / save-state
        "GHA-032":  ["CM-6", "SA-11"],                   # local script on untrusted trigger
        "GHA-033":  ["IA-5", "AU-9"],                    # secret echoed in run:
        "GHA-034":  ["AC-6", "IA-5"],                    # secrets: inherit
        "GHA-035":  ["CM-6", "SI-7", "SA-11"],           # github-script injection
        "GHA-036":  ["CM-6", "SA-11"],                   # runs-on untrusted context
        "GHA-037":  ["IA-5"],                            # checkout persists GITHUB_TOKEN
        "GHA-038":  ["CM-6", "SA-11"],                   # ACTIONS_ALLOW_UNSECURE_COMMANDS
        "GHA-039":  ["IA-5"],                            # services / container creds literal
        "GHA-040":  ["SR-3", "SR-11", "RA-5"],           # known-compromised action ref
        "GHA-041":  ["SR-3", "SR-11"],                   # single-maintainer action
        "GHA-042":  ["SR-3", "SR-11"],                   # very-young action repo
        "GHA-043":  ["SR-3", "SR-11", "AC-6"],           # low-star + sensitive perms
        "GHA-044":  ["CM-6", "SA-11"],                   # build-tool PPE on untrusted trigger
        "GHA-045":  ["CM-6", "SA-11"],                   # caller-ref input drives checkout
        "GHA-046":  ["CM-6", "SA-11"],                   # manual PR-head fetch
        "GHA-047":  ["SR-3", "SR-11"],                   # fresh-ref cooldown
        "GHA-048":  ["SI-7", "CM-6"],                    # workflow self-mutation
        "GHA-049":  ["AC-6", "IA-5"],                    # cross-repo push from CI
        "GHA-050":  ["IA-5", "AC-6"],                    # long-lived registry publish token
        "GHA-051":  ["SR-3", "SR-11", "SI-2"],           # services / container image unpinned
        "GHA-052":  ["CM-6", "SA-11"],                   # cache key untrusted-input poisoning
        "GHA-053":  ["CM-6", "SA-11"],                   # if: predicate untrusted-context
        "GHA-054":  ["IA-5"],                            # checkout ssh-key persists
        "GHA-055":  ["IA-5", "AU-9"],                    # reusable outputs leak secret
        "GHA-056":  ["SR-3", "RA-5"],                    # worm IOC strings
        "GHA-057":  ["IA-5", "SC-7"],                    # secret-scanner output → egress
        "GHA-058":  ["CM-6", "SA-11"],                   # agentic CLI permission-bypass
        "GHA-059":  ["SR-3", "SR-11", "SI-7"],            # npm install without audit signatures
        "GHA-060":  ["SR-3", "SR-11", "SI-7"],            # pip install without --require-hashes
        "GHA-061":  ["AC-6", "IA-5"],                     # App token minted without permissions filter
        "GHA-106":  ["AC-6", "IA-5"],                     # AI agent with write-scoped token
        "GHA-111":  ["AC-6", "IA-5"],  # AI agent edits IaC applied in the same job
        "GHA-112":  ["AC-3", "CM-7"],  # self-hosted deploy with no environment gate
        "GHA-113":  ["AC-3", "IA-5"],  # OIDC trusted-publish w/o env gate
        "GHA-114":  ["AC-3", "IA-5"],  # publish workflow on an unrestricted push trigger
        "GHA-115":  ["AC-6", "CM-7"],                     # id-token granted workflow-wide, not job-scoped
        "GHA-116":  ["AC-6", "IA-5"],                     # bulk secrets serialization
        "GHA-062":  ["AC-3", "AC-6"],                     # OIDC trust subject in sibling IaC is overly broad
        "GHA-063":  ["AC-3", "SI-7"],                     # spoofable bot-actor if-predicate
        "GHA-064":  ["SA-10", "AC-3"],                    # unsound contains() with comma-string operand
        "GHA-065":  ["SI-7", "SA-10"],                    # zero-width / bidi unicode in workflow body
        "GHA-066":  ["AU-9", "IA-5"],                     # upload-artifact wildcard sweeps workspace
        "GHA-067":  ["IA-5", "SC-28"],                    # cache step publishes credential-shaped paths
        "GHA-068":  ["SI-2", "CM-2"],                     # runs-on targets a deprecated hosted runner
        "GHA-069":  ["AC-6", "CM-7"],                     # orphan id-token: write scope
        "GHA-070":  ["SC-8", "IA-5"],                     # ssh-keyscan / host-key check TOFU
        "GHA-071":  ["SA-11"],                            # powershell on Linux / macOS step
        "GHA-072":  ["IA-5", "AC-6"],                     # secret env: at wider scope than consumer
        "GHA-073":  ["IA-5", "CM-7"],                     # unused workflow_call.secrets declaration
        "GHA-086":  ["SA-10", "AC-3"],                    # wildcard branch trigger + environment binding
        "GHA-087":  ["IA-5", "AU-9"],                     # derived-value of secret printed to log
        "GHA-088":  ["SR-3", "SR-11", "RA-5"],            # typosquat uses: near-edit of top action
        "GHA-089":  ["SR-3", "SR-11", "RA-5"],            # archived upstream repo
        "GHA-090":  ["SR-3", "SR-11", "RA-5", "SI-7"],    # impostor-commit: SHA absent from repo
        "GHA-091":  ["SR-3", "SR-11", "RA-5"],             # repojacking: action upstream missing
        "GHA-092":  ["CM-6", "SA-11", "SI-7"],             # TOCTOU PR head SHA force-push race
        "GHA-093":  ["IA-5", "AU-9"],                      # LOTP indicators
        "GHA-094":  ["SR-3", "SR-11"],                     # stale-action-refs
        "GHA-096":  ["SR-3", "SR-11", "RA-5"],           # known-vulnerable action ref (GHSA)
        # GitLab CI
        "GL-001":   ["SR-3", "SR-11", "SI-2"],
        "GL-037": ["CM-7", "SR-3"],  # CI env disables Go module verification
        "GL-002":   ["SI-7", "SA-11", "CM-6"],
        "GL-003":   ["IA-5"],
        "GL-004":   ["SA-10", "AC-3"],
        "GL-044":   ["SA-10", "AC-3"],                   # auto production deploy on an MR pipeline
        "GL-005":   ["SR-3", "SR-11", "CM-6"],
        "GL-042":   ["SR-3", "SR-11", "CM-6"],    # include: component unpinned
        "GL-006":   ["SI-7", "SR-4"],                    # unsigned artifacts
        "GL-007":   ["SR-4", "CM-8"],                    # no SBOM
        "GL-008":   ["IA-5"],                            # literal secrets
        "GL-009":   ["SR-3", "SR-11", "SI-2"],           # image not digest-pinned
        "GL-010":   ["SI-7", "SA-11"],                   # multi-project artifact unverified
        "GL-011":   ["CM-6", "SA-11"],                   # include: local on MR pipeline
        "GL-012":   ["CM-6", "SA-11"],                   # cache key tainted
        "GL-013":   ["IA-5"],                            # long-lived AWS keys
        "GL-014":   ["CM-6", "CM-7"],                    # self-managed runner not ephemeral
        "GL-015":   ["CM-6"],                            # no timeout
        "GL-016":   ["SR-3", "SR-11"],                   # remote script piped to shell
        "GL-017":   ["CM-6", "CM-7"],                    # docker privileged / host
        "GL-039":   ["CM-6", "CM-7"],                    # dind daemon TLS disabled / exposed on 2375
        "GL-018":   ["SR-3", "SR-11"],                   # package install insecure source
        "GL-019":   ["RA-5", "SI-2"],                    # no vulnerability scanning
        "GL-043":   ["RA-5", "SI-2"],                    # native security scanner disabled
        "GL-020":   ["IA-5"],                            # CI_JOB_TOKEN persisted
        "GL-021":   ["SR-3", "SR-11"],                   # install without lockfile
        "GL-022":   ["SR-3", "SR-11", "SI-2"],           # dep-update bypasses lockfile pins
        "GL-023":   ["SC-8", "SC-13"],                   # TLS bypass
        "GL-024":   ["SI-7", "SR-4", "CM-2"],            # no SLSA provenance
        "GL-025":   ["SR-3", "RA-5"],                    # malicious-activity indicators
        "GL-026":   ["CM-6", "SA-11"],                   # dangerous shell idiom
        "GL-027":   ["SR-3", "SR-11"],                   # install bypasses registry integrity
        "GL-028":   ["SR-3", "SR-11", "SI-2"],           # services: image not pinned
        "GL-029":   ["SA-10", "AC-3"],                   # manual deploy allow_failure
        "GL-030":   ["SR-3", "SR-11"],                   # trigger: include w/o pinned ref
        "GL-031":   ["AC-3", "IA-5"],                    # id_tokens missing audience pin
        "GL-040":   ["AC-3", "IA-5"],                    # CI_JOB_TOKEN used for cross-project access
        "GL-041":   ["CM-6", "SA-11", "SA-15"],          # IaC apply on an untrusted MR trigger
        "GL-032":   ["CM-6", "SA-11"],                   # tags interpolates untrusted
        "GL-033":   ["CM-6", "SA-11"],                   # global before_script taint
        "GL-034":   ["SR-3", "SR-11", "SI-7"],            # npm install without audit signatures
        "GL-035":   ["SR-3", "SR-11", "SI-7"],            # pip install without --require-hashes
        # Bitbucket Pipelines
        "BB-001":   ["SR-3", "SR-11", "SI-2"],
        "BB-002":   ["SI-7", "SA-11", "CM-6"],
        "BB-003":   ["IA-5"],
        "BB-004":   ["SA-10", "AC-3"],
        "BB-034":   ["SA-10", "AC-3"],                   # prod deploy on a PR pipeline
        "BB-033":   ["CM-6", "SA-11", "SA-15"],          # IaC apply on a PR pipeline
        "ADO-033":  ["CM-6", "SA-11", "SA-15"],          # IaC apply on a PR-validated pipeline
        "BK-016":   ["CM-6", "SA-11"],                   # dangerous shell idiom
        "JF-036":   ["CM-6", "SA-11"],                   # shell step interpolates params.*
        "BB-005":   ["CM-6"],
        "BB-006":   ["SI-7", "SR-4"],                    # unsigned artifacts
        "BB-007":   ["SR-4", "CM-8"],                    # no SBOM
        "BB-008":   ["IA-5"],                            # literal secrets
        "BB-009":   ["SR-3", "SR-11", "SI-2"],           # pipe not digest-pinned
        "BB-010":   ["SI-7", "SA-11"],                   # deploy step PR artifact unverified
        "BB-011":   ["IA-5"],                            # long-lived AWS keys
        "BB-012":   ["SR-3", "SR-11"],                   # remote script piped to shell
        "BB-013":   ["AC-6", "CM-7"],                    # docker privileged
        "BB-014":   ["SR-3", "SR-11"],                   # package install insecure source
        "BB-015":   ["RA-5", "SI-2"],                    # no vulnerability scanning
        "BB-016":   ["CM-6", "CM-7"],                    # self-hosted runner not ephemeral
        "BB-017":   ["IA-5"],                            # repo token persisted to storage
        "BB-018":   ["CM-6", "SA-11"],                   # cache key tainted
        "BB-019":   ["IA-5", "AU-9"],                    # after-script references secrets
        "BB-020":   ["IA-5"],                            # full clone depth exposes history
        "BB-021":   ["SR-3", "SR-11"],                   # install without lockfile
        "BB-022":   ["SR-3", "SR-11", "SI-2"],           # dep-update bypasses lockfile pins
        "BB-023":   ["SC-8", "SC-13"],                   # TLS bypass
        "BB-024":   ["SI-7", "SR-4", "CM-2"],            # no SLSA provenance
        "BB-025":   ["SR-3", "RA-5"],                    # malicious-activity indicators
        "BB-026":   ["CM-6", "SA-11"],                   # dangerous shell idiom
        "BB-027":   ["SR-3", "SR-11"],                   # install bypasses registry integrity
        "BB-028":   ["AC-3", "IA-5"],                    # OIDC step w/o env-gated deployment
        "BB-029":   ["SR-3", "SR-11", "SI-2"],           # step+service image pinning
        "BB-030":   ["SR-3", "SR-11", "SI-7"],            # npm install without audit signatures
        "BB-031":   ["SR-3", "SR-11", "SI-7"],            # pip install without --require-hashes
        # Azure DevOps Pipelines
        "ADO-001":  ["SR-3", "SR-11", "SI-2"],
        "ADO-002":  ["SI-7", "SA-11", "CM-6"],
        "ADO-003":  ["IA-5"],
        "ADO-004":  ["SA-10", "AC-3"],
        "ADO-005":  ["SR-3", "SR-11", "CM-2"],
        "ADO-006":  ["SI-7", "SR-4"],                    # unsigned artifacts
        "ADO-007":  ["SR-4", "CM-8"],                    # no SBOM
        "ADO-008":  ["IA-5"],                            # literal secrets
        "ADO-009":  ["SR-3", "SR-11", "SI-2"],           # container image not digest-pinned
        "ADO-010":  ["SI-7", "SA-11"],                   # cross-pipeline download unverified
        "ADO-011":  ["CM-6", "SA-11"],                   # template: local on PR-validated
        "ADO-012":  ["CM-6", "SA-11"],                   # Cache@2 PullRequest context
        "ADO-013":  ["CM-6", "CM-7"],                    # self-hosted pool not ephemeral
        "ADO-014":  ["IA-5"],                            # long-lived AWS keys
        "ADO-015":  ["CM-6"],                            # no timeoutInMinutes
        "ADO-016":  ["SR-3", "SR-11"],                   # remote script piped to shell
        "ADO-017":  ["AC-6", "CM-7"],                    # docker privileged
        "ADO-018":  ["SR-3", "SR-11"],                   # package install insecure source
        "ADO-019":  ["CM-6", "SA-11"],                   # extends template injection
        "ADO-020":  ["RA-5", "SI-2"],                    # no vulnerability scanning
        "ADO-021":  ["SR-3", "SR-11"],                   # install without lockfile
        "ADO-022":  ["SR-3", "SR-11", "SI-2"],           # dep-update bypasses lockfile pins
        "ADO-023":  ["SC-8", "SC-13"],                   # TLS bypass
        "ADO-024":  ["SI-7", "SR-4", "CM-2"],            # no SLSA provenance
        "ADO-025":  ["SR-3", "SR-11", "SI-2"],           # unpinned cross-repo template
        "ADO-026":  ["SR-3", "RA-5"],                    # malicious-activity indicators
        "ADO-027":  ["CM-6", "SA-11"],                   # dangerous shell idiom
        "ADO-028":  ["SR-3", "SR-11"],                   # install bypasses registry integrity
        "ADO-029":  ["SA-10", "AC-3"],                   # service-conn job w/o env gate
        "ADO-030":  ["CM-6", "SA-11"],                   # pool interpolates untrusted
        # CircleCI
        "CC-001":   ["SR-3", "SR-11", "SI-2", "RA-5"],  # orb not pinned to SHA
        "CC-033": ["CM-7", "SR-3"],  # CI env disables Go module verification
        "CC-002":   ["CM-6", "SA-11", "SA-15"],          # script injection
        "CC-003":   ["SR-3", "SR-11", "SI-2", "RA-5"],  # image not pinned to digest
        "CC-004":   ["IA-5"],                            # unrestricted context
        "CC-005":   ["IA-5"],                            # long-lived AWS keys
        "CC-006":   ["SI-7", "SR-4"],                    # unsigned artifacts
        "CC-007":   ["CM-8", "SR-4"],                    # no SBOM / provenance
        "CC-008":   ["IA-5"],                            # literal secrets in config
        "CC-009":   ["SA-10", "SA-15"],                  # no deployment approval
        "CC-010":   ["CM-6", "CM-7"],                    # self-hosted runner
        "CC-011":   ["AU-2", "AU-11", "AU-12"],          # no build retention
        "CC-012":   ["CM-6", "SA-11", "SA-15"],          # setup / dynamic config
        "CC-013":   ["SA-10"],                           # no branch filter
        "CC-014":   ["AC-6", "CM-6"],                    # resource class isolation
        "CC-015":   ["CM-6"],                            # no timeout
        "CC-016":   ["SR-3", "SR-11"],                   # curl | bash
        "CC-017":   ["CM-6", "CM-7"],                    # insecure Docker config
        "CC-018":   ["SR-3", "SR-11"],                   # insecure package source
        "CC-019":   ["IA-5"],                            # SSH key in config
        "CC-020":   ["RA-5", "SI-2"],                    # no vulnerability scanning
        "CC-021":   ["SR-3", "SR-11"],                   # no lockfile
        "CC-022":   ["SI-2", "SR-3"],                    # no dependency updates
        "CC-023":   ["SC-8"],                            # TLS verification bypass
        "CC-024":   ["SI-7", "SR-4", "CM-2"],            # no SLSA provenance
        "CC-025":   ["CM-6", "SA-11"],                   # cache key tainted
        "CC-026":   ["SR-3", "RA-5"],                    # malicious-activity indicators
        "CC-027":   ["CM-6", "SA-11"],                   # dangerous shell idiom
        "CC-028":   ["SR-3", "SR-11"],                   # install bypasses registry integrity
        "CC-029":   ["SR-3", "SR-11", "SI-2"],           # machine executor image not pinned
        "CC-030":   ["SA-10", "AC-3"],                   # job w/o branch filter / approval gate
        "CC-031":   ["AC-3", "IA-5"],                    # OIDC role w/o branch filter
        # Jenkins
        "JF-001":   ["SR-3", "SR-11"],                   # tools / agents not pinned
        "JF-004":   ["IA-5"],                            # plaintext credentials in Jenkinsfile
        "JF-008":   ["IA-5"],                            # literal secrets in Groovy
        "JF-010":   ["IA-5"],                            # long-lived AWS keys
        "JF-011":   ["AU-2", "AU-11", "AU-12"],          # build log retention
        "JF-015":   ["CM-6"],                            # no timeout
        "JF-033":   ["IA-5", "AU-9"],                    # withCredentials leaked via Groovy ${}
        "JF-034":   ["IA-5", "SC-28"],                   # password() build parameter
        "JF-035":   ["SC-8", "SC-13"],                   # httpRequest ignoreSslErrors
        "JF-002":   ["CM-6", "SA-11"],                   # script step untrusted env
        "JF-003":   ["AC-6", "CM-6"],                    # agent any (no executor isolation)
        "JF-005":   ["SA-10", "SA-15"],                  # deploy stage missing manual input
        "JF-006":   ["SI-7", "SR-4"],                    # artifacts not signed
        "JF-007":   ["SR-4", "CM-8"],                    # SBOM not produced
        "JF-009":   ["SR-3", "SR-11", "SI-2"],           # agent docker image not digest-pinned
        "JF-012":   ["SR-3", "SR-11", "SI-7"],           # load step pulls Groovy w/o integrity pin
        "JF-013":   ["SI-7", "SA-11"],                   # copyArtifacts ingests upstream unverified
        "JF-014":   ["CM-6", "CM-7"],                    # agent label missing ephemeral marker
        "JF-016":   ["SR-3", "SR-11"],                   # remote script piped to shell
        "JF-017":   ["AC-6", "CM-7"],                    # docker run privileged / host
        "JF-018":   ["SR-3", "SR-11"],                   # package install insecure source
        "JF-019":   ["CM-6", "SA-11"],                   # Groovy sandbox escape pattern
        "JF-020":   ["RA-5", "SI-2"],                    # no vulnerability scanning
        "JF-021":   ["SR-3", "SR-11"],                   # install without lockfile
        "JF-022":   ["SR-3", "SR-11", "SI-2"],           # dep-update bypasses lockfile pins
        "JF-023":   ["SC-8", "SC-13"],                   # TLS bypass
        "JF-024":   ["SA-10", "AC-3"],                   # input approval missing submitter restriction
        "JF-025":   ["AC-6", "CM-7"],                    # K8s agent pod privileged / hostPath
        "JF-026":   ["SA-10", "SA-15"],                  # build job: trigger ignores downstream failure
        "JF-027":   ["SR-4", "CM-8"],                    # archiveArtifacts no fingerprint
        "JF-028":   ["SI-7", "SR-4", "CM-2"],            # no SLSA provenance attestation
        "JF-029":   ["SR-3", "RA-5"],                    # malicious-activity indicators
        "JF-030":   ["CM-6", "SA-11"],                   # dangerous shell idiom
        "JF-031":   ["SR-3", "SR-11"],                   # install bypasses registry integrity
        "JF-032":   ["CM-6", "SA-11"],                   # agent label interpolates untrusted
        # ── Drone CI ─────────────────────────────────────────────
        "DR-001":   ["SR-3", "SR-11", "SI-2"],           # step image not digest-pinned
        "DR-002":   ["AC-6", "CM-7"],                    # privileged step
        "DR-003":   ["CM-6", "SA-11"],                   # Drone variable injection
        "DR-004":   ["IA-5"],                            # literal credential
        "DR-005":   ["SR-3", "SR-11", "SI-2"],           # plugin floating tag
        "DR-006":   ["SC-8", "SC-13"],                   # TLS bypass in commands
        "DR-007":   ["SC-7", "AC-6", "SI-7"],            # sensitive host-path mount
        "DR-008":   ["SR-3", "SR-11"],                   # pull: never (skips registry verify)
        "DR-009":   ["CM-6", "SA-11"],                   # cache key tainted
        "DR-010":   ["SR-3", "SR-11"],                   # unpinned package install
        "DR-011":   ["CM-6", "SA-11"],                   # node map interpolates untrusted
        # ── Drone extended pack ──
        "DR-012":   ["SR-3", "SR-11"],                   # service image not pinned
        "DR-013":   ["AC-6", "CM-7"],                    # no trigger event filter
        "DR-014":   ["SI-7", "CM-7"],                    # pipe-to-shell
        "DR-015":   ["SI-7", "CM-7"],                    # clone recursive
        "DR-016":   ["CM-7", "SI-7"],                    # image field interpolation
        "DR-017":   ["CM-6", "SA-11"],                   # dangerous shell idiom
        # Cloud Build
        "GCB-001":  ["SR-3", "SR-11", "SI-2", "RA-5"],   # step image not digest-pinned
        "GCB-002":  ["AC-3", "AC-6"],                    # default service account
        "GCB-003":  ["IA-5"],                            # secrets fetched in args
        "GCB-004":  ["SR-3", "SR-11", "SI-2"],           # community step not SHA-pinned
        "GCB-005":  ["CM-6"],                            # no timeout
        "GCB-006":  ["CM-6", "SA-11"],                   # shell-eval idiom
        "GCB-007":  ["CM-2", "SR-4"],                    # rolling 'latest' secret version
        "GCB-008":  ["RA-5", "SI-2", "SA-11"],           # no vuln scanning
        "GCB-009":  ["SI-7", "SR-4"],                    # unsigned artifact
        "GCB-010":  ["SR-3", "SR-11"],                   # remote script via curl-pipe
        "GCB-011":  ["SC-8"],                            # TLS bypass
        "GCB-012":  ["IA-5"],                            # literal secret in YAML
        "GCB-013":  ["SR-3", "SR-11"],                   # package source integrity
        "GCB-014":  ["AU-2", "AU-12", "AU-9"],           # logging disabled
        "GCB-015":  ["SR-4", "CM-8"],                    # no SBOM
        "GCB-016":  ["CM-6", "AC-6"],                    # dir path escape
        "GCB-017":  ["SR-4", "SI-7", "CM-2"],            # no SLSA provenance
        "GCB-018":  ["IA-5", "CM-2"],                    # legacy KMS secrets block
        "GCB-019":  ["CM-6", "SA-11"],                   # shell entrypoint + user substitution
        "GCB-020":  ["AC-3", "AC-6"],                    # default Cloud Build SA email
        "GCB-021":  ["SC-7"],                            # no private worker pool
        "GCB-022":  ["CM-6", "SA-11"],                   # substitutionOption ALLOW_LOOSE
        "GCB-023":  ["CM-6", "SA-11"],                   # undeclared user substitution
        "GCB-024":  ["SR-4", "CM-8"],                    # images: missing
        "GCB-025":  ["AU-2", "SI-2"],                    # tags: empty
        "GCB-026":  ["CM-6"],                            # waitFor unknown id
        "GCB-027":  ["SR-3", "RA-5"],                    # malicious-activity indicators
        # Kubernetes, runtime configuration evidences SC-7 (boundary
        # protection), CM-6/CM-7 (least functionality), AC-3/AC-6
        # (least privilege), AU-2/AU-12 (audit), SC-28 (data at rest).
        "K8S-001":  ["SR-3", "SR-11", "SI-2"],           # image not digest-pinned
        "K8S-002":  ["SC-7", "CM-7"],                    # hostNetwork: true
        "K8S-003":  ["SC-7", "CM-7"],                    # hostPID: true
        "K8S-004":  ["SC-7", "CM-7"],                    # hostIPC: true
        "K8S-005":  ["AC-6", "CM-6", "CM-7"],            # privileged container
        "K8S-006":  ["AC-6", "CM-6"],                    # allowPrivilegeEscalation
        "K8S-007":  ["AC-6", "CM-6"],                    # runAsNonRoot
        "K8S-008":  ["SC-28", "CM-6"],                   # readOnlyRootFilesystem
        "K8S-009":  ["AC-6", "CM-7"],                    # capabilities
        "K8S-010":  ["CM-6", "SI-7"],                    # seccompProfile missing
        "K8S-011":  ["AC-2", "AC-6"],                    # default service account
        "K8S-012":  ["AC-6", "CM-7"],                    # automountServiceAccountToken
        "K8S-013":  ["SC-7", "AC-6", "SI-7"],            # hostPath volumes
        "K8S-014":  ["SC-7", "AC-6", "SI-7"],            # sensitive hostPath
        "K8S-015":  ["CM-6"],                            # no memory limit
        "K8S-016":  ["CM-6"],                            # no CPU limit
        "K8S-017":  ["IA-5"],                            # credential literals in env
        "K8S-018":  ["IA-5", "SC-28"],                   # Secret carries plaintext
        "K8S-019":  ["CM-6"],                            # default namespace
        "K8S-020":  ["AC-3", "AC-6"],                    # cluster-admin binding
        "K8S-021":  ["AC-3", "AC-6", "CM-7"],            # wildcard RBAC
        "K8S-022":  ["SC-7", "CM-7"],                    # service exposes SSH
        "K8S-023":  ["AC-6", "CM-6"],                    # PSA enforce label missing
        "K8S-044":  ["AC-6", "CM-6"],                    # admission webhook fail-open / unscoped mutating
        "K8S-024":  ["AU-2", "SI-2"],                    # missing health probes
        "K8S-025":  ["AC-6", "CM-7"],                    # system-* priority class
        "K8S-026":  ["SC-7", "AC-3"],                    # LB without source ranges
        "K8S-027":  ["SC-8", "SC-13"],                   # Ingress without TLS
        "K8S-028":  ["SC-7", "CM-7"],                    # container hostPort
        "K8S-029":  ["AC-3", "AC-6"],                    # default-SA binding
        "K8S-030":  ["AC-6", "SC-7", "CM-7"],            # control-plane scheduling
        "K8S-031":  ["CM-6", "AC-6"],                    # PSA warn missing
        "K8S-032":  ["SC-7", "AC-3"],                    # NetworkPolicy default-deny missing
        "K8S-033":  ["CM-6", "SI-2"],                    # ResourceQuota / LimitRange missing
        "K8S-034":  ["AC-6", "AC-2"],                    # ServiceAccount automount default
        "K8S-035":  ["AC-6", "CM-6"],                    # runAsUser: 0
        "K8S-036":  ["SR-3", "SR-11", "SI-7"],           # SA imagePullSecret missing
        "K8S-037":  ["IA-5", "SC-28"],                   # ConfigMap credential literal
        "K8S-038":  ["SC-7", "AC-3"],                    # NetworkPolicy allow-all
        "K8S-039":  ["AC-6", "CM-6"],                    # shareProcessNamespace
        "K8S-040":  ["AC-6", "CM-6"],                    # procMount: Unmasked
        "K8S-041":  ["SC-7", "AC-3"],                    # Service externalIPs (CVE-2020-8554)
        "K8S-042":  ["AC-2", "AC-3", "AC-6"],            # anonymous RoleBinding
        "K8S-043":  ["SC-7", "CM-6"],                    # Ingress wildcard host
        # Helm chart-supply-chain. The same SR family that covers
        # image pinning (K8S-001 / DF-001) covers chart pinning;
        # SC-8 (transmission integrity) covers HELM-003's plaintext
        # repo URL. SR-3, supply chain controls. SR-11, component
        # authenticity (the Chart.lock digest is the authenticity
        # signal). SI-2, flaw remediation hooks on the schema lock.
        "HELM-001": ["SR-3", "CM-2"],                    # legacy v1 schema
        "HELM-002": ["SR-3", "SR-11", "SI-7"],           # Chart.lock digest
        "HELM-003": ["SR-3", "SC-8", "SC-13"],           # non-HTTPS dep repo
        "HELM-004": ["SR-3", "SR-11", "SI-2"],           # version not exact-pinned
        "HELM-005": ["SR-3", "SR-4"],                    # maintainers chain-of-custody
        "HELM-006": ["CM-2", "CM-6"],                    # kubeVersion compat range
        "HELM-007": ["SR-3"],                            # description (chain-of-custody)
        "HELM-008": ["SR-3", "SI-2"],                    # Chart.lock stale (flaw remediation cadence)
        "HELM-009": ["SR-3", "SC-8"],                    # home / sources non-HTTPS
        "HELM-010": ["CM-2"],                            # appVersion (config baseline)
        # ── Helm extended pack ──
        "HELM-011": ["IA-5", "SC-28"],                   # dependency URL embedded creds
        "HELM-012": ["CM-2", "SI-2"],                    # deprecated without successor
        "HELM-013": ["CM-2"],                            # invalid chart type
        "HELM-014": ["SI-2", "SR-3"],                    # known-compromised dep
        "HELM-015": ["CM-7", "SR-3"],  # oci:// dependency not digest-pinned
        "HELM-016": ["IA-5", "SC-28"],  # default secret in values.yaml
        "HELM-017": ["CM-7"],  # tpl of an untrusted .Values value
        # Buildkite, pipeline-config posture maps to the same SR /
        # CM / IA families as the other CI providers' rules.
        "BK-001":   ["SR-3", "SR-11", "SI-2"],           # plugin not pinned
        "BK-002":   ["IA-5", "SC-28"],                   # secret in env
        "BK-003":   ["CM-6", "SA-11"],                   # untrusted variable injection
        "BK-004":   ["SR-3", "SR-11", "SI-7"],           # curl | bash
        "BK-005":   ["AC-6", "CM-7"],                    # Docker privileged
        "BK-006":   ["AU-2", "SI-2"],                    # no timeout
        "BK-007":   ["AC-3", "SA-10"],                   # deploy not gated
        "BK-008":   ["SC-8", "SC-13"],                   # TLS bypass
        "BK-009":   ["SI-7", "SR-4"],                    # artifacts not signed
        "BK-010":   ["SR-4", "CM-8"],                    # no SBOM
        "BK-011":   ["SI-7", "SR-4", "CM-2"],            # no SLSA provenance
        "BK-012":   ["RA-5", "SI-2"],                    # no vuln scanning
        "BK-013":   ["AC-3"],                            # deploy without branch filter
        "BK-014":   ["SR-3", "SR-11"],                   # unpinned package install
        "BK-015":   ["CM-6", "SA-11"],                   # agents map untrusted interpolation
        # Tekton. Kubernetes-native pipeline kinds.
        "TKN-001":  ["SR-3", "SR-11", "SI-2"],           # step image not digest-pinned
        "TKN-016": ["SR-3", "SR-11", "SI-2"],  # remote resolver / bundle task body not pinned
        "TKN-002":  ["AC-6", "CM-7"],                    # step privileged
        "TKN-003":  ["CM-6", "SA-11"],                   # param injection
        "TKN-004":  ["SC-7", "AC-6", "SI-7"],            # hostPath / host namespaces
        "TKN-005":  ["IA-5", "SC-28"],                   # leaked creds
        "TKN-006":  ["AU-2", "SI-2"],                    # no timeout
        "TKN-007":  ["AC-2", "AC-6"],                    # default ServiceAccount
        "TKN-008":  ["SR-3", "SR-11", "SC-8", "SI-7"],   # remote install / TLS
        "TKN-009":  ["SI-7", "SR-4"],                    # artifacts not signed
        "TKN-010":  ["SR-4", "CM-8"],                    # no SBOM
        "TKN-011":  ["SI-7", "SR-4", "CM-2"],            # no SLSA provenance
        "TKN-012":  ["RA-5", "SI-2"],                    # no vuln scanning
        "TKN-013":  ["AC-6", "CM-7"],                    # sidecar privileged
        "TKN-014":  ["SR-3", "SR-11"],                   # unpinned package install
        "TKN-015":  ["CM-6", "SA-11"],                   # workspace subPath param injection
        # Argo Workflows
        "ARGO-001": ["SR-3", "SR-11", "SI-2"],           # template image not pinned
        "ARGO-002": ["AC-6", "CM-7"],                    # template privileged
        "ARGO-003": ["AC-2", "AC-6"],                    # default SA
        "ARGO-016": ["AC-2", "AC-6"],                    # cluster-admin / over-privileged ServiceAccount
        "ARGO-004": ["SC-7", "AC-6", "SI-7"],            # hostPath / namespaces
        "ARGO-005": ["CM-6", "SA-11"],                   # parameter injection
        "ARGO-017": ["CM-6", "SA-11"],                   # resource template manifest injection
        "ARGO-006": ["IA-5", "SC-28"],                   # leaked creds
        "ARGO-007": ["AU-2", "SI-2"],                    # no activeDeadlineSeconds
        "ARGO-008": ["SR-3", "SR-11", "SC-8", "SI-7"],   # remote install / TLS
        "ARGO-009": ["SI-7", "SR-4"],                    # artifacts not signed
        "ARGO-010": ["SR-4", "CM-8"],                    # no SBOM
        "ARGO-011": ["SI-7", "SR-4", "CM-2"],            # no SLSA provenance
        "ARGO-012": ["RA-5", "SI-2"],                    # no vuln scanning
        "ARGO-013": ["AC-6", "IA-5"],                    # SA token automount
        "ARGO-014": ["SR-3", "SR-11"],                   # unpinned package install
        "ARGO-015": ["SC-8", "SI-7"],                    # insecure (non-HTTPS) artifact URL
        # ── Argo CD (GitOps deployment) ──
        "ARGOCD-010": ["CM-7", "SR-3"],                  # mutable targetRevision
        "ARGOCD-017": ["CM-7", "SR-3"],  # in-cluster mutable source
        "ARGOCD-019": ["CM-7", "SR-3"],  # drift detection disabled on a sensitive field
        "ARGOCD-016": ["CM-7", "SR-3"],  # Helm valueFiles from a remote URL
        "ARGOCD-018": ["CM-7", "SR-3"],  # custom resource health / action Lua
        "ARGOCD-011": ["AC-6", "CM-7"],                  # cluster-resource wildcard
        "ARGOCD-012": ["CM-6", "AU-2"],                  # no sync windows
        "ARGOCD-013": ["AU-11"],                         # no revision history cap
        # Dockerfile, image build choices evidence supply-chain (SR)
        # and configuration (CM) controls primarily.
        "DF-001":   ["SR-3", "SR-11", "SI-2"],           # FROM not digest-pinned
        "DF-031":   ["SR-3", "SR-11", "SI-2"],           # COPY --from external image not digest-pinned
        "DF-002":   ["AC-6", "CM-6"],                    # no USER
        "DF-003":   ["SR-3", "SR-11", "SI-7"],           # ADD URL no checksum
        "DF-004":   ["SR-3", "SR-11", "SI-7"],           # curl-pipe
        "DF-005":   ["CM-6", "SA-11"],                   # shell-eval
        "DF-006":   ["IA-5"],                            # secret in ENV/ARG
        "DF-007":   ["SI-2", "AU-2"],                    # no HEALTHCHECK
        "DF-008":   ["AC-6", "CM-7"],                    # privileged in RUN
        "DF-009":   ["CM-6"],                            # ADD where COPY suffices
        "DF-010":   ["CM-2", "SR-3", "SI-2"],            # apt dist-upgrade
        "DF-011":   ["CM-6"],                            # apt cache not cleaned
        "DF-012":   ["AC-6", "CM-6"],                    # sudo in RUN
        "DF-013":   ["SC-7", "CM-7"],                    # EXPOSE 22
        "DF-014":   ["CM-6", "AC-6"],                    # WORKDIR system path
        "DF-015":   ["AC-6", "CM-6"],                    # chmod 777
        "DF-016":   ["SR-4", "CM-8"],                    # OCI provenance labels
        "DF-017":   ["AC-6", "CM-6"],                    # ENV PATH writable prefix
        "DF-018":   ["AC-6", "CM-6"],                    # RUN chown system path
        "DF-019":   ["IA-5", "SC-28"],                   # COPY/ADD credential-shaped file
        "DF-020":   ["IA-5", "AU-2"],                    # ARG credential-shaped name
        "DF-021":   ["SC-8", "SC-13", "SR-3"],           # pip install TLS bypass / http index
        "DF-022":   ["SR-3", "SR-11", "CM-2"],           # npm install (no lockfile enforcement)
        "DF-023":   ["CM-6", "AC-6"],                    # ENV LD_PRELOAD / LD_LIBRARY_PATH
        "DF-024":   ["CM-6", "CM-7"],                    # npm install runs lifecycle scripts
        "DF-025":   ["IA-5", "SC-28"],                   # registry token in image layer
        "DF-026":   ["SC-8", "SC-13"],                   # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027":   ["SC-8", "SC-13"],                   # PYTHONHTTPSVERIFY=0
        "DF-028":   ["SC-8", "SC-13"],                   # GIT_SSL_NO_VERIFY=1
        "DF-029":   ["SC-8", "SC-13"],                   # REQUESTS_CA_BUNDLE neutered
        "DF-030":   ["CM-6", "CM-7"],                    # NODE_OPTIONS --require / --inspect
        # Additional AWS services not previously mapped.
        "KMS-001":  ["SC-12", "SC-13"],                  # CMK rotation disabled
        "KMS-002":  ["AC-3", "AC-6"],                    # CMK policy wildcard
        "CT-001":   ["AU-2", "AU-12", "AU-9"],           # no trail
        "CT-002":   ["AU-9", "SI-7"],                    # log file validation off
        "CT-003":   ["AU-2", "AU-12"],                   # not multi-region
        "CWL-001":  ["AU-2", "AU-11"],                   # no log retention
        "CWL-002":  ["AU-9", "SC-12", "SC-28"],          # logs not KMS-encrypted
        "CW-001":   ["AU-2", "SI-2"],                    # failed-build alarm
        "SM-001":   ["IA-5", "SC-12"],                   # secret rotation off
        "SM-002":   ["AC-3", "SC-7"],                    # secret resource policy public
        "SSM-001":  ["IA-5"],                            # SSM string not SecureString
        "SSM-002":  ["SC-12", "SC-13"],                  # SSM default KMS key
        "SIGN-001": ["SI-7", "SR-4"],                    # signing profile missing
        "SIGN-002": ["SI-7", "SR-4"],                    # signing profile revoked
        "LMB-001":  ["SI-7", "SR-4"],                    # Lambda code-signing config
        "LMB-002":  ["AC-3"],                            # function URL no auth
        "LMB-003":  ["IA-5"],                            # Lambda env plaintext secret
        "LMB-004":  ["AC-3", "SC-7"],                    # Lambda resource policy public
        "EB-001":   ["AU-2", "SI-2"],                    # no pipeline-failure rule
        "EB-002":   ["AC-6"],                            # wildcard event target
        "CCM-001":  ["SA-10", "AC-3"],                   # CodeCommit approval rules
        "CCM-002":  ["SC-12", "SC-28"],                  # CodeCommit repo not KMS
        "CCM-003":  ["AC-3", "SC-7"],                    # cross-account trigger
        "CA-001":   ["SC-12", "SC-13"],                  # CodeArtifact domain encryption
        "CA-002":   ["SR-3", "SR-11"],                   # public upstream repo
        "CA-003":   ["AC-3", "SC-7"],                    # domain policy public
        "CA-004":   ["AC-6"],                            # repo wildcard actions
        # ── NPM / PyPI / Maven dep supply-chain ──────────────────
        # Pinning + integrity + non-registry sources land on SR-3
        # (supply chain controls) + SR-11 (component authenticity)
        # + SI-2 (flaw remediation cadence). Compromised packages
        # add RA-5 (vuln monitoring). Lifecycle / ignore-scripts
        # land on CM-6 + CM-7 (config + least functionality).
        # Secrets in files land on IA-5.
        "NPM-001":  ["SR-3", "SR-11", "SI-2"],           # floating range
        "NPM-002":  ["SR-3", "SR-11", "SI-7"],           # lock entry missing integrity
        "NPM-003":  ["SR-3", "SR-11"],                   # non-registry source
        "NPM-004":  ["CM-6", "CM-7"],                    # install-time lifecycle script
        "NPM-005":  ["SR-3", "SR-11", "SI-2"],           # git dep mutable ref
        "NPM-006":  ["SR-3", "SR-11", "RA-5"],           # compromised npm version
        "NPM-007":  ["CM-6", "CM-7"],                    # .npmrc ignore-scripts
        "NPM-011":  ["IA-5"],                            # secret-shaped paths in files field
        "NPM-013":  ["IA-5", "AC-3"],                    # broad files-field publishes everything
        "PYPI-001": ["SR-3", "SR-11", "SI-2"],           # missing ==pin
        "PYPI-002": ["SR-3", "SR-11", "SI-7"],           # hash pinning missing
        "PYPI-003": ["SR-3", "SR-11", "SC-8"],           # http index / --trusted-host
        "PYPI-018": ["SR-3", "SR-11", "SC-8"],  # --no-binary forces sdist build
        "PYPI-019": ["SR-3", "SR-11", "RA-5"],  # missing PEP 740 build provenance
        "PYPI-020": ["SR-3", "SR-11", "RA-5"],  # low OpenSSF Scorecard upstream
        "PYPI-021": ["SR-3", "SR-11", "RA-5"],  # provenance built from a non-release ref
        "PYPI-004": ["SR-3", "SR-11", "SI-2"],           # VCS dep without commit SHA
        "PYPI-015": ["SR-3", "SR-11", "SI-2"],  # direct artifact URL
        "PYPI-005": ["SR-3", "SR-11"],                   # --extra-index-url (dep confusion)
        "PYPI-017": ["SR-3", "SR-11"],  # remote --find-links
        "PYPI-016": ["SR-3", "SR-11"],  # primary index repointed
        "PYPI-006": ["SR-3", "SR-11", "RA-5"],           # compromised PyPI version
        "MVN-001":  ["SR-3", "SR-11", "SI-2"],           # floating Maven range
        "MVN-002":  ["SR-3", "SR-11", "SI-2"],           # mutable SNAPSHOT dep
        "MVN-003":  ["SR-3", "SR-11", "SC-8"],           # plaintext-HTTP repository
        "MVN-004":  ["SR-3", "SR-11"],                   # missing <version>
        "MVN-005":  ["SR-3", "SR-11", "SI-7"],           # lax checksumPolicy
        "MVN-006":  ["SR-3", "SR-11", "RA-5"],           # compromised Maven version
        "MVN-007":  ["SR-3", "SR-11"],                   # settings.xml wildcard mirror
        "MVN-008":  ["SR-3", "SR-11", "RA-5"],           # cooldown gate (--resolve-remote)
        "MVN-009":  ["SR-3", "SR-11", "RA-5"],           # OSV advisory (--resolve-remote)
        # ── Maven extended pack ──
        "MVN-010":  ["IA-5", "SC-28"],                   # plaintext server password
        "MVN-011":  ["IA-5", "SC-28"],                   # repo URL credentials
        "MVN-012":  ["CM-7", "SR-3"],                    # build plugin floating
        "MVN-013":  ["CM-7", "SR-3"],                    # build extension floating
        "MVN-014":  ["SI-7", "CM-7"],                    # wrapper sha256 missing
        "MVN-015": ["CM-7", "SR-3"],  # build-time plugin exec bound to lifecycle
        "MVN-016": ["CM-7", "SR-3"],  # gradle allowInsecureProtocol
        "MVN-017": ["IA-5", "SC-28"],  # settings.xml privateKey + plaintext passphrase
        "MVN-018": ["CM-7", "SR-3"],  # distributionManagement release accepts snapshots
        "NPM-008":  ["SR-3", "SR-11", "RA-5"],           # cooldown gate (--resolve-remote)
        "NPM-009":  ["SR-3", "SR-11"],                   # new-transitive-dep diff gate
        "NPM-010":  ["SR-3", "SR-11", "RA-5"],           # OSV advisory (--resolve-remote)
        "NPM-014":  ["SR-3", "SR-11", "RA-5"],           # single-publisher risk
        "NPM-015":  ["SR-3", "SR-11", "RA-5"],           # missing build provenance
        "NPM-017":  ["SR-3", "SR-11", "RA-5"],           # provenance built from a non-release ref
        "NPM-018":  ["SR-3", "SR-11", "RA-5"],           # latest release from a new publisher
        "NPM-019":  ["SR-3", "SR-11", "RA-5"],           # overrides / resolutions redirect
        "NPM-020":  ["SR-3", "SR-11", "RA-5"],           # .npmrc registry repoint
        "NPM-016":  ["SR-3", "SR-11", "RA-5"],           # low OpenSSF Scorecard
        "PYPI-008": ["SR-3", "SR-11", "RA-5"],           # cooldown gate (--resolve-remote)
        "PYPI-009": ["SR-3", "SR-11", "RA-5"],           # OSV advisory (--resolve-remote)
        # ── PyPI extended pack (PYPI-010..014) ──
        "PYPI-010": ["IA-5", "SC-28"],                   # index URL embedded credentials
        "PYPI-011": ["SC-8", "SC-13"],                   # --trusted-host disables TLS
        "PYPI-012": ["CM-7", "SI-7"],                    # build-system requires floating
        "PYPI-013": ["CM-7"],                            # pyproject dynamic dependencies
        "PYPI-014": ["SC-8"],                            # custom source HTTP
        # ── nuget (dep supply-chain) ─────────────────────────────
        "NUGET-001": ["SR-3", "SR-11", "SI-2"],          # floating NuGet version range
        "NUGET-002": ["SR-3", "SR-11", "SI-2"],          # wildcard prerelease version
        "NUGET-003": ["SR-3", "SR-11"],                  # missing explicit version
        "NUGET-004": ["SR-3", "SR-11", "SC-8"],          # HTTP-only package source
        "NUGET-005": ["SR-3", "SR-11", "RA-5"],          # known-compromised package version
        "NUGET-006": ["SR-3", "SR-11", "SI-7"],          # no lock file for reproducible restores
        "NUGET-007": ["SR-3", "SR-11"],                  # multiple sources without packageSourceMapping
        "NUGET-008": ["SR-3", "SR-11", "RA-5"],          # cooldown gate (--resolve-remote)
        "NUGET-009": ["SR-3", "SR-11", "RA-5"],          # OSV advisory (--resolve-remote)
        "NUGET-010": ["IA-5", "AC-3"],                   # NuGet.config cleartext feed credential
        # ── NuGet extended pack ──
        "NUGET-011": ["CM-7", "SR-3"],                   # source mapping wildcard
        "NUGET-012": ["SI-7"],                           # signature validation off
        "NUGET-013": ["CM-7", "SR-3"],                   # dotnet-tools unpinned
        "NUGET-014": ["IA-5", "SC-28"],                  # source URL credentials
        "NUGET-015": ["CM-6"],                           # VersionOverride breaks CPM
        "NUGET-016": ["CM-7", "SR-3"],                   # missing <clear/> inherits public gallery
        "NUGET-017": ["CM-7", "SR-3"],  # public gallery active alongside private feed, not disabled
        "NUGET-018": ["CM-7", "SR-3"],                   # build-time MSBuild execution
        "NUGET-019": ["SI-7"],                           # require mode, no trusted signers
        # ── Go modules (GOMOD-001..006) ─────────────────────────
        "GOMOD-001": ["SI-7", "CM-7"],                   # go.sum integrity manifest missing
        "GOMOD-002": ["CM-7", "SR-3"],                  # replace directive to local path
        "GOMOD-003": ["CM-7", "SR-3"],                  # replace directive to different module
        "GOMOD-004": ["SI-2"],                           # +incompatible direct require
        "GOMOD-005": ["CM-6"],                           # missing go toolchain directive
        "GOMOD-006": ["SI-2", "SR-3"],                  # known-compromised module version
        # ── Go modules extended pack ──
        "GOMOD-007": ["SI-7", "CM-7"],                   # vendor/modules.txt stale
        "GOMOD-008": ["CM-7", "SR-3"],                   # replace without version pin
        "GOMOD-009": ["CM-7"],                           # pre-release direct require
        "GOMOD-010": ["CM-7"],                           # stale exclude directive
        "GOMOD-011": ["CM-7"],  # tool directive build-time exec
        "GOMOD-012": ["CM-7"],  # insecure / non-canonical module host
        # ── Cargo (CARGO-001..006) ─────────────────────────────
        "CARGO-001": ["CM-7"],                           # floating Cargo.toml version spec
        "CARGO-002": ["CM-7", "SR-3"],                  # git dep with mutable ref (no rev)
        "CARGO-003": ["SI-7", "CM-7"],                   # missing Cargo.lock
        "CARGO-004": ["CM-7", "SR-3"],                  # local-path Cargo dependency
        "CARGO-005": ["CM-7", "SR-3"],                  # alternate-registry Cargo dependency
        "CARGO-006": ["SI-2", "SR-3"],                  # known-compromised crate version
        # ── Cargo extended pack ──
        "CARGO-007": ["CM-7", "SR-3"],                   # build-deps floating
        "CARGO-008": ["CM-7", "SR-3"],                   # patch.crates-io substitution
        "CARGO-009": ["CM-7"],                           # workspace deps floating
        "CARGO-010": ["CM-6"],                           # missing rust-version
        "CARGO-011": ["CM-7"],  # build.rs compile-time egress / exec
        "CARGO-012": ["CM-7"],  # .cargo/config.toml source override / build flags
        "CARGO-013": ["CM-7"],  # Cargo.lock off-crates.io source
        "CARGO-014": ["CM-7"],  # no supply-chain audit-gate config
        # ── Composer / PHP ──
        "COMPOSER-001": ["SR-3", "CM-8"],                # missing composer.lock
        "COMPOSER-002": ["CM-7", "SR-3"],                # floating constraint
        "COMPOSER-003": ["SC-8", "SC-13"],               # HTTP repository
        "COMPOSER-012": ["SC-8", "SC-13"],  # disables Packagist / marks custom repo canonical
        "COMPOSER-011": ["SC-8", "SC-13"],  # external VCS repository re-points a package
        "COMPOSER-004": ["IA-5", "SC-28"],               # repo URL credentials
        "COMPOSER-005": ["CM-7", "SR-3"],                # minimum-stability dev
        "COMPOSER-014": ["CM-7", "SR-3"],  # minimum-stability without prefer-stable
        "COMPOSER-006": ["CM-7", "SI-7"],                # scripts curl-pipe-shell
        "COMPOSER-007": ["SI-2", "SR-3"],                # compromised package
        "COMPOSER-008": ["CM-7", "SR-3"],                # allow-plugins wildcard
        "COMPOSER-009": ["IA-5", "SC-28"],               # auth.json credentials
        "COMPOSER-010": ["SC-8", "SC-13"],               # secure-http false
        "COMPOSER-013": ["SC-8", "SC-13"],  # config.disable-tls
        # ── RubyGems / Bundler ──
        "GEM-001": ["SR-3", "CM-8"],                     # missing Gemfile.lock
        "GEM-002": ["CM-7", "SR-3"],                     # floating gem constraint
        "GEM-003": ["SC-8", "SC-13"],                    # HTTP source
        "GEM-004": ["IA-5", "SC-28"],                    # source URL credentials
        "GEM-005": ["CM-7", "SR-3"],                     # git/github source mutable
        "GEM-006": ["SI-2", "SR-3"],                     # compromised gem
        "GEM-007": ["CM-7", "SR-3"],                     # multiple top-level sources
        "GEM-008": ["CM-7", "SR-3"],                     # path: source in prod
        "GEM-009": ["IA-5", "SC-28"],                    # .bundle/config credentials
        "GEM-010": ["CM-7", "SR-3"],                     # dynamic Gemfile
        "GEM-011": ["CM-7", "SR-3"],  # Bundler plugin install-time exec
        "GEM-012": ["CM-7", "SR-3"],  # per-gem :source override
        "GEM-013": ["CM-7", "SR-3"],  # insecure git transport
        # ── Pulumi (PULUMI-001..006) ──
        "PULUMI-001": ["SC-13", "SC-12"],                # passphrase secretsprovider
        "PULUMI-002": ["IA-5", "SC-28"],                 # secret-shaped config plaintext
        "PULUMI-003": ["IA-5", "SC-28"],                 # hardcoded credentials in source
        "PULUMI-011": ["IA-5", "SC-28"],  # plugin from custom download server
        "PULUMI-004": ["AU-9", "SC-8"],                  # insecure state backend
        "PULUMI-005": ["AC-6", "AC-3"],                  # wildcard IAM policy in source
        "PULUMI-006": ["AC-3", "CM-7"],                  # StackReference unguarded
        # ── Pulumi extended pack ──
        "PULUMI-007": ["AC-3", "AC-6"],                  # public-access cloud resource
        "PULUMI-008": ["CM-7", "SI-7"],                  # shell-exec with non-constant input
        "PULUMI-013": ["CM-7", "SI-7"],  # dynamic provider deploy-time code
        "PULUMI-014": ["CM-7", "SI-7"],  # ESC environment imported without a qualifier
        "PULUMI-009": ["CM-6"],                          # runtime / source mismatch
        "PULUMI-012": ["CM-6"],  # plugin version unpinned
        "PULUMI-010": ["SC-12", "IA-5"],                 # stack orphaned encryption salt
        # ── OCI image manifest gaps ──────────────────────────────
        "OCI-001":  ["SR-4", "CM-8"],                    # provenance annotations missing
        "OCI-002":  ["SI-7", "SR-4"],                    # build attestation missing
        "OCI-003":  ["SR-4", "CM-8"],                    # missing image.created
        "OCI-004":  ["SR-3", "SR-11", "SI-7"],           # foreign-layer URL reference
        "OCI-005":  ["SR-4", "CM-8"],                    # missing image.licenses
        "OCI-006":  ["CM-2", "CM-7"],                    # excessive layer count (baseline hygiene)
        "OCI-007":  ["SR-3", "SR-11", "SI-7"],           # legacy schemaVersion 1
        "OCI-008":  ["SR-3", "SR-11", "SI-7", "SC-13"],  # weak digest algorithm
        "OCI-009":  ["SR-4", "CM-8"],                    # missing base-image annotations
        # ── SLSA / in-toto attestation content ───────────────────
        # ATTEST-NNN family is the provenance document itself.
        # SI-7 (software integrity) + SR-4 (provenance) cover all;
        # SBOM-content variants add CM-8 (component inventory).
        "ATTEST-001": ["SI-7", "SR-4"],                  # untrusted SLSA builder identity
        "ATTEST-002": ["SI-7", "SR-4"],                  # source-repo claim unverifiable
        "ATTEST-003": ["SR-4", "CM-8"],                  # SBOM floating versions
        "ATTEST-004": ["SR-4", "CM-8"],                  # provenance lacks resolved materials
        "ATTEST-005": ["SI-7", "SR-4"],                  # in-toto subject digest unpinned
        "ATTEST-006": ["SR-4", "CM-8"],                  # buildType missing / placeholder
        "ATTEST-007": ["SR-4", "CM-8"],                  # SBOM missing supplier
        # ── Cross-cutting dataflow / taint engine ────────────────
        # Cross-step / cross-job untrusted-data flow into privileged
        # sinks is a CM-6 (config-baseline) failure plus a developer-
        # testing gap (SA-11) for catching the flow in review.
        "TAINT-001": ["CM-6", "SA-11"],
        "TAINT-002": ["CM-6", "SA-11"],
        "TAINT-003": ["CM-6", "SA-11"],
        "TAINT-004": ["CM-6", "SA-11"],
        "TAINT-005": ["CM-6", "SA-11"],
        "TAINT-006": ["CM-6", "SA-11"],
        "TAINT-007": ["CM-6", "SA-11"],
        "TAINT-008": ["CM-6", "SA-11"],
        "TAINT-009": ["IA-5", "AC-3"],                     # env-protected secret flows to unprotected job
        # ── SCM posture (governance via the platform REST API) ──────
        # Branch protection / review controls map primarily to SA-15
        # (Development Process, Standards, and Tools) — the developer-
        # side governance regime — supplemented by AC-3 / AC-6 for
        # access enforcement, SI-7 for history-integrity surfaces,
        # and IA-5 for credential-shaped surfaces (workflow tokens,
        # deploy keys). AU-9 (audit-log tamper protection) is not used
        # here: git-history rewrite is not an audit log.
        "SCM-001":  ["SA-15", "AC-3"],                  # default branch unprotected
        "SCM-002":  ["SA-15"],                          # required reviews missing
        "SCM-003":  ["SA-11"],                          # default code scanning disabled (SAST)
        "SCM-004":  ["SI-7", "IA-5"],                   # secret scanning disabled
        "SCM-005":  ["RA-5", "SI-2"],                   # Dependabot security updates off
        "SCM-006":  ["SI-7", "SR-4"],                   # signed commits not required (provenance)
        "SCM-007":  ["SI-7"],                           # force-push allowed (history rewrite)
        "SCM-008":  ["SA-15", "SA-11"],                 # required status checks missing
        "SCM-009":  ["SI-7"],                           # branch deletions allowed
        "SCM-010":  ["AC-6", "SA-15"],                  # admin bypass allowed
        "SCM-011":  ["SA-15", "AC-3"],                  # CODEOWNERS reviews not required
        "SCM-012":  ["SA-15"],                          # stale reviews not dismissed
        "SCM-013":  ["SA-15"],                          # conversation resolution not required
        "SCM-014":  ["SA-15"],                          # last-push approval not required
        "SCM-015":  ["SI-7", "IA-5"],                   # secret scanning push protection off
        "SCM-016":  ["RA-5"],                           # private vulnerability reporting (vuln intake surface)
        "SCM-017":  ["SA-15"],                          # CODEOWNERS file missing
        "SCM-018":  ["SA-15", "AC-6"],                  # PR review bypass allowed
        "SCM-019":  ["AC-3", "AC-6"],                   # push-restriction allowlist names users
        # Actions governance + environments + deploy keys
        "SCM-020":  ["AC-6", "IA-5"],                   # workflow_token default write
        "SCM-021":  ["AC-3", "SA-15"],                  # Actions can approve PRs (self-approval)
        "SCM-022":  ["SR-3", "SR-11", "CM-7"],          # allowed_actions unrestricted
        "SCM-023":  ["SA-10", "AC-3"],                  # env missing reviewers
        "SCM-024":  ["CM-6", "SA-10"],                  # env branch policy missing
        "SCM-025":  ["IA-5", "AC-6"],                   # deploy keys write-enabled
        "SCM-026":  ["SC-8", "IA-5"],                   # webhook insecure transport / no HMAC
        "SCM-027":  ["AC-2", "AC-6"],                   # outside collaborator elevated
        "SCM-028":  ["AC-3"],                           # private repo allows forking
        # Ruleset enforcement (modern variant of branch protection)
        "SCM-029":  ["SA-15", "CM-6"],                  # ruleset not enforced
        "SCM-030":  ["AC-6", "SA-15"],                  # ruleset always-bypass
        "SCM-031":  ["SA-15"],                          # auto-merge enabled
        "SCM-032":  ["SA-15"],                          # ruleset lacks PR review
        "SCM-033":  ["SA-11", "SA-15"],                 # ruleset lacks status_checks
        "SCM-034":  ["SI-7"],                           # ruleset allows force_push
        "SCM-035":  ["SI-7"],                           # ruleset allows deletion
        "SCM-036":  ["SI-7", "SR-4"],                   # ruleset lacks signed_commits
        "SCM-037":  ["SA-15"],                          # ruleset stale-review dismissal
        "SCM-038":  ["SA-15"],                          # ruleset lacks linear_history (audit hygiene, not SI-7)
        "SCM-039":  ["SA-11", "SA-15"],                 # ruleset lacks required_workflows
        "SCM-040":  ["SA-11", "RA-5"],                  # ruleset lacks code_scanning gate
        "SCM-041":  ["SA-10", "SA-15"],                 # ruleset lacks deployment-env gate
        "SCM-042":  ["SA-11", "SA-15"],                 # ruleset lacks merge queue (post-merge re-test)
        "SCM-043":  ["SI-7", "SR-4"],                   # tag-ruleset lacks signed_commits
        "SCM-044":  ["SI-7", "AC-6"],                   # required_signatures bypassed for admins
        "SCM-045":  ["RA-5", "SA-11"],                  # default code scanning limited query suite
        "SCM-046":  ["RA-5", "SA-11"],                  # default code scanning paused
        "SCM-047":  ["RA-5", "SA-11"],                  # repo language not covered
        # ── Terraform / CloudFormation (IaC-native) ──────────────
        "TF-001":   ["IA-5"],                           # aws_iam_access_key declared as code
        "TF-002":   ["IA-5"],                           # hard-coded secret in resource attr
        "TF-003":   ["SC-7"],                           # CodeBuild VPC shares public subnet
        "CF-001":   ["IA-5"],                           # AWS::IAM::AccessKey declared as code
        "CF-002":   ["IA-5"],                           # hard-coded secret in resource property
        "CF-003":   ["SC-7"],                           # CodeBuild VPC shares public subnet
        # supply-chain posture pack
        "GHA-097":  ["CM-6", "SA-11"],                     # recursive PR auto-merge loop
        "GHA-098":  ["SA-10", "RA-5"],                     # deploy without security scan gate
        "GHA-099":  ["IA-5", "SC-28"],                     # deploy env plaintext secret
        "GHA-100":  ["SI-7", "SR-11"],                     # cosign verify no identity binding
        "GHA-102":  ["SI-7", "CM-6"],                      # submodule checkout on PR trigger
        "GHA-103":  ["CM-6", "SA-11"],                   # AI review bot on untrusted trigger
        "GHA-104":  ["CM-6", "SA-11"],                   # AI agent auto-push without PR review
        "GL-036":   ["IA-5", "AU-9"],                      # secret echoed to GitLab CI log
        "GL-038":   ["IA-5", "AU-9"],                      # CI_DEBUG_TRACE dumps secrets to GitLab CI log
        "BB-032":   ["IA-5", "AU-9"],                      # secret echoed to Bitbucket log
        "ADO-031":  ["IA-5", "AU-9"],                      # secret echoed to Azure DevOps log
        "ADO-032":  ["IA-5", "AU-9"],                      # checkout persistCredentials leaks token to .git/config
        "CC-032":   ["IA-5", "AU-9"],                      # secret echoed to CircleCI log
        "SCM-048":  ["AC-6", "IA-5"],                      # org codespace secrets scoped to all repos
        "SCM-049":  ["AC-6", "IA-5"],                      # classic PAT used where fine-grained suffices
        "NPM-012":  ["IA-5", "SR-3"],                      # publish token missing restrictions
        # ── Azure Cloud (Entra ID / Storage / Key Vault / ACR / Monitor) ──
        "ENTRA-001": ["AC-3", "AC-6"],                     # SP assigned Global Administrator
        "ENTRA-002": ["IA-5"],                             # app credential beyond 180 days
        "ENTRA-003": ["IA-5"],                             # SP uses password credential
        "AZST-001":  ["AC-3", "SC-7"],                     # public blob access
        "AZST-002":  ["SC-8", "SC-13"],                    # non-HTTPS traffic
        "AZST-003":  ["SC-12", "SC-13", "SC-28"],          # no CMK encryption
        "AKV-001":   ["SC-28", "CM-6"],                    # soft delete not enabled
        "AKV-002":   ["SC-28", "CM-6"],                    # purge protection not enabled
        "AKV-003":   ["SC-7", "AC-3"],                     # network ACLs allow all
        "ACR-001":   ["AC-2", "AC-6", "IA-5"],             # admin user enabled
        "ACR-002":   ["SC-7", "AC-3"],                     # public network access
        "ACR-003":   ["SI-7", "SR-4"],                     # content trust not enabled
        "AZMON-001": ["AU-2", "AU-12"],                    # no diagnostic setting
        "AZMON-002": ["AU-11"],                            # log retention < 365 days
        "AZMON-003": ["AU-2", "SI-2"],                     # no alert rule
        # ── GCP (IAM / GCS / KMS / Artifact Registry / Cloud Logging) ────
        "GCIAM-001": ["AC-3", "AC-6"],                     # SA has Owner/Editor role
        "GCIAM-002": ["IA-5"],                             # user-managed SA key
        "GCIAM-003": ["AC-3", "AC-6"],                     # token creator without condition
        "GCS-001":   ["AC-3", "SC-7"],                     # public bucket
        "GCS-002":   ["AC-3", "CM-6"],                     # no uniform access
        "GCS-003":   ["SI-7", "CM-6"],                     # versioning not enabled
        "GCKMS-001": ["SC-12", "SC-13"],                   # key rotation > 365 days
        "GCKMS-002": ["AC-3", "SC-12"],                    # public KMS key access
        "GCKMS-003": ["SC-12", "SC-13"],                   # no HSM protection
        "GAR-001":   ["RA-5", "SI-2"],                     # no vulnerability scanning
        "GAR-002":   ["AC-3", "SC-7"],                     # publicly readable repo
        "GAR-003":   ["CM-2", "CM-8"],                     # no cleanup policy
        "GCLOG-001": ["AU-2", "AU-12"],                    # audit logs not enabled
        "GCLOG-002": ["AU-2", "AU-12", "AU-9"],            # no log sink
        "GCLOG-003": ["AU-11"],                            # log retention < 365 days
        # ── Azure Cloud phase-2 ──────────────────────────────────────
        "ENTRA-004": ["IA-5", "AC-3"],                     # cond access MFA
        "ENTRA-005": ["AC-2", "AC-3"],                     # ext user restrict
        "ENTRA-006": ["AU-2", "SI-2"],                     # risky signin
        "AZST-004":  ["SC-8", "SC-13"],                    # min TLS
        "AZST-005":  ["CM-2", "CM-8"],                     # lifecycle
        "AZST-006":  ["SC-12", "SC-13"],                   # key rotation
        "AKV-004":   ["SC-12", "IA-5"],                    # key expiry
        "AKV-005":   ["SC-12", "IA-5"],                    # secret expiry
        "AKV-006":   ["AC-3", "AC-6"],                     # RBAC
        "ACR-004":   ["RA-5", "SI-2"],                     # defender scan
        "ACR-005":   ["SI-7", "CM-6"],                     # tag immutability
        "AZMON-004": ["AU-2", "AU-12"],                    # KV diagnostics
        "AZMON-005": ["AU-2", "AU-11"],                    # NSG flow retention
        "AZMON-006": ["AU-11"],                            # LAW retention
        "AZMON-007": ["AU-2", "SI-2"],                     # svc health alert
        "AZNW-001":  ["SC-7", "AC-3"],                     # SSH/RDP internet (CRITICAL)
        "AZNW-002":  ["AU-2", "AU-12"],                    # flow logs
        "AZNW-003":  ["SC-7", "SI-2"],                     # WAF
        "AZNW-004":  ["SC-7", "AC-3"],                     # deny-all
        "AZNW-005":  ["SC-7", "CM-7"],                     # public IP VM
        "AZAPP-001": ["SC-8", "SC-13"],                    # HTTPS
        "AZAPP-002": ["SC-8", "SC-13"],                    # TLS
        "AZAPP-003": ["IA-5", "AC-2"],                     # managed identity
        "AZAPP-004": ["CM-7", "SC-7"],                     # remote debug
        "AZAPP-005": ["CM-7", "SC-8"],                     # FTP
        "AZSQL-001": ["SC-12", "SC-28"],                   # TDE CMK
        "AZSQL-002": ["AU-2", "AU-12"],                    # auditing
        "AZSQL-003": ["SC-7", "AC-3"],                     # public access
        "AZSQL-004": ["AC-2", "AC-3"],                     # AAD admin
        "AZSQL-005": ["RA-5", "SI-2"],                     # threat detect
        "AZVM-001":  ["SC-28", "SC-12"],                   # disk encrypt
        "AZVM-002":  ["SC-7", "CM-7"],                     # public IP
        "AZVM-003":  ["SC-7", "AC-3"],                     # JIT
        "AZVM-004":  ["SI-2", "CM-6"],                     # OS patch
        "AZVM-005":  ["IA-5", "AC-2"],                     # managed identity
        # ── GCP phase-2 ──────────────────────────────────────────────
        "GCIAM-004": ["AC-2", "AC-6"],                     # default SA
        "GCIAM-005": ["AC-2", "AC-3"],                     # domain restrict
        "GCIAM-006": ["IA-5", "SC-12"],                    # SA key age
        "GCS-004":   ["SC-12", "SC-28"],                   # CMEK
        "GCS-005":   ["AU-2", "AU-12"],                    # access logging
        "GCLOG-004": ["AU-2", "AU-12"],                    # VPC flow logs
        "GCLOG-005": ["AU-2", "AU-12"],                    # firewall logging
        "GCLOG-006": ["AU-2", "AU-12"],                    # data access
        "GCLOG-007": ["AU-2", "SI-2"],                     # metric filter IAM
        "GCLOG-008": ["AU-2", "SI-2"],                     # metric filter firewall
        "GCLOG-009": ["AU-2", "SI-2"],                     # metric filter route
        "GCLOG-010": ["AU-2", "SI-2"],                     # metric filter SQL
        "GCLOG-011": ["AU-2", "SI-2"],                     # metric filter custom role
        "GCNET-001": ["SC-7", "CM-7"],                     # default network
        "GCNET-002": ["SC-7", "AC-3"],                     # deny-all
        "GCNET-003": ["SC-7", "AC-3"],                     # SSH/RDP (CRITICAL)
        "GCNET-004": ["SC-7", "CM-7"],                     # private access
        "GCNET-005": ["SC-7", "CM-7"],                     # Cloud NAT
        "GCCE-001":  ["CM-6", "SI-7"],                     # shielded VM
        "GCCE-002":  ["AC-2", "IA-5"],                     # OS Login
        "GCCE-003":  ["CM-7", "SC-7"],                     # serial port
        "GCCE-004":  ["SC-7", "CM-7"],                     # public IP
        "GCCE-005":  ["CM-6", "AC-3"],                     # project SSH keys
        "GCSQL-001": ["SC-7", "AC-3"],                     # public IP
        "GCSQL-002": ["CM-6", "SI-2"],                     # backups
        "GCSQL-003": ["SC-8", "SC-13"],                    # SSL
        "GCSQL-004": ["AC-2", "AC-3"],                     # IAM auth
        "GCSQL-005": ["CM-6", "SI-2"],                     # PITR
        "GCRUN-001": ["SC-7", "AC-3"],                     # unauth
        "GCRUN-002": ["AC-2", "AC-6"],                     # custom SA
        "GCRUN-003": ["CM-6", "SI-2"],                     # min instances
        "GCRUN-004": ["SC-7", "CM-7"],                     # VPC connector
        "GCKMS-004": ["AC-3", "AC-6"],                     # keyring IAM
        "GCKMS-005": ["SC-12", "CM-6"],                    # destroy sched
        "GCKMS-006": ["SC-12", "SC-13"],                   # imported key
        # Developer-environment auto-execution
        "DEV-001":   ["CM-7"],                             # vscode folderOpen task
        "DEV-006":   ["CM-7"],                             # vscode settings exec-path / env injection
        "DEV-002":   ["CM-7"],                             # devcontainer lifecycle
        "DEV-003":   ["CM-7"],                             # committed claude hook
        "DEV-004":   ["SI-7", "CM-7"],                     # auto-run remote fetch+exec
        "DEV-005":   ["CM-7", "AC-6"],                     # initializeCommand on host
    },
)
