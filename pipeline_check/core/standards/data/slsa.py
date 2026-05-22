"""SLSA (Supply-chain Levels for Software Artifacts) v1.0. Build track.

SLSA v1.0 organizes requirements into "tracks". This module covers the
Build track (L1–L3), the only track whose requirements are evidenced
by CI/CD configuration state visible to this scanner. The Source and
Dependency tracks require SCM/registry introspection outside this scan.

Each control ID here is a requirement that must hold for a given Build
level. A check "evidences" a requirement when its passing state is
necessary for the level to be achievable.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="slsa",
    title="SLSA Build Track",
    version="1.0",
    url="https://slsa.dev/spec/v1.0/",
    controls={
        # Build L1, provenance exists
        "Build.L1.Scripted":   "Build L1: Build process is fully defined and automated (scripted build)",
        "Build.L1.Provenance": "Build L1: Provenance describing how the artifact was produced is generated",
        # Build L2, hosted build platform with signed provenance
        "Build.L2.Hosted":     "Build L2: Builds run on a hosted build platform (not a developer workstation)",
        "Build.L2.Signed":     "Build L2: Provenance is authenticated and cannot be forged by tenants",
        # Build L3, hardened builds
        "Build.L3.Isolated":   "Build L3: Build runs in an isolated environment not influenced by other builds",
        "Build.L3.Ephemeral":  "Build L3: Build environment is ephemeral and provisioned fresh for each run",
        "Build.L3.NonFalsifiable": "Build L3: Provenance cannot be falsified by the build's own tenant",
    },
    mappings={
        # Build.L1.Scripted is structurally satisfied by any pipeline
        # pipeline_check can scan: if a CI config exists, the build
        # is "scripted" in SLSA's sense (as opposed to a developer
        # running commands by hand on a workstation). No posture rule
        # fires on the "build is not scripted" case because such a
        # build wouldn't be parseable by this scanner in the first
        # place. Left unmapped on purpose.
        # CodeBuild, isolation & ephemerality
        "CB-001":   ["Build.L3.NonFalsifiable"],                   # plaintext secrets = forgeable creds
        "CB-002":   ["Build.L3.Isolated"],                         # privileged mode breaks isolation
        "CB-004":   ["Build.L3.Ephemeral"],                        # unbounded timeout ≠ ephemeral
        "CB-005":   ["Build.L3.NonFalsifiable"],                   # outdated managed build image
        "CB-006":   ["Build.L3.NonFalsifiable"],                   # long-lived source token
        "CB-007":   ["Build.L3.Isolated", "Build.L3.Ephemeral"],   # uncapped webhook triggers
        "CB-008":   ["Build.L3.NonFalsifiable"],                   # inline buildspec (not from protected repo)
        "CB-009":   ["Build.L3.NonFalsifiable"],                   # build image not digest-pinned
        "CB-010":   ["Build.L3.Isolated",
                     "Build.L3.NonFalsifiable"],                   # fork-PR webhook unfiltered
        "CB-011":   ["Build.L3.NonFalsifiable"],                   # buildspec malicious indicators
        # CodePipeline, provenance storage integrity
        "CP-001":   ["Build.L3.NonFalsifiable"],                   # no approval gate
        "CP-002":   ["Build.L1.Provenance", "Build.L2.Signed"],    # artifact store not CMK-encrypted
        "CP-004":   ["Build.L3.NonFalsifiable"],                   # OAuth token source (forgeable creds)
        "CP-005":   ["Build.L3.NonFalsifiable"],                   # prod Deploy stage no manual approval
        "CP-007":   ["Build.L3.Isolated",
                     "Build.L3.NonFalsifiable"],                   # v2 PR trigger accepts all branches
        # ECR, artifact-to-provenance binding
        "ECR-002":  ["Build.L2.Signed", "Build.L3.NonFalsifiable"],# mutable tags break binding
        "ECR-005":  ["Build.L2.Signed"],                           # AES256 (no CMK = weaker integrity)
        "ECR-006":  ["Build.L3.NonFalsifiable"],                   # pull-through untrusted upstream
        # AWS Signer / Lambda code-signing
        "SIGN-001": ["Build.L2.Signed"],                           # no AWS Signer profile for Lambda
        "SIGN-002": ["Build.L2.Signed"],                           # Signer profile revoked / inactive
        "LMB-001":  ["Build.L2.Signed"],                           # Lambda has no code-signing config
        "CA-001":   ["Build.L2.Signed"],                           # CodeArtifact domain not CMK-encrypted
        # IAM, tenant-forgeable provenance if over-privileged
        "IAM-001":  ["Build.L3.NonFalsifiable"],                   # admin can rewrite artifacts
        "IAM-002":  ["Build.L3.NonFalsifiable"],                   # wildcard action
        "IAM-003":  ["Build.L3.NonFalsifiable"],                   # no permission boundary
        "IAM-004":  ["Build.L3.NonFalsifiable"],                   # PassRole * → role hopping
        "IAM-005":  ["Build.L3.NonFalsifiable"],                   # trust policy missing externalId
        "IAM-006":  ["Build.L3.NonFalsifiable"],                   # wildcard resource
        "IAM-007":  ["Build.L3.NonFalsifiable"],                   # access key > 90 days (forgeable)
        "IAM-008":  ["Build.L3.NonFalsifiable"],                   # OIDC trust missing aud/sub pin
        # PBAC, cross-build contamination breaks isolation
        "PBAC-001": ["Build.L3.Isolated"],                         # no VPC boundary
        "PBAC-002": ["Build.L3.Isolated"],                         # shared service role
        "PBAC-005": ["Build.L3.NonFalsifiable"],                   # stage roles mirror pipeline role
        # ── GitHub Actions ────────────────────────────────────────
        "GHA-001":  ["Build.L3.NonFalsifiable"],                   # unpinned 3rd-party action
        "GHA-002":  ["Build.L3.NonFalsifiable", "Build.L3.Isolated"], # pull_request_target + PR head
        "GHA-003":  ["Build.L3.Isolated"],                         # script injection
        "GHA-004":  ["Build.L3.NonFalsifiable"],                   # unrestricted GITHUB_TOKEN
        "GHA-006":  ["Build.L2.Signed"],                           # unsigned artifacts
        "GHA-007":  ["Build.L1.Provenance"],                       # no SBOM / provenance
        "GHA-008":  ["Build.L3.NonFalsifiable"],                   # leaked creds → forge provenance
        "GHA-009":  ["Build.L3.Isolated"],                         # workflow_run artifact poisoning
        "GHA-010":  ["Build.L3.Isolated"],                         # local action on untrusted trigger
        "GHA-011":  ["Build.L3.Isolated"],                         # cache key tainting
        "GHA-012":  ["Build.L2.Hosted", "Build.L3.Ephemeral"],     # self-hosted runner
        "GHA-013":  ["Build.L3.Isolated"],                         # issue_comment without guard
        "GHA-015":  ["Build.L3.Ephemeral"],                        # unbounded build
        "GHA-016":  ["Build.L3.Isolated"],                         # curl | bash → RCE
        "GHA-017":  ["Build.L3.Isolated"],                         # Docker privileged
        "GHA-019":  ["Build.L3.NonFalsifiable"],                   # token persistence
        "GHA-021":  ["Build.L3.Isolated"],                         # no lockfile → dep substitution
        "GHA-023":  ["Build.L3.Isolated"],                         # TLS bypass → MITM injection
        "GHA-024":  ["Build.L1.Provenance", "Build.L2.Signed",
                     "Build.L3.NonFalsifiable"],                   # SLSA attestation missing
        "GHA-025":  ["Build.L3.NonFalsifiable"],                   # unpinned reusable workflow
        "GHA-026":  ["Build.L3.Isolated"],                         # container escape via options
        "GHA-028":  ["Build.L3.Isolated"],                         # eval / shell re-invocation
        "GHA-029":  ["Build.L3.Isolated"],                         # package source bypasses lockfile
        # OIDC w/o env-protected job (provenance binding weak)
        "GHA-030":  ["Build.L3.NonFalsifiable"],
        "GHA-037":  ["Build.L3.NonFalsifiable"],                   # checkout persists GITHUB_TOKEN
        "GHA-040":  ["Build.L3.NonFalsifiable"],                   # known-compromised action ref
        "GHA-041":  ["Build.L3.NonFalsifiable"],                   # single-maintainer action
        "GHA-042":  ["Build.L3.NonFalsifiable"],                   # very-young action repo
        "GHA-043":  ["Build.L3.NonFalsifiable"],                   # low-star + sensitive perms
        "GHA-047":  ["Build.L3.NonFalsifiable"],                   # fresh-ref cooldown
        "GHA-088":  ["Build.L3.NonFalsifiable"],                   # typosquat uses
        "GHA-089":  ["Build.L3.NonFalsifiable"],                   # archived upstream
        "GHA-090":  ["Build.L3.NonFalsifiable"],                   # impostor-commit
        "GHA-091":  ["Build.L3.NonFalsifiable"],                   # repojacking
        "GHA-048":  ["Build.L3.NonFalsifiable",
                     "Build.L3.Isolated"],                         # workflow self-mutation
        "GHA-049":  ["Build.L3.NonFalsifiable"],                   # cross-repo push
        "GHA-050":  ["Build.L2.Signed"],                           # publish w/o OIDC = long-lived sig identity
        "GHA-051":  ["Build.L3.NonFalsifiable"],                   # services / container image unpinned
        "GHA-052":  ["Build.L3.Isolated"],                         # cache key derives from untrusted input
        "GHA-053":  ["Build.L3.Isolated"],                         # if-predicate evaluates untrusted context
        "GHA-054":  ["Build.L3.NonFalsifiable"],                   # checkout ssh-key persists into .git/config
        "GHA-005":  ["Build.L3.NonFalsifiable"],                   # long-lived AWS keys
        "GHA-014":  ["Build.L3.NonFalsifiable"],                   # deploy job missing environment
        "GHA-018":  ["Build.L3.NonFalsifiable"],                   # GITHUB_TOKEN persisted to storage
        "GHA-022":  ["Build.L3.Isolated",
                     "Build.L3.NonFalsifiable"],                   # TLS bypass
        "GHA-027":  ["Build.L3.Isolated"],                         # dangerous shell idiom
        "GHA-031":  ["Build.L3.Isolated"],                         # retired set-output / save-state
        "GHA-032":  ["Build.L3.Isolated"],                         # local script on untrusted trigger
        "GHA-033":  ["Build.L3.NonFalsifiable"],                   # secret echoed in run:
        "GHA-034":  ["Build.L3.NonFalsifiable"],                   # secrets: inherit (broad cred surface)
        "GHA-035":  ["Build.L3.Isolated"],                         # github-script untrusted context
        "GHA-036":  ["Build.L3.Isolated"],                         # runs-on untrusted context
        "GHA-038":  ["Build.L3.Isolated"],                         # ACTIONS_ALLOW_UNSECURE_COMMANDS
        "GHA-039":  ["Build.L3.NonFalsifiable"],                   # services / container creds literal
        "GHA-044":  ["Build.L3.Isolated"],                         # build-tool PPE on untrusted trigger
        "GHA-045":  ["Build.L3.Isolated"],                         # caller-ref input drives checkout
        "GHA-046":  ["Build.L3.Isolated"],                         # manual PR-head fetch
        "GHA-055":  ["Build.L3.NonFalsifiable"],                   # reusable outputs leak secret
        "GHA-056":  ["Build.L3.NonFalsifiable"],                   # worm IOC strings
        "GHA-057":  ["Build.L3.Isolated"],                         # secret-scanner output → egress
        "GHA-058":  ["Build.L3.Isolated"],                         # agentic CLI permission-bypass
        "GHA-059":  ["Build.L3.NonFalsifiable"],                   # npm install without audit signatures
        "GHA-060":  ["Build.L3.NonFalsifiable"],                   # pip install without --require-hashes
        "GHA-061":  ["Build.L3.NonFalsifiable"],                   # App token minted without permissions filter
        "GHA-062":  ["Build.L3.NonFalsifiable"],                   # OIDC trust subject in sibling IaC is overly broad
        # ── GitLab CI ─────────────────────────────────────────────
        "GL-001":   ["Build.L3.NonFalsifiable"],                   # floating image tag
        "GL-002":   ["Build.L3.Isolated"],                         # script injection
        "GL-005":   ["Build.L3.NonFalsifiable"],                   # unpinned include
        "GL-006":   ["Build.L2.Signed"],
        "GL-007":   ["Build.L1.Provenance"],
        "GL-008":   ["Build.L3.NonFalsifiable"],                   # leaked creds
        "GL-009":   ["Build.L3.NonFalsifiable"],                   # tag-pinned not digest
        "GL-010":   ["Build.L3.Isolated"],                         # multi-project artifact ingestion
        "GL-011":   ["Build.L3.Isolated"],                         # include: local on MR pipeline
        "GL-012":   ["Build.L3.Isolated"],                         # cache key tainting
        "GL-014":   ["Build.L2.Hosted", "Build.L3.Ephemeral"],     # self-hosted runner
        "GL-015":   ["Build.L3.Ephemeral"],                        # unbounded build
        "GL-016":   ["Build.L3.Isolated"],                         # curl | bash
        "GL-017":   ["Build.L3.Isolated"],                         # Docker privileged
        "GL-020":   ["Build.L3.NonFalsifiable"],                   # token persistence
        "GL-021":   ["Build.L3.Isolated"],                         # no lockfile
        "GL-023":   ["Build.L3.Isolated"],                         # TLS bypass
        "GL-024":   ["Build.L1.Provenance", "Build.L2.Signed",
                     "Build.L3.NonFalsifiable"],
        "GL-026":   ["Build.L3.Isolated"],                         # eval / shell re-invocation
        "GL-027":   ["Build.L3.Isolated"],                         # package source bypasses lockfile
        "GL-003":   ["Build.L3.NonFalsifiable"],                   # secret in env
        "GL-004":   ["Build.L3.NonFalsifiable"],                   # manual deploy allow_failure
        "GL-013":   ["Build.L3.NonFalsifiable"],                   # long-lived AWS keys
        "GL-018":   ["Build.L3.NonFalsifiable"],                   # package install insecure source
        "GL-022":   ["Build.L3.NonFalsifiable"],                   # dep-update bypasses lockfile pins
        "GL-025":   ["Build.L3.NonFalsifiable"],                   # malicious-activity indicators
        "GL-028":   ["Build.L3.NonFalsifiable"],                   # services image not pinned
        "GL-029":   ["Build.L3.NonFalsifiable"],                   # manual deploy allow_failure
        "GL-030":   ["Build.L3.NonFalsifiable"],                   # trigger: include w/o pinned ref
        "GL-031":   ["Build.L3.NonFalsifiable"],                   # id_tokens missing audience pin
        "GL-032":   ["Build.L3.Isolated"],                         # tags interpolates untrusted variable
        "GL-033":   ["Build.L3.Isolated"],                         # global before_script taint
        "GL-034":   ["Build.L3.NonFalsifiable"],                   # npm install without audit signatures
        "GL-035":   ["Build.L3.NonFalsifiable"],                   # pip install without --require-hashes
        # ── Bitbucket Pipelines ───────────────────────────────────
        "BB-001":   ["Build.L3.NonFalsifiable"],                   # unpinned pipe
        "BB-002":   ["Build.L3.Isolated"],                         # script injection
        "BB-005":   ["Build.L3.Ephemeral"],                        # unbounded runtime
        "BB-006":   ["Build.L2.Signed"],
        "BB-007":   ["Build.L1.Provenance"],
        "BB-008":   ["Build.L3.NonFalsifiable"],                   # leaked creds
        "BB-009":   ["Build.L3.NonFalsifiable"],                   # tag not digest
        "BB-010":   ["Build.L3.Isolated"],                         # PR artifact handover
        "BB-012":   ["Build.L3.Isolated"],                         # curl | bash
        "BB-013":   ["Build.L3.Isolated"],                         # Docker privileged
        "BB-016":   ["Build.L2.Hosted", "Build.L3.Ephemeral"],     # self-hosted runner
        "BB-017":   ["Build.L3.NonFalsifiable"],                   # token persistence
        "BB-018":   ["Build.L3.Isolated"],                         # cache key tainting
        "BB-021":   ["Build.L3.Isolated"],                         # no lockfile
        "BB-023":   ["Build.L3.Isolated"],                         # TLS bypass
        "BB-024":   ["Build.L1.Provenance", "Build.L2.Signed",
                     "Build.L3.NonFalsifiable"],
        "BB-026":   ["Build.L3.Isolated"],                         # eval / shell re-invocation
        "BB-027":   ["Build.L3.Isolated"],                         # package source bypasses lockfile
        "BB-003":   ["Build.L3.NonFalsifiable"],                   # secret in env
        "BB-004":   ["Build.L3.NonFalsifiable"],                   # deploy step missing environment
        "BB-011":   ["Build.L3.NonFalsifiable"],                   # long-lived AWS keys
        "BB-014":   ["Build.L3.NonFalsifiable"],                   # package install insecure source
        "BB-019":   ["Build.L3.NonFalsifiable"],                   # after-script references secrets
        "BB-022":   ["Build.L3.NonFalsifiable"],                   # dep-update bypasses lockfile pins
        "BB-025":   ["Build.L3.NonFalsifiable"],                   # malicious-activity indicators
        "BB-028":   ["Build.L3.NonFalsifiable"],                   # OIDC step w/o env-gated deployment
        "BB-029":   ["Build.L3.NonFalsifiable"],                   # step + service image not digest-pinned
        "BB-030":   ["Build.L3.NonFalsifiable"],                   # npm install without audit signatures
        "BB-031":   ["Build.L3.NonFalsifiable"],                   # pip install without --require-hashes
        # ── Azure DevOps Pipelines ────────────────────────────────
        "ADO-001":  ["Build.L3.NonFalsifiable"],                   # unpinned task
        "ADO-002":  ["Build.L3.Isolated"],                         # script injection
        "ADO-005":  ["Build.L3.NonFalsifiable"],                   # unpinned container
        "ADO-006":  ["Build.L2.Signed"],
        "ADO-007":  ["Build.L1.Provenance"],
        "ADO-008":  ["Build.L3.NonFalsifiable"],                   # leaked creds
        "ADO-009":  ["Build.L3.NonFalsifiable"],                   # tag not digest
        "ADO-010":  ["Build.L3.Isolated"],                         # cross-pipeline download
        "ADO-011":  ["Build.L3.Isolated"],                         # local template on PR
        "ADO-012":  ["Build.L3.Isolated"],                         # cache key tainting
        "ADO-013":  ["Build.L2.Hosted", "Build.L3.Ephemeral"],     # self-hosted pool
        "ADO-015":  ["Build.L3.Ephemeral"],                        # unbounded build
        "ADO-016":  ["Build.L3.Isolated"],                         # curl | bash
        "ADO-017":  ["Build.L3.Isolated"],                         # Docker privileged
        "ADO-019":  ["Build.L3.Isolated"],                         # extends template injection
        "ADO-021":  ["Build.L3.Isolated"],                         # no lockfile
        "ADO-023":  ["Build.L3.Isolated"],                         # TLS bypass
        "ADO-024":  ["Build.L1.Provenance", "Build.L2.Signed",
                     "Build.L3.NonFalsifiable"],
        "ADO-025":  ["Build.L3.NonFalsifiable"],                   # unpinned template
        "ADO-027":  ["Build.L3.Isolated"],                         # eval / shell re-invocation
        "ADO-028":  ["Build.L3.Isolated"],                         # package source bypasses lockfile
        "ADO-003":  ["Build.L3.NonFalsifiable"],                   # secret in env
        "ADO-004":  ["Build.L3.NonFalsifiable"],                   # deploy stage missing environment
        "ADO-014":  ["Build.L3.NonFalsifiable"],                   # long-lived AWS keys
        "ADO-018":  ["Build.L3.NonFalsifiable"],                   # package install insecure source
        "ADO-022":  ["Build.L3.NonFalsifiable"],                   # dep-update bypasses lockfile pins
        "ADO-026":  ["Build.L3.NonFalsifiable"],                   # malicious-activity indicators
        "ADO-029":  ["Build.L3.NonFalsifiable"],                   # service-conn job w/o env/branch gate
        "ADO-030":  ["Build.L3.Isolated"],                         # pool interpolates untrusted value
        # ── Jenkins ───────────────────────────────────────────────
        "JF-001":   ["Build.L3.NonFalsifiable"],                   # unpinned shared library
        "JF-002":   ["Build.L3.Isolated"],                         # script injection
        "JF-003":   ["Build.L3.Isolated"],                         # agent any, no isolation
        "JF-006":   ["Build.L2.Signed"],                           # unsigned artifacts
        "JF-007":   ["Build.L1.Provenance"],                       # no SBOM
        "JF-008":   ["Build.L3.NonFalsifiable"],                   # leaked creds
        "JF-009":   ["Build.L3.NonFalsifiable"],                   # image not digest-pinned
        "JF-012":   ["Build.L3.Isolated"],                         # load unverified Groovy
        "JF-013":   ["Build.L3.Isolated"],                         # copyArtifacts unverified
        "JF-014":   ["Build.L2.Hosted", "Build.L3.Ephemeral"],     # non-ephemeral agent
        "JF-015":   ["Build.L3.Ephemeral"],                        # unbounded build
        "JF-016":   ["Build.L3.Isolated"],                         # curl | bash
        "JF-017":   ["Build.L3.Isolated"],                         # Docker privileged
        "JF-019":   ["Build.L3.Isolated"],                         # Groovy sandbox escape
        "JF-021":   ["Build.L3.Isolated"],                         # no lockfile
        "JF-023":   ["Build.L3.Isolated"],                         # TLS bypass
        "JF-028":   ["Build.L1.Provenance", "Build.L2.Signed",
                     "Build.L3.NonFalsifiable"],                   # SLSA attestation missing
        "JF-030":   ["Build.L3.Isolated"],                         # eval / shell re-invocation
        "JF-031":   ["Build.L3.Isolated"],                         # package source bypasses lockfile
        "JF-004":   ["Build.L3.NonFalsifiable"],                   # AWS long-lived keys via withCredentials
        "JF-005":   ["Build.L3.NonFalsifiable"],                   # deploy stage missing manual input
        "JF-010":   ["Build.L3.NonFalsifiable"],                   # long-lived AWS keys in environment {}
        "JF-018":   ["Build.L3.NonFalsifiable"],                   # package install insecure source
        "JF-022":   ["Build.L3.NonFalsifiable"],                   # dep-update bypasses lockfile pins
        "JF-024":   ["Build.L3.NonFalsifiable"],                   # input no submitter restriction
        "JF-025":   ["Build.L3.Isolated"],                         # K8s pod template privileged / hostPath
        "JF-026":   ["Build.L3.NonFalsifiable"],                   # build job: ignores downstream failure
        "JF-027":   ["Build.L1.Provenance"],                       # archiveArtifacts no fingerprint
        "JF-029":   ["Build.L3.NonFalsifiable"],                   # malicious-activity indicators
        "JF-032":   ["Build.L3.Isolated"],                         # agent label interpolates untrusted
        "JF-033":   ["Build.L3.NonFalsifiable"],                   # withCredentials leaked via Groovy ${}
        "JF-034":   ["Build.L3.NonFalsifiable"],                   # password() build parameter
        "JF-035":   ["Build.L3.Isolated",
                     "Build.L3.NonFalsifiable"],                   # httpRequest SSL off
        # ── CircleCI ──────────────────────────────────────────────
        "CC-001":   ["Build.L3.NonFalsifiable"],                   # orb not pinned
        "CC-002":   ["Build.L3.Isolated"],                         # script injection
        "CC-003":   ["Build.L3.NonFalsifiable"],                   # image not pinned to digest
        "CC-004":   ["Build.L3.NonFalsifiable"],                   # unrestricted context
        "CC-006":   ["Build.L2.Signed"],                           # unsigned artifacts
        "CC-007":   ["Build.L1.Provenance"],                       # no SBOM
        "CC-008":   ["Build.L3.NonFalsifiable"],                   # leaked creds
        "CC-010":   ["Build.L2.Hosted", "Build.L3.Ephemeral"],     # self-hosted runner
        "CC-012":   ["Build.L3.Isolated"],                         # dynamic config
        "CC-014":   ["Build.L3.Isolated"],                         # resource class isolation
        "CC-015":   ["Build.L3.Ephemeral"],                        # no timeout
        "CC-016":   ["Build.L3.Isolated"],                         # curl | bash
        "CC-017":   ["Build.L3.Isolated"],                         # Docker privileged
        "CC-021":   ["Build.L3.Isolated"],                         # no lockfile
        "CC-023":   ["Build.L3.Isolated"],                         # TLS bypass
        "CC-024":   ["Build.L1.Provenance", "Build.L2.Signed",
                     "Build.L3.NonFalsifiable"],
        "CC-025":   ["Build.L3.Isolated"],                         # cache poisoning
        "CC-027":   ["Build.L3.Isolated"],                         # eval / shell re-invocation
        "CC-028":   ["Build.L3.Isolated"],                         # package source bypasses lockfile
        "CC-005":   ["Build.L3.NonFalsifiable"],                   # leaked credentials
        "CC-009":   ["Build.L3.NonFalsifiable"],                   # job missing approval gate
        "CC-013":   ["Build.L3.Isolated"],                         # no branch filter on jobs
        "CC-018":   ["Build.L3.NonFalsifiable"],                   # install bypasses registry integrity
        "CC-019":   ["Build.L3.NonFalsifiable"],                   # long-lived AWS credentials
        "CC-022":   ["Build.L3.NonFalsifiable"],                   # dep-update bypasses lockfile pins
        "CC-026":   ["Build.L3.NonFalsifiable"],                   # malicious-activity indicators
        "CC-029":   ["Build.L3.NonFalsifiable"],                   # machine executor image not pinned
        "CC-030":   ["Build.L3.NonFalsifiable"],                   # job w/o branch filter / approval gate
        "CC-031":   ["Build.L3.NonFalsifiable"],                   # OIDC role w/o branch filter
        # ── Buildkite ─────────────────────────────────────────────
        "BK-001":   ["Build.L3.NonFalsifiable"],                   # plugin not pinned
        "BK-002":   ["Build.L3.NonFalsifiable"],                   # leaked creds in env
        "BK-003":   ["Build.L3.Isolated"],                         # untrusted variable injection
        "BK-004":   ["Build.L3.Isolated"],                         # curl | bash
        "BK-005":   ["Build.L3.Isolated"],                         # Docker privileged
        "BK-006":   ["Build.L3.Ephemeral"],                        # no timeout
        "BK-007":   ["Build.L3.NonFalsifiable"],                   # deploy not gated
        "BK-008":   ["Build.L3.Isolated"],                         # TLS bypass
        "BK-009":   ["Build.L2.Signed"],                           # artifact signing
        "BK-010":   ["Build.L1.Provenance"],                       # SBOM
        "BK-011":   ["Build.L1.Provenance", "Build.L2.Signed",
                     "Build.L3.NonFalsifiable"],                   # SLSA provenance
        "BK-013":   ["Build.L3.NonFalsifiable"],                   # deploy step no branches filter
        "BK-014":   ["Build.L3.NonFalsifiable"],                   # unpinned package install
        "BK-015":   ["Build.L3.Isolated"],                         # agents map untrusted interpolation
        # ── Tekton ────────────────────────────────────────────────
        "TKN-001":  ["Build.L3.NonFalsifiable"],                   # step image not digest-pinned
        "TKN-002":  ["Build.L3.Isolated"],                         # step privileged / root
        "TKN-003":  ["Build.L3.Isolated"],                         # param injection in script
        "TKN-004":  ["Build.L3.Isolated"],                         # hostPath / host namespaces
        "TKN-005":  ["Build.L3.NonFalsifiable"],                   # leaked creds in env / param
        "TKN-006":  ["Build.L3.Ephemeral"],                        # no timeout
        "TKN-007":  ["Build.L3.NonFalsifiable"],                   # default ServiceAccount
        "TKN-008":  ["Build.L3.Isolated"],                         # remote install / TLS bypass
        "TKN-009":  ["Build.L2.Signed"],                           # artifact signing
        "TKN-010":  ["Build.L1.Provenance"],                       # SBOM
        "TKN-011":  ["Build.L1.Provenance", "Build.L2.Signed",
                     "Build.L3.NonFalsifiable"],                   # SLSA provenance
        "TKN-013":  ["Build.L3.Isolated"],                         # sidecar privileged / root
        "TKN-014":  ["Build.L3.NonFalsifiable"],                   # unpinned package install
        "TKN-015":  ["Build.L3.Isolated"],                         # workspace subPath param injection
        # ── Argo Workflows ────────────────────────────────────────
        "ARGO-001": ["Build.L3.NonFalsifiable"],                   # template image not digest-pinned
        "ARGO-002": ["Build.L3.Isolated"],                         # template privileged / root
        "ARGO-003": ["Build.L3.NonFalsifiable"],                   # default ServiceAccount
        "ARGO-004": ["Build.L3.Isolated"],                         # hostPath / host namespaces
        "ARGO-005": ["Build.L3.Isolated"],                         # parameter injection in script
        "ARGO-006": ["Build.L3.NonFalsifiable"],                   # leaked creds in env / param
        "ARGO-007": ["Build.L3.Ephemeral"],                        # no activeDeadlineSeconds
        "ARGO-008": ["Build.L3.Isolated"],                         # remote install / TLS bypass
        "ARGO-009": ["Build.L2.Signed"],                           # artifact signing
        "ARGO-010": ["Build.L1.Provenance"],                       # SBOM
        "ARGO-011": ["Build.L1.Provenance", "Build.L2.Signed",
                     "Build.L3.NonFalsifiable"],                   # SLSA provenance
        "ARGO-013": ["Build.L3.NonFalsifiable"],                   # SA token automount default
        "ARGO-014": ["Build.L3.NonFalsifiable"],                   # unpinned package install
        "ARGO-015": ["Build.L3.Isolated",
                     "Build.L3.NonFalsifiable"],                   # insecure (non-HTTPS) artifact URL
        # ── Drone CI ─────────────────────────────────────────────
        "DR-001":   ["Build.L3.NonFalsifiable"],                   # step image not digest-pinned
        "DR-002":   ["Build.L3.Isolated"],                         # privileged step
        "DR-003":   ["Build.L3.Isolated"],                         # Drone variable injection
        "DR-004":   ["Build.L3.NonFalsifiable"],                   # literal credential
        "DR-005":   ["Build.L3.NonFalsifiable"],                   # plugin floating tag
        "DR-006":   ["Build.L3.Isolated",
                     "Build.L3.NonFalsifiable"],                   # TLS bypass in commands
        "DR-007":   ["Build.L3.Isolated"],                         # sensitive host-path mount
        "DR-008":   ["Build.L3.NonFalsifiable"],                   # pull: never (skips registry verify)
        "DR-009":   ["Build.L3.Isolated"],                         # cache key tainted by attacker input
        "DR-010":   ["Build.L3.NonFalsifiable"],                   # unpinned package install
        "DR-011":   ["Build.L3.Isolated"],                         # node map interpolates untrusted
        # ── Cross-cutting dataflow / taint engine ─────────────────
        # The TAINT-NNN family flags cross-step / cross-job flows
        # where untrusted data reaches a privileged sink. That's
        # both an isolation failure (the build env is influenced by
        # the build's own tenant) and a provenance-falsification
        # surface (the tenant-controlled value lands in a signed
        # output).
        "TAINT-001": ["Build.L3.Isolated", "Build.L3.NonFalsifiable"],
        "TAINT-002": ["Build.L3.Isolated", "Build.L3.NonFalsifiable"],
        "TAINT-003": ["Build.L3.Isolated", "Build.L3.NonFalsifiable"],
        "TAINT-004": ["Build.L3.Isolated", "Build.L3.NonFalsifiable"],
        "TAINT-005": ["Build.L3.Isolated", "Build.L3.NonFalsifiable"],
        "TAINT-006": ["Build.L3.Isolated", "Build.L3.NonFalsifiable"],
        "TAINT-007": ["Build.L3.Isolated", "Build.L3.NonFalsifiable"],
        "TAINT-008": ["Build.L3.Isolated", "Build.L3.NonFalsifiable"],
        # ── NPM / PyPI / Maven dep supply-chain ──────────────────
        # Each unpinned / non-registry / compromised-version finding
        # is a tenant-substitutable input — the canonical
        # L3.NonFalsifiable shape for the dep leg of the build.
        "NPM-001":  ["Build.L3.NonFalsifiable"],                   # floating range
        "NPM-002":  ["Build.L3.NonFalsifiable"],                   # lock entry missing integrity
        "NPM-003":  ["Build.L3.NonFalsifiable"],                   # non-registry source
        "NPM-004":  ["Build.L3.Isolated"],                         # install-time lifecycle script
        "NPM-005":  ["Build.L3.NonFalsifiable"],                   # git dep with mutable ref
        "NPM-006":  ["Build.L3.NonFalsifiable"],                   # compromised npm version
        "NPM-007":  ["Build.L3.Isolated"],                         # .npmrc ignore-scripts
        "NPM-011":  ["Build.L3.NonFalsifiable"],                   # secret-shaped paths in files field
        "PYPI-001": ["Build.L3.NonFalsifiable"],                   # missing ==pin
        "PYPI-002": ["Build.L3.NonFalsifiable"],                   # missing hash
        "PYPI-003": ["Build.L3.NonFalsifiable"],                   # http index / --trusted-host
        "PYPI-004": ["Build.L3.NonFalsifiable"],                   # VCS dep without commit SHA
        "PYPI-005": ["Build.L3.NonFalsifiable"],                   # --extra-index-url (dep confusion)
        "PYPI-006": ["Build.L3.NonFalsifiable"],                   # compromised PyPI version
        "MVN-001":  ["Build.L3.NonFalsifiable"],                   # floating Maven range
        "MVN-002":  ["Build.L3.NonFalsifiable"],                   # mutable SNAPSHOT dep
        "MVN-003":  ["Build.L3.NonFalsifiable"],                   # plaintext-HTTP repository
        "MVN-004":  ["Build.L3.NonFalsifiable"],                   # missing <version> element
        "MVN-005":  ["Build.L3.NonFalsifiable"],                   # lax checksumPolicy
        "MVN-006":  ["Build.L3.NonFalsifiable"],                   # compromised Maven version
        "MVN-007":  ["Build.L3.NonFalsifiable"],                   # settings.xml wildcard mirror
        # ── Helm chart-supply-chain ───────────────────────────────
        # The chart's own packaging metadata sits at the build-output
        # boundary. Chart.lock and Chart.yaml are the chart's
        # "provenance metadata" the same way an image manifest is for
        # a container build. HELM-002 (no Chart.lock digest) is the
        # exact NonFalsifiable failure for chart distribution.
        "HELM-001": ["Build.L1.Provenance"],                       # legacy v1 schema
        "HELM-002": ["Build.L3.NonFalsifiable",
                     "Build.L1.Provenance"],                       # missing Chart.lock digests
        "HELM-003": ["Build.L3.Isolated",
                     "Build.L3.NonFalsifiable"],                   # non-HTTPS dep repo
        "HELM-004": ["Build.L3.NonFalsifiable"],                   # version not exact-pinned
        "HELM-005": ["Build.L1.Provenance"],                       # maintainers chain-of-custody
        "HELM-006": ["Build.L1.Provenance"],                       # kubeVersion compat range
        "HELM-007": ["Build.L1.Provenance"],                       # description (provenance metadata)
        "HELM-008": ["Build.L3.NonFalsifiable"],                   # stale Chart.lock > 90 days
        "HELM-009": ["Build.L3.Isolated",
                     "Build.L3.NonFalsifiable"],                   # non-HTTPS home / sources URL
        "HELM-010": ["Build.L1.Provenance"],                       # appVersion (provenance metadata)
        # ── Dockerfile (image build process is the SLSA build) ────
        # Pinning rules tie to L3.NonFalsifiable (digest pinning is
        # the canonical "tenant can't substitute" mitigation).
        # Privileged / root build steps tie to L3.Isolated (the
        # build environment must not be influenced by other builds
        # or by the build's own tenant). Provenance labels tie to
        # L1.Provenance + L2.Signed.
        "DF-001": ["Build.L3.NonFalsifiable"],                     # FROM not digest-pinned
        "DF-003": ["Build.L3.NonFalsifiable"],                     # ADD remote no integrity
        "DF-004": ["Build.L3.Isolated",
                   "Build.L3.NonFalsifiable"],                     # curl-pipe
        "DF-005": ["Build.L3.Isolated"],                           # shell-eval idiom
        "DF-006": ["Build.L3.NonFalsifiable"],                     # ENV credential literal
        "DF-008": ["Build.L3.Isolated"],                           # docker --privileged
        "DF-009": ["Build.L3.NonFalsifiable"],                     # ADD where COPY suffices
        "DF-010": ["Build.L3.NonFalsifiable"],                     # apt upgrade
        "DF-012": ["Build.L3.Isolated"],                           # sudo in RUN
        "DF-016": ["Build.L1.Provenance",
                   "Build.L2.Signed"],                             # OCI provenance labels
        "DF-019": ["Build.L3.NonFalsifiable"],                     # COPY credential file
        "DF-020": ["Build.L3.NonFalsifiable"],                     # credential ARG
        # Env-bypass pack: each setting disables the trusted-source
        # channel for any in-image install. That's both an isolation
        # failure (MITM during build) and a NonFalsifiable failure
        # (substituted dep flows into the signed image).
        "DF-021": ["Build.L3.Isolated",
                   "Build.L3.NonFalsifiable"],                     # pip TLS bypass / http index
        "DF-022": ["Build.L3.NonFalsifiable"],                     # npm install (not npm ci)
        "DF-023": ["Build.L3.Isolated"],                           # LD_PRELOAD / LD_LIBRARY_PATH
        "DF-024": ["Build.L3.Isolated"],                           # npm install runs lifecycle scripts
        "DF-025": ["Build.L3.NonFalsifiable"],                     # registry token in image layer
        "DF-026": ["Build.L3.Isolated",
                   "Build.L3.NonFalsifiable"],                     # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027": ["Build.L3.Isolated",
                   "Build.L3.NonFalsifiable"],                     # PYTHONHTTPSVERIFY=0
        "DF-028": ["Build.L3.Isolated",
                   "Build.L3.NonFalsifiable"],                     # GIT_SSL_NO_VERIFY=1
        "DF-029": ["Build.L3.Isolated",
                   "Build.L3.NonFalsifiable"],                     # REQUESTS_CA_BUNDLE neutered
        "DF-030": ["Build.L3.Isolated"],                           # NODE_OPTIONS --require / --inspect
        # ── Cloud Build (GCB platform IS a SLSA build environment) ─
        "GCB-001": ["Build.L3.NonFalsifiable"],                    # step image not pinned
        "GCB-004": ["Build.L3.NonFalsifiable"],                    # community step not SHA-pinned
        "GCB-007": ["Build.L3.NonFalsifiable"],                    # version: latest secret
        # GCB-008 (no vuln scanning step) isn't a SLSA Build track
        # control — vuln scanning is dep-track posture. Left unmapped.
        "GCB-009": ["Build.L2.Signed"],                            # artifacts not signed (cosign/sigstore)
        # GCB-014 (build logging disabled) isn't a SLSA Build track
        # control on its own; the audit signal lives under OWASP
        # CICD-SEC-10. Left unmapped.
        "GCB-015": ["Build.L1.Provenance"],                        # no SBOM produced
        "GCB-016": ["Build.L3.Isolated"],                          # step dir path escape
        "GCB-017": ["Build.L1.Provenance",
                    "Build.L2.Signed",
                    "Build.L3.NonFalsifiable"],                    # image build no SLSA provenance
        "GCB-018": ["Build.L3.NonFalsifiable"],                    # legacy KMS secrets block
        "GCB-019": ["Build.L3.Isolated"],                          # shell entrypoint + user substitution
        "GCB-020": ["Build.L3.NonFalsifiable"],                    # default Cloud Build SA email
        "GCB-021": ["Build.L3.Isolated",
                    "Build.L3.Ephemeral"],                         # no private worker pool
        "GCB-022": ["Build.L3.Isolated"],                          # ALLOW_LOOSE substitution
        "GCB-023": ["Build.L3.Isolated"],                          # undeclared user substitution
        "GCB-024": ["Build.L1.Provenance"],                        # images: missing for docker push
        # GCB-025 (tags: empty) is audit/discoverability, not SLSA.
        # Existing mapping retained for backward compatibility.
        "GCB-025": ["Build.L3.NonFalsifiable"],
        # ── Cloud Build expansion ─────────────────────────────────
        "GCB-002": ["Build.L3.NonFalsifiable"],                    # default Cloud Build service account
        "GCB-003": ["Build.L3.NonFalsifiable"],                    # Secret Manager value referenced in step args
        "GCB-005": ["Build.L3.Ephemeral"],                         # build timeout unset / excessive
        "GCB-006": ["Build.L3.Isolated"],                          # dangerous shell idiom
        "GCB-010": ["Build.L3.Isolated",
                    "Build.L3.NonFalsifiable"],                    # remote script piped to shell
        "GCB-011": ["Build.L3.Isolated",
                    "Build.L3.NonFalsifiable"],                    # TLS bypass
        "GCB-012": ["Build.L3.NonFalsifiable"],                    # literal secret in pipeline body
        "GCB-013": ["Build.L3.NonFalsifiable"],                    # pkg install bypasses registry integrity
        # ── OCI image manifest + attestation content ───────────────
        # OCI-002 detects whether *any* SLSA attestation is attached;
        # the ATTEST-NNN rules verify the *content* of those
        # attestations. Together they cover L1 (provenance exists) +
        # L2 (provenance is authenticated) + L3 (provenance is
        # non-falsifiable + names an isolated builder).
        "OCI-001": ["Build.L1.Provenance"],                        # provenance annotations missing
        "OCI-002": ["Build.L1.Provenance",
                    "Build.L2.Signed"],                            # build attestation missing
        "OCI-003": ["Build.L1.Provenance"],                        # missing image.created
        "OCI-004": ["Build.L3.NonFalsifiable"],                    # foreign-layer URL reference
        "OCI-005": ["Build.L1.Provenance"],                        # missing image.licenses
        "OCI-007": ["Build.L3.NonFalsifiable"],                    # legacy schemaVersion 1
        "OCI-008": ["Build.L3.NonFalsifiable"],                    # weak digest algorithm
        "ATTEST-001": ["Build.L2.Hosted",
                       "Build.L3.Isolated",
                       "Build.L3.NonFalsifiable"],                 # untrusted builder identity
        "ATTEST-002": ["Build.L1.Provenance",
                       "Build.L3.NonFalsifiable"],                 # source-repo claim unverifiable
        "ATTEST-003": ["Build.L1.Provenance"],                     # SBOM floating versions
        "ATTEST-004": ["Build.L1.Provenance",
                       "Build.L3.NonFalsifiable"],                 # provenance lacks materials
        "ATTEST-005": ["Build.L2.Signed",
                       "Build.L3.NonFalsifiable"],                 # subject digest unpinned
        "ATTEST-006": ["Build.L1.Provenance"],                     # buildType missing
        "ATTEST-007": ["Build.L1.Provenance"],                     # SBOM supplier missing
        # ── SCM posture (source-side trust assumptions) ─────────────
        # SLSA's Build track presumes a stable, attested source. SCM
        # rules that undermine that presumption — history rewrite,
        # bypassed governance, untrusted action allowlists — map to
        # Build.L3.NonFalsifiable and Build.L2.Signed. Most SCM rules
        # cover review-control governance that's outside SLSA's
        # scope (SLSA cares about the build, not the source-side
        # review trail) and are intentionally left unmapped.
        "SCM-006":  ["Build.L2.Signed"],            # signed commits (source-side provenance root)
        "SCM-007":  ["Build.L3.NonFalsifiable"],    # force-push allowed (history rewrite breaks provenance)
        "SCM-009":  ["Build.L3.NonFalsifiable"],    # branch deletions allowed (provenance lineage erased)
        "SCM-022":  ["Build.L3.Isolated",
                     "Build.L3.NonFalsifiable"],    # allowed_actions unrestricted (untrusted 3rd-party in build)
        "SCM-029":  ["Build.L3.NonFalsifiable"],    # ruleset not enforced (governance silently disabled)
        "SCM-030":  ["Build.L3.NonFalsifiable"],    # ruleset always-bypass (governance bypassed silently)
        "SCM-034":  ["Build.L3.NonFalsifiable"],    # ruleset allows force_push
        "SCM-035":  ["Build.L3.NonFalsifiable"],    # ruleset allows deletion
        "SCM-036":  ["Build.L2.Signed"],            # ruleset lacks signed_commits
        "SCM-038":  ["Build.L3.NonFalsifiable"],    # ruleset lacks linear_history (lineage muddied)
        "SCM-039":  ["Build.L3.NonFalsifiable"],    # ruleset lacks required_workflows (scan removable in-PR)
        "SCM-008":  ["Build.L3.NonFalsifiable"],    # required status checks missing (CI gate removable)
        "SCM-033":  ["Build.L3.NonFalsifiable"],    # ruleset lacks status_checks
        "SCM-040":  ["Build.L3.NonFalsifiable"],    # ruleset lacks code_scanning gate
        "SCM-043":  ["Build.L2.Signed"],            # tag-ruleset lacks signed_commits
        "SCM-044":  ["Build.L2.Signed"],            # required_signatures bypassed for admins
        # ── Terraform / CloudFormation (IaC-native) ────────────────
        # Long-lived access keys declared as code and hard-coded
        # credentials are forgeable-provenance shapes. Sharing a
        # CodeBuild VPC with a public subnet means the build env
        # isn't isolated from public network influence.
        "TF-001":   ["Build.L3.NonFalsifiable"],    # aws_iam_access_key declared as code
        "TF-002":   ["Build.L3.NonFalsifiable"],    # hard-coded secret in resource attr
        "TF-003":   ["Build.L3.Isolated"],          # CodeBuild VPC shares public subnet
        "CF-001":   ["Build.L3.NonFalsifiable"],    # AWS::IAM::AccessKey declared as code
        "CF-002":   ["Build.L3.NonFalsifiable"],    # hard-coded secret in resource property
        "CF-003":   ["Build.L3.Isolated"],          # CodeBuild VPC shares public subnet
    },
)
