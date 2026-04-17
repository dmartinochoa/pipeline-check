"""SLSA (Supply-chain Levels for Software Artifacts) v1.0 — Build track.

SLSA v1.0 organizes requirements into "tracks". This module covers the
Build track (L1–L3) — the only track whose requirements are evidenced
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
        # Build L1 — provenance exists
        "Build.L1.Scripted":   "Build L1: Build process is fully defined and automated (scripted build)",
        "Build.L1.Provenance": "Build L1: Provenance describing how the artifact was produced is generated",
        # Build L2 — hosted build platform with signed provenance
        "Build.L2.Hosted":     "Build L2: Builds run on a hosted build platform (not a developer workstation)",
        "Build.L2.Signed":     "Build L2: Provenance is authenticated and cannot be forged by tenants",
        # Build L3 — hardened builds
        "Build.L3.Isolated":   "Build L3: Build runs in an isolated environment not influenced by other builds",
        "Build.L3.Ephemeral":  "Build L3: Build environment is ephemeral and provisioned fresh for each run",
        "Build.L3.NonFalsifiable": "Build L3: Provenance cannot be falsified by the build's own tenant",
    },
    mappings={
        # CodeBuild — isolation & ephemerality
        "CB-002":   ["Build.L3.Isolated"],                         # privileged mode breaks isolation
        "CB-004":   ["Build.L3.Ephemeral"],                        # unbounded timeout ≠ ephemeral
        "CB-007":   ["Build.L3.Isolated", "Build.L3.Ephemeral"],   # uncapped webhook triggers
        # CodePipeline — provenance storage integrity
        "CP-001":   ["Build.L3.NonFalsifiable"],                   # no approval gate
        "CP-002":   ["Build.L1.Provenance", "Build.L2.Signed"],    # artifact store not CMK-encrypted
        # ECR — artifact-to-provenance binding
        "ECR-002":  ["Build.L2.Signed", "Build.L3.NonFalsifiable"],# mutable tags break binding
        # IAM — tenant-forgeable provenance if over-privileged
        "IAM-001":  ["Build.L3.NonFalsifiable"],                   # admin can rewrite artifacts
        "IAM-002":  ["Build.L3.NonFalsifiable"],                   # wildcard action
        "IAM-004":  ["Build.L3.NonFalsifiable"],                   # PassRole * → role hopping
        "IAM-006":  ["Build.L3.NonFalsifiable"],                   # wildcard resource
        # PBAC — cross-build contamination breaks isolation
        "PBAC-001": ["Build.L3.Isolated"],                         # no VPC boundary
        "PBAC-002": ["Build.L3.Isolated"],                         # shared service role
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
        # ── Jenkins ───────────────────────────────────────────────
        "JF-001":   ["Build.L3.NonFalsifiable"],                   # unpinned shared library
        "JF-002":   ["Build.L3.Isolated"],                         # script injection
        "JF-003":   ["Build.L3.Isolated"],                         # agent any — no isolation
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
    },
)
