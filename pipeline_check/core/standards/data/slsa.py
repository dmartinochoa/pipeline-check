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
        # GitHub Actions
        "GHA-001":  ["Build.L3.NonFalsifiable"],                   # unpinned 3rd-party action
        "GHA-002":  ["Build.L3.NonFalsifiable", "Build.L3.Isolated"], # pull_request_target + PR head
        "GHA-003":  ["Build.L3.Isolated"],                         # script injection
        "GHA-004":  ["Build.L3.NonFalsifiable"],                   # unrestricted GITHUB_TOKEN
        # GitLab CI — supply-chain and isolation
        "GL-001":   ["Build.L3.NonFalsifiable"],                   # floating image tag
        "GL-002":   ["Build.L3.Isolated"],                         # script injection
        "GL-005":   ["Build.L3.NonFalsifiable"],                   # unpinned include
        # Bitbucket Pipelines
        "BB-001":   ["Build.L3.NonFalsifiable"],                   # unpinned pipe
        "BB-002":   ["Build.L3.Isolated"],                         # script injection
        "BB-005":   ["Build.L3.Ephemeral"],                        # unbounded runtime
        # Azure DevOps Pipelines
        "ADO-001":  ["Build.L3.NonFalsifiable"],                   # unpinned task
        "ADO-002":  ["Build.L3.Isolated"],                         # script injection
        "ADO-005":  ["Build.L3.NonFalsifiable"],                   # unpinned container
    },
)
