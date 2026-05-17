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
        # CodeBuild, isolation & ephemerality
        "CB-002":   ["Build.L3.Isolated"],                         # privileged mode breaks isolation
        "CB-004":   ["Build.L3.Ephemeral"],                        # unbounded timeout ≠ ephemeral
        "CB-007":   ["Build.L3.Isolated", "Build.L3.Ephemeral"],   # uncapped webhook triggers
        # CodePipeline, provenance storage integrity
        "CP-001":   ["Build.L3.NonFalsifiable"],                   # no approval gate
        "CP-002":   ["Build.L1.Provenance", "Build.L2.Signed"],    # artifact store not CMK-encrypted
        # ECR, artifact-to-provenance binding
        "ECR-002":  ["Build.L2.Signed", "Build.L3.NonFalsifiable"],# mutable tags break binding
        # IAM, tenant-forgeable provenance if over-privileged
        "IAM-001":  ["Build.L3.NonFalsifiable"],                   # admin can rewrite artifacts
        "IAM-002":  ["Build.L3.NonFalsifiable"],                   # wildcard action
        "IAM-004":  ["Build.L3.NonFalsifiable"],                   # PassRole * → role hopping
        "IAM-006":  ["Build.L3.NonFalsifiable"],                   # wildcard resource
        # PBAC, cross-build contamination breaks isolation
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
        "DF-008": ["Build.L3.Isolated"],                           # docker --privileged
        "DF-010": ["Build.L3.NonFalsifiable"],                     # apt upgrade
        "DF-016": ["Build.L1.Provenance",
                   "Build.L2.Signed"],                             # OCI provenance labels
        # ── Cloud Build (GCB platform IS a SLSA build environment) ─
        "GCB-001": ["Build.L3.NonFalsifiable"],                    # step image not pinned
        "GCB-004": ["Build.L3.NonFalsifiable"],                    # community step not SHA-pinned
        "GCB-007": ["Build.L3.NonFalsifiable"],                    # version: latest secret
        "GCB-008": ["Build.L1.Provenance",
                    "Build.L2.Signed"],                            # no signing
        "GCB-009": ["Build.L1.Provenance"],                        # no SBOM
        "GCB-014": ["Build.L3.Isolated"],                          # untrusted substitution
        "GCB-015": ["Build.L1.Provenance",
                    "Build.L2.Signed",
                    "Build.L3.NonFalsifiable"],                    # no provenance attestation
        "GCB-018": ["Build.L3.NonFalsifiable"],                    # legacy gcr.io
        "GCB-019": ["Build.L3.Isolated"],                          # privileged step
        "GCB-021": ["Build.L3.Isolated",
                    "Build.L3.Ephemeral"],                         # no private worker pool
        "GCB-022": ["Build.L3.Isolated"],                          # ALLOW_LOOSE substitution
        "GCB-023": ["Build.L1.Provenance",
                    "Build.L2.Signed"],                            # build artifacts not signed
        "GCB-024": ["Build.L1.Provenance"],                        # missing provenance labels
        "GCB-025": ["Build.L3.NonFalsifiable"],                    # outdated runner image
        # ── OCI image manifest + attestation content ───────────────
        # OCI-002 detects whether *any* SLSA attestation is attached;
        # the ATTEST-NNN rules verify the *content* of those
        # attestations. Together they cover L1 (provenance exists) +
        # L2 (provenance is authenticated) + L3 (provenance is
        # non-falsifiable + names an isolated builder).
        "OCI-001": ["Build.L1.Provenance"],                        # provenance annotations missing
        "OCI-002": ["Build.L1.Provenance",
                    "Build.L2.Signed"],                            # build attestation missing
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
    },
)
