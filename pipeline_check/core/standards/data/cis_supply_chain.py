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
        "4.3.3": "Ensure package registries use authentication and authorisation",
        "4.4.1": "Ensure artifacts have provenance/SBOM metadata",
        # 5. Deployment
        "5.1.4": "Ensure deployment configuration manifests are reviewed before apply",
        "5.2.1": "Ensure deployment environments are separated",
        "5.2.3": "Ensure deployment environment activity is audited",
    },
    mappings={
        # CodeBuild
        "CB-001":   ["2.3.4", "2.4.3"],                  # plaintext secrets
        "CB-002":   ["2.1.3", "2.1.6"],                  # privileged mode / host network
        "CB-003":   ["2.3.7"],                           # build logs disabled
        "CB-004":   ["2.2.2"],                           # no timeout → not single-use
        "CB-005":   ["2.1.3", "1.4.1"],                  # outdated managed build image
        "CB-006":   ["1.3.4"],                           # long-lived source token
        "CB-007":   ["2.3.8"],                           # webhook no filter group
        # CodePipeline
        "CP-001":   ["2.3.8", "5.1.4"],                  # no manual approval
        "CP-002":   ["2.4.2", "4.1.1"],                  # artifact store not CMK-encrypted
        "CP-003":   ["2.3.8"],                           # polling source
        "CP-004":   ["1.3.4"],                           # OAuth token source
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
        # IAM
        "IAM-001":  ["2.4.3"],
        "IAM-002":  ["2.4.3"],
        "IAM-003":  ["2.4.3"],
        "IAM-004":  ["2.4.3"],
        "IAM-005":  ["2.4.3", "1.3.4"],                  # sts:ExternalId
        "IAM-006":  ["2.4.3"],
        # PBAC
        "PBAC-001": ["2.1.6"],                           # no VPC boundary
        "PBAC-002": ["2.2.2", "2.4.3"],                  # shared service role
        # S3 artifact bucket
        "S3-001":   ["4.2.1"],
        "S3-002":   ["4.1.1"],
        "S3-003":   ["4.1.1", "4.4.1"],                  # versioning = provenance history
        "S3-004":   ["2.3.7", "5.2.3"],
        "S3-005":   ["4.2.1"],
        # GitHub Actions
        "GHA-001":  ["1.4.1", "3.1.5"],                  # unpinned 3rd-party action
        "GHA-002":  ["2.1.3", "2.3.8"],                  # pull_request_target + PR head
        "GHA-003":  ["2.1.3"],                           # script injection
        "GHA-004":  ["2.4.3"],                           # unrestricted GITHUB_TOKEN
        "GHA-005":  ["1.3.4"],                           # long-lived AWS keys
        "GHA-006":  ["4.1.1"],                           # artifact signing
        "GHA-007":  ["4.4.1"],                           # SBOM
        "GHA-040":  ["1.4.1", "3.1.3"],                  # known-compromised action ref
        "GHA-041":  ["3.1.3"],                           # single-maintainer action
        "GHA-042":  ["3.1.3"],                           # very-young action repo
        "GHA-043":  ["3.1.3"],                           # low-star + sensitive perms
        "GHA-047":  ["3.1.3"],                           # fresh-ref cooldown
        # GitLab CI
        "GL-001":   ["1.4.1", "3.1.5"],
        "GL-002":   ["2.1.3", "2.3.8"],
        "GL-003":   ["2.3.4", "2.4.3"],
        "GL-004":   ["5.1.4", "5.2.1"],
        "GL-005":   ["1.4.1", "3.1.3", "3.1.5"],
        "GL-006":   ["4.1.1"],
        "GL-007":   ["4.4.1"],
        # Bitbucket Pipelines
        "BB-001":   ["1.4.1", "3.1.5"],
        "BB-002":   ["2.1.3", "2.3.8"],
        "BB-003":   ["2.3.4", "2.4.3"],
        "BB-004":   ["5.1.4", "5.2.1"],
        "BB-005":   ["2.2.2"],
        "BB-006":   ["4.1.1"],
        "BB-007":   ["4.4.1"],
        # Azure DevOps Pipelines
        "ADO-001":  ["1.4.1", "3.1.5"],
        "ADO-002":  ["2.1.3", "2.3.8"],
        "ADO-003":  ["2.3.4", "2.4.3"],
        "ADO-004":  ["5.1.4", "5.2.1"],
        "ADO-005":  ["1.4.1", "3.1.5"],
        "ADO-006":  ["4.1.1"],
        "ADO-007":  ["4.4.1"],
        # CircleCI
        "CC-001":   ["1.4.1", "3.1.5"],
        "CC-002":   ["2.1.3"],
        "CC-003":   ["1.4.1", "3.1.5"],
        "CC-004":   ["2.3.4", "2.4.3"],
        "CC-005":   ["1.3.4"],
        "CC-006":   ["4.1.1"],
        "CC-007":   ["4.4.1"],
        "CC-008":   ["2.3.4", "2.4.3"],
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
        # ── Buildkite ─────────────────────────────────────────────
        "BK-001":   ["1.4.1", "3.1.5"],            # plugin not pinned
        "BK-002":   ["2.3.4"],                     # secret in env
        "BK-003":   ["2.1.3", "2.3.8"],            # untrusted variable injection
        "BK-004":   ["1.4.1", "3.1.5"],            # curl | bash
        "BK-005":   ["2.1.3"],                     # Docker privileged
        "BK-006":   ["2.2.2"],                     # no timeout
        "BK-007":   ["2.3.8", "5.1.4"],            # deploy not gated
        "BK-008":   ["3.1.3"],                     # TLS bypass
        "BK-009":   ["4.1.1"],                     # artifact signing
        "BK-010":   ["4.4.1"],                     # SBOM
        "BK-011":   ["4.1.1", "4.4.1"],            # SLSA provenance
        "BK-012":   ["1.4.1", "3.1.3"],            # vuln scanning
        # ── Tekton ────────────────────────────────────────────────
        "TKN-001":  ["1.4.1", "3.1.3"],            # step image not digest-pinned
        "TKN-002":  ["2.1.3"],                     # step privileged
        "TKN-003":  ["2.1.3", "2.3.8"],            # param injection
        "TKN-004":  ["2.1.3"],                     # hostPath / host namespaces
        "TKN-005":  ["2.3.4"],                     # leaked creds
        "TKN-006":  ["2.2.2"],                     # no timeout
        "TKN-007":  ["2.4.3"],                     # default SA
        "TKN-008":  ["1.4.1", "3.1.5"],            # remote install / TLS
        "TKN-009":  ["4.1.1"],                     # artifact signing
        "TKN-010":  ["4.4.1"],                     # SBOM
        "TKN-011":  ["4.1.1", "4.4.1"],            # SLSA provenance
        "TKN-012":  ["1.4.1", "3.1.3"],            # vuln scanning
        # ── Argo Workflows ────────────────────────────────────────
        "ARGO-001": ["1.4.1", "3.1.3"],            # template image not pinned
        "ARGO-002": ["2.1.3"],                     # template privileged
        "ARGO-003": ["2.4.3"],                     # default SA
        "ARGO-004": ["2.1.3"],                     # hostPath / host namespaces
        "ARGO-005": ["2.1.3", "2.3.8"],            # parameter injection
        "ARGO-006": ["2.3.4"],                     # leaked creds
        "ARGO-007": ["2.2.2"],                     # no activeDeadlineSeconds
        "ARGO-008": ["1.4.1", "3.1.5"],            # remote install / TLS
        "ARGO-009": ["4.1.1"],                     # artifact signing
        "ARGO-010": ["4.4.1"],                     # SBOM
        "ARGO-011": ["4.1.1", "4.4.1"],            # SLSA provenance
        "ARGO-012": ["1.4.1", "3.1.3"],            # vuln scanning
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
        "DF-006": ["2.3.4"],                       # ENV credential literal
        "DF-008": ["2.1.3"],                       # docker --privileged
        "DF-010": ["1.4.1"],                       # apt upgrade unpinned
        "DF-011": ["1.4.1"],                       # no cache cleanup
        "DF-012": ["2.1.3"],                       # RUN sudo
        "DF-013": ["2.1.3", "2.1.6"],              # sensitive EXPOSE / network
        "DF-014": ["2.1.3"],                       # WORKDIR /etc
        "DF-015": ["2.1.3"],                       # chmod 777
        "DF-016": ["4.4.1"],                       # OCI provenance labels
        "DF-017": ["2.1.3"],                       # PATH world-writable
        "DF-018": ["2.1.3"],                       # chown system path
        "DF-019": ["2.3.4"],                       # COPY credential file
        "DF-020": ["2.3.4"],                       # credential ARG
        # ── Cloud Build ────────────────────────────────────────────
        # Mirrors the GCB-* coverage other CI providers got across
        # rounds 22-24 in the catalog.
        "GCB-001": ["1.4.1", "3.1.3"],             # step image not pinned
        "GCB-002": ["2.1.3"],                      # plaintext env secret
        "GCB-003": ["2.3.4"],                      # plain script secret
        "GCB-004": ["1.4.1", "3.1.3"],             # community step not SHA-pinned
        "GCB-005": ["2.3.4"],                      # secret-shaped substitution
        "GCB-006": ["2.3.7"],                      # build logging disabled
        "GCB-007": ["1.4.1", "3.1.3"],             # version: latest secret
        "GCB-008": ["2.4.2"],                      # no signing step
        "GCB-009": ["4.4.1"],                      # no SBOM
        "GCB-010": ["2.1.6"],                      # default network egress
        "GCB-011": ["3.1.5"],                      # TLS bypass
        "GCB-012": ["1.4.1"],                      # no vuln scan
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
        # SCM posture (governance scanned via the GitHub REST API)
        "SCM-001":  ["1.1.17"],                     # default branch unprotected
        "SCM-002":  ["1.1.5"],                      # required reviews missing
        "SCM-003":  ["1.1.7"],                      # default code scanning disabled (SAST)
        "SCM-004":  ["1.5.1"],                      # secret scanning disabled
        "SCM-005":  ["1.1.8"],                      # Dependabot security updates off (SCA)
        "SCM-006":  ["1.1.6"],                      # signed commits not required
        "SCM-007":  ["1.1.17"],                     # force-push allowed
        "SCM-008":  ["1.1.5", "1.1.7"],             # required status checks missing
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
    },
)
