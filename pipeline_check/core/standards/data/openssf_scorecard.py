"""OpenSSF Scorecard v5. CI/CD posture checks.

Scorecard is a set of automated checks that score open-source projects
on supply-chain posture. Many of its checks. Dangerous-Workflow,
Pinned-Dependencies, Token-Permissions, Signed-Releases, SBOM,
Vulnerabilities, Dependency-Update-Tool, are exactly the signals this
scanner already produces from pipeline config, so the mapping is
largely 1:1.

Scorecard checks we do NOT evidence (require repo/registry introspection
outside this scanner's scope):
  Binary-Artifacts, Branch-Protection, CI-Tests, CII-Best-Practices,
  Contributors, Fuzzing, License, Maintained, Packaging,
  Security-Policy, Webhooks.

Code-Review is partially evidenced. Scorecard defines it as "PR review
required before merge", which we can't see, but pipeline-level approval
gates (CICD-SEC-1 flow-control rules) and SCM-side approval-rule
templates (CCM-001) are the closest CI/CD analogue and are included
here. SAST is partially evidenced via registry/build-side vulnerability
scanning rules (ECR-001, GCB-008, and the per-provider `vuln_scanning`
rules).
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="openssf_scorecard",
    title="OpenSSF Scorecard",
    version="5",
    url="https://github.com/ossf/scorecard/blob/main/docs/checks.md",
    controls={
        "Code-Review":            "Changes merged to the default branch require review",
        "Dangerous-Workflow":     "No dangerous patterns in CI workflows (untrusted checkout, script injection)",
        "Dependency-Update-Tool": "Project uses an automated dependency-update tool (Dependabot / Renovate)",
        "Pinned-Dependencies": (
            "Dependencies (actions, images, includes, packages) are "
            "pinned to immutable references from trusted sources"
        ),
        "SAST":                   "Project uses static analysis / vulnerability scanning",
        "SBOM":                   "Releases publish a software bill of materials",
        "Signed-Releases":        "Release artifacts are cryptographically signed",
        "Token-Permissions":      "CI tokens are scoped to the minimum required permissions",
        "Vulnerabilities":        "Project scans for and resolves known vulnerabilities",
    },
    mappings={
        # ── Pinned-Dependencies ──────────────────────────────────────
        "CB-005":   ["Pinned-Dependencies"],
        "CB-009":   ["Pinned-Dependencies"],
        "ECR-002":  ["Pinned-Dependencies"],
        "ECR-006":  ["Pinned-Dependencies"],                           # ECR pull-through untrusted upstream
        "CA-002":   ["Pinned-Dependencies"],                           # CodeArtifact public upstream
        "GHA-001":  ["Pinned-Dependencies"],
        "GHA-018":  ["Pinned-Dependencies"],                           # insecure package registry
        "GHA-025":  ["Pinned-Dependencies"],
        "GL-001":   ["Pinned-Dependencies"],
        "GL-005":   ["Pinned-Dependencies"],
        "GL-009":   ["Pinned-Dependencies"],
        "GL-018":   ["Pinned-Dependencies"],
        "GL-028":   ["Pinned-Dependencies"],
        "GL-030":   ["Pinned-Dependencies"],
        "BB-001":   ["Pinned-Dependencies"],
        "BB-009":   ["Pinned-Dependencies"],
        "BB-014":   ["Pinned-Dependencies"],
        "ADO-001":  ["Pinned-Dependencies"],
        "ADO-005":  ["Pinned-Dependencies"],
        "ADO-009":  ["Pinned-Dependencies"],
        "ADO-018":  ["Pinned-Dependencies"],
        "ADO-025":  ["Pinned-Dependencies"],
        "JF-001":   ["Pinned-Dependencies"],
        "JF-009":   ["Pinned-Dependencies"],
        "JF-018":   ["Pinned-Dependencies"],
        "CC-001":   ["Pinned-Dependencies"],
        "CC-003":   ["Pinned-Dependencies"],
        "CC-018":   ["Pinned-Dependencies"],
        "CC-029":   ["Pinned-Dependencies"],
        "GCB-001":  ["Pinned-Dependencies"],
        # Lockfile-integrity rules: package-source bypass of the lockfile
        # is a form of unpinned dependency ingestion.
        "GHA-021":  ["Pinned-Dependencies"],
        "GHA-029":  ["Pinned-Dependencies"],
        "GL-021":   ["Pinned-Dependencies"],
        "GL-027":   ["Pinned-Dependencies"],
        "BB-021":   ["Pinned-Dependencies"],
        "BB-027":   ["Pinned-Dependencies"],
        "ADO-021":  ["Pinned-Dependencies"],
        "ADO-028":  ["Pinned-Dependencies"],
        "JF-021":   ["Pinned-Dependencies"],
        "JF-031":   ["Pinned-Dependencies"],
        "CC-021":   ["Pinned-Dependencies"],
        "CC-028":   ["Pinned-Dependencies"],

        # ── Dangerous-Workflow ───────────────────────────────────────
        "CB-010":   ["Dangerous-Workflow"],                            # fork PR builds without actor filter
        "CB-011":   ["Dangerous-Workflow"],                            # malicious buildspec indicators
        "CP-003":   ["Dangerous-Workflow"],                            # polling source = source poisoning window
        "CP-007":   ["Dangerous-Workflow"],                            # v2 PR trigger all branches
        "GHA-002":  ["Dangerous-Workflow"],
        "GHA-003":  ["Dangerous-Workflow"],
        "GHA-009":  ["Dangerous-Workflow"],
        "GHA-010":  ["Dangerous-Workflow"],
        "GHA-011":  ["Dangerous-Workflow"],
        "GHA-013":  ["Dangerous-Workflow"],
        "GHA-023":  ["Dangerous-Workflow"],
        "GHA-026":  ["Dangerous-Workflow"],
        "GHA-027":  ["Dangerous-Workflow"],
        "GHA-028":  ["Dangerous-Workflow"],
        "GL-002":   ["Dangerous-Workflow"],
        "GL-011":   ["Dangerous-Workflow"],
        "GL-012":   ["Dangerous-Workflow"],
        "GL-023":   ["Dangerous-Workflow"],
        "GL-025":   ["Dangerous-Workflow"],                            # malicious activity
        "GL-026":   ["Dangerous-Workflow"],
        "BB-002":   ["Dangerous-Workflow"],
        "BB-018":   ["Dangerous-Workflow"],
        "BB-023":   ["Dangerous-Workflow"],
        "BB-025":   ["Dangerous-Workflow"],                            # malicious activity
        "BB-026":   ["Dangerous-Workflow"],
        "ADO-002":  ["Dangerous-Workflow"],
        "ADO-011":  ["Dangerous-Workflow"],
        "ADO-012":  ["Dangerous-Workflow"],
        "ADO-019":  ["Dangerous-Workflow"],
        "ADO-023":  ["Dangerous-Workflow"],
        "ADO-026":  ["Dangerous-Workflow"],                            # malicious activity
        "ADO-027":  ["Dangerous-Workflow"],
        "JF-002":   ["Dangerous-Workflow"],
        "JF-012":   ["Dangerous-Workflow"],
        "JF-013":   ["Dangerous-Workflow"],
        "JF-019":   ["Dangerous-Workflow"],
        "JF-023":   ["Dangerous-Workflow"],
        "JF-029":   ["Dangerous-Workflow"],                            # malicious activity
        "JF-030":   ["Dangerous-Workflow"],
        "CC-002":   ["Dangerous-Workflow"],
        "CC-012":   ["Dangerous-Workflow"],
        "CC-013":   ["Dangerous-Workflow"],                            # no branch filter on jobs
        "CC-023":   ["Dangerous-Workflow"],
        "CC-025":   ["Dangerous-Workflow"],
        "CC-026":   ["Dangerous-Workflow"],                            # malicious activity
        "CC-027":   ["Dangerous-Workflow"],
        "GCB-004":  ["Dangerous-Workflow"],
        "GCB-006":  ["Dangerous-Workflow"],
        # curl|bash is classic Dangerous-Workflow territory
        "GHA-016":  ["Dangerous-Workflow"],
        "GL-016":   ["Dangerous-Workflow"],
        "BB-012":   ["Dangerous-Workflow"],
        "ADO-016":  ["Dangerous-Workflow"],
        "JF-016":   ["Dangerous-Workflow"],
        "CC-016":   ["Dangerous-Workflow"],

        # ── Token-Permissions ────────────────────────────────────────
        # Scorecard's check targets GITHUB_TOKEN scope, but applies in
        # spirit to any overbroad CI identity.
        "GHA-004":  ["Token-Permissions"],
        "GHA-005":  ["Token-Permissions"],
        "GHA-008":  ["Token-Permissions"],
        "GHA-019":  ["Token-Permissions"],
        "GL-003":   ["Token-Permissions"],
        "GL-008":   ["Token-Permissions"],
        "GL-013":   ["Token-Permissions"],
        "GL-020":   ["Token-Permissions"],
        "BB-003":   ["Token-Permissions"],
        "BB-008":   ["Token-Permissions"],
        "BB-011":   ["Token-Permissions"],
        "BB-017":   ["Token-Permissions"],
        "BB-019":   ["Token-Permissions"],
        "ADO-003":  ["Token-Permissions"],
        "ADO-008":  ["Token-Permissions"],
        "ADO-014":  ["Token-Permissions"],
        "JF-004":   ["Token-Permissions"],
        "JF-008":   ["Token-Permissions"],
        "JF-010":   ["Token-Permissions"],
        "CC-005":   ["Token-Permissions"],
        "CC-008":   ["Token-Permissions"],
        "CC-019":   ["Token-Permissions"],
        "CC-030":   ["Token-Permissions"],
        "GCB-002":  ["Token-Permissions"],
        "GCB-003":  ["Token-Permissions"],
        "GCB-007":  ["Token-Permissions"],
        "CB-001":   ["Token-Permissions"],
        "CB-006":   ["Token-Permissions"],
        "CP-004":   ["Token-Permissions"],
        "CCM-003":  ["Token-Permissions"],                             # CodeCommit cross-account trigger
        "CA-004":   ["Token-Permissions"],                             # CodeArtifact wildcard Resource
        "IAM-001":  ["Token-Permissions"],
        "IAM-002":  ["Token-Permissions"],
        "IAM-003":  ["Token-Permissions"],                             # no permission boundary
        "IAM-004":  ["Token-Permissions"],
        "IAM-005":  ["Token-Permissions"],                             # relaxed external-trust
        "IAM-006":  ["Token-Permissions"],
        "IAM-007":  ["Token-Permissions"],
        "IAM-008":  ["Token-Permissions"],                             # OIDC audience not pinned
        "KMS-001":  ["Token-Permissions"],                             # CMK rotation disabled
        "KMS-002":  ["Token-Permissions"],                             # KMS policy wildcard
        "LMB-002":  ["Token-Permissions"],                             # public Lambda function URL
        "LMB-003":  ["Token-Permissions"],                             # plaintext secrets in Lambda env
        "LMB-004":  ["Token-Permissions"],                             # public Lambda resource policy
        "SM-001":   ["Token-Permissions"],
        "SM-002":   ["Token-Permissions"],                             # Secrets Manager public policy
        "SSM-001":  ["Token-Permissions"],
        "SSM-002":  ["Token-Permissions"],                             # SSM SecureString default key

        # ── Signed-Releases ──────────────────────────────────────────
        "SIGN-001": ["Signed-Releases"],
        "SIGN-002": ["Signed-Releases"],
        "CP-002":   ["Signed-Releases"],
        "ECR-005":  ["Signed-Releases"],
        "CA-001":   ["Signed-Releases"],                               # CodeArtifact KMS (artifact integrity)
        "LMB-001":  ["Signed-Releases"],                               # Lambda code-signing config
        "GHA-006":  ["Signed-Releases"],
        "GHA-024":  ["Signed-Releases"],
        "GL-006":   ["Signed-Releases"],
        "GL-024":   ["Signed-Releases"],
        "BB-006":   ["Signed-Releases"],
        "BB-024":   ["Signed-Releases"],
        "ADO-006":  ["Signed-Releases"],
        "ADO-024":  ["Signed-Releases"],
        "JF-006":   ["Signed-Releases"],
        "JF-028":   ["Signed-Releases"],
        "CC-006":   ["Signed-Releases"],
        "CC-024":   ["Signed-Releases"],
        "GCB-009":  ["Signed-Releases"],

        # ── SBOM ─────────────────────────────────────────────────────
        "GHA-007":  ["SBOM"],
        "GL-007":   ["SBOM"],
        "BB-007":   ["SBOM"],
        "ADO-007":  ["SBOM"],
        "JF-007":   ["SBOM"],
        "CC-007":   ["SBOM"],

        # ── Vulnerabilities / SAST ───────────────────────────────────
        "ECR-001":  ["Vulnerabilities", "SAST"],
        "ECR-007":  ["Vulnerabilities", "SAST"],                       # Inspector v2 enhanced scanning
        "GHA-020":  ["Vulnerabilities", "SAST"],
        "GL-019":   ["Vulnerabilities", "SAST"],
        "BB-015":   ["Vulnerabilities", "SAST"],
        "ADO-020":  ["Vulnerabilities", "SAST"],
        "JF-020":   ["Vulnerabilities", "SAST"],
        "CC-020":   ["Vulnerabilities", "SAST"],
        "GCB-008":  ["Vulnerabilities", "SAST"],

        # ── Dependency-Update-Tool ───────────────────────────────────
        "GHA-022":  ["Dependency-Update-Tool"],
        "GL-022":   ["Dependency-Update-Tool"],
        "BB-022":   ["Dependency-Update-Tool"],
        "ADO-022":  ["Dependency-Update-Tool"],
        "JF-022":   ["Dependency-Update-Tool"],
        "CC-022":   ["Dependency-Update-Tool"],

        # ── Code-Review (loose: pipeline approval gates) ─────────────
        "CP-001":   ["Code-Review"],
        "CP-005":   ["Code-Review"],
        "CD-002":   ["Code-Review"],
        "CCM-001":  ["Code-Review"],                                   # CodeCommit approval rule template
        "GHA-014":  ["Code-Review"],
        "GL-004":   ["Code-Review"],
        "GL-029":   ["Code-Review"],
        "BB-004":   ["Code-Review"],
        "ADO-004":  ["Code-Review"],
        "JF-005":   ["Code-Review"],
        "JF-024":   ["Code-Review"],
        "JF-026":   ["Code-Review"],                                   # build job unchecked
        "CC-009":   ["Code-Review"],
        "CB-008":   ["Code-Review"],
        # ── Buildkite ────────────────────────────────────────────────
        "BK-001":   ["Pinned-Dependencies"],                           # plugin not pinned
        "BK-002":   ["Token-Permissions"],                             # leaked creds in env
        "BK-003":   ["Dangerous-Workflow"],                            # untrusted variable injection
        "BK-004":   ["Dangerous-Workflow", "Pinned-Dependencies"],     # curl | bash
        "BK-005":   ["Dangerous-Workflow"],                            # Docker privileged
        "BK-007":   ["Code-Review"],                                   # deploy not gated
        "BK-008":   ["Pinned-Dependencies"],                           # TLS bypass
        "BK-009":   ["Signed-Releases"],                               # artifact signing
        "BK-010":   ["SBOM"],                                          # SBOM
        "BK-011":   ["Signed-Releases", "SBOM"],                       # SLSA provenance
        "BK-012":   ["Vulnerabilities", "SAST"],                       # vuln scanning
        # ── Tekton ───────────────────────────────────────────────────
        "TKN-001":  ["Pinned-Dependencies"],                           # step image not digest-pinned
        "TKN-002":  ["Dangerous-Workflow"],                            # step privileged
        "TKN-003":  ["Dangerous-Workflow"],                            # param injection
        "TKN-004":  ["Dangerous-Workflow"],                            # hostPath / namespaces
        "TKN-005":  ["Token-Permissions"],                             # leaked creds
        "TKN-007":  ["Token-Permissions"],                             # default SA
        "TKN-008":  ["Dangerous-Workflow", "Pinned-Dependencies"],     # remote install / TLS
        "TKN-009":  ["Signed-Releases"],                               # artifact signing
        "TKN-010":  ["SBOM"],                                          # SBOM
        "TKN-011":  ["Signed-Releases", "SBOM"],                       # SLSA provenance
        "TKN-012":  ["Vulnerabilities", "SAST"],                       # vuln scanning
        # ── Argo Workflows ───────────────────────────────────────────
        "ARGO-001": ["Pinned-Dependencies"],                           # template image not pinned
        "ARGO-002": ["Dangerous-Workflow"],                            # template privileged
        "ARGO-003": ["Token-Permissions"],                             # default SA
        "ARGO-004": ["Dangerous-Workflow"],                            # hostPath / namespaces
        "ARGO-005": ["Dangerous-Workflow"],                            # parameter injection
        "ARGO-006": ["Token-Permissions"],                             # leaked creds
        "ARGO-008": ["Dangerous-Workflow", "Pinned-Dependencies"],     # remote install / TLS
        "ARGO-009": ["Signed-Releases"],                               # artifact signing
        "ARGO-010": ["SBOM"],                                          # SBOM
        "ARGO-011": ["Signed-Releases", "SBOM"],                       # SLSA provenance
        "ARGO-012": ["Vulnerabilities", "SAST"],                       # vuln scanning
        # ── Helm chart-supply-chain ──────────────────────────────────
        # Chart deps ARE pinned dependencies in the Scorecard sense —
        # an unlocked Chart.lock is a Pinned-Dependencies failure.
        # HELM-005 (maintainers) and HELM-006 (kubeVersion) sit
        # outside Scorecard's check set; left unmapped on purpose.
        "HELM-001": ["Pinned-Dependencies"],                           # legacy v1 (no in-tree lock)
        "HELM-002": ["Pinned-Dependencies"],                           # missing Chart.lock digests
        "HELM-003": ["Pinned-Dependencies"],                           # non-HTTPS dep repo
        "HELM-004": ["Pinned-Dependencies"],                           # version range
        # ── Dockerfile (image base / build deps = pinned deps) ────
        # Scorecard's Pinned-Dependencies covers actions, images,
        # includes, and packages. ``FROM image:tag`` without a
        # digest is the canonical image-not-pinned failure.
        "DF-001": ["Pinned-Dependencies"],                              # FROM not digest-pinned
        "DF-003": ["Pinned-Dependencies"],                              # ADD remote no integrity
        "DF-004": ["Pinned-Dependencies", "Dangerous-Workflow"],        # curl-pipe
        "DF-005": ["Dangerous-Workflow"],                               # shell-eval
        "DF-006": ["Token-Permissions"],                                # ENV credential literal
        "DF-010": ["Pinned-Dependencies"],                              # apt upgrade unpinned
        "DF-016": ["SBOM"],                                             # missing OCI provenance
        "DF-019": ["Token-Permissions"],                                # COPY credential file
        "DF-020": ["Token-Permissions"],                                # credential ARG
    },
)
