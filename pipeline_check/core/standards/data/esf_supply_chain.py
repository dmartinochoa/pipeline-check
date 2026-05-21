"""NSA/CISA Enduring Security Framework. Securing the Software Supply Chain.

Three-volume guidance published by the NSA/CISA/ODNI Enduring Security
Framework working group (Developer 2022, Supplier 2022, Customer 2022).
The mitigations cut across the SDLC: secure development, verified
third-party components, hardened build environments, and secure
delivery. This module maps the recommendations this scanner can
evidence from AWS / GitHub Actions / GitLab / Bitbucket / Azure /
Terraform state.

Control IDs follow ``ESF-<volume>-<topic>``:
    D = Developer, S = Supplier, C = Customer
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="esf_supply_chain",
    title="NSA/CISA ESF. Securing the Software Supply Chain",
    version="2022",
    url="https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain-recommended-practices-guide-developers",
    controls={
        # Developer guide, secure development & build
        "ESF-D-BUILD-ENV":       "Harden the build environment (isolated, minimal, ephemeral workers)",
        "ESF-D-BUILD-LOGS":      "Generate and preserve build audit logs",
        "ESF-D-BUILD-TIMEOUT":   "Enforce bounded build execution (single-use, time-limited)",
        "ESF-D-SECRETS":         "Protect secrets used during build; no secrets in source or env",
        "ESF-D-PRIV-BUILD":      "Avoid privileged / host-networked build workers",
        "ESF-D-SIGN-ARTIFACTS":  "Sign build artifacts and verify signatures before release",
        "ESF-D-SBOM":            "Produce SBOM / provenance metadata with every build",
        "ESF-D-CODE-REVIEW":     "Require peer review of source and pipeline configuration",
        "ESF-D-TOKEN-HYGIENE":   "Use short-lived, federated credentials (OIDC), not long-lived tokens",
        "ESF-D-INJECTION":       "Prevent script / template injection from untrusted pipeline context",
        "ESF-D-TAMPER":          "Protect build artifacts from tampering and detect unauthorized modification",
        # Supplier guide, verify and gate third-party inputs
        "ESF-S-VERIFY-DEPS":     "Verify third-party and open-source dependencies before use",
        "ESF-S-PIN-DEPS":        "Pin dependencies / actions / images to immutable digests",
        "ESF-S-TRUSTED-REG":     "Use only trusted, authenticated package and image registries",
        "ESF-S-VULN-MGMT":       "Scan inbound artifacts (images, packages) for known vulnerabilities",
        "ESF-S-IMMUTABLE":       "Enforce artifact / tag immutability to preserve provenance",
        "ESF-S-PROVENANCE":      "Generate and verify provenance metadata (SLSA / in-toto) for produced artifacts",
        # Customer guide, deployment & runtime governance
        "ESF-C-APPROVAL":        "Require explicit approval before production deployment",
        "ESF-C-ROLLBACK":        "Automated rollback on deployment failure or alarm",
        "ESF-C-DEPLOY-MON":      "Monitor deployments with alarms / health checks",
        "ESF-C-ENV-SEP":         "Separate deployment environments (dev / staging / prod)",
        "ESF-C-ARTIFACT-AUTHZ":  "Restrict access to artifact storage and deployment pipelines",
        "ESF-C-LEAST-PRIV":      "Apply least-privilege to CI/CD service roles and pipelines",
        "ESF-C-AUDIT":           "Audit deployment / pipeline activity and retain logs",
    },
    mappings={
        # ── Degraded-mode findings (API access failures) ──────────
        "CB-000":   ["ESF-C-AUDIT"],
        "CP-000":   ["ESF-C-AUDIT"],
        "CD-000":   ["ESF-C-AUDIT"],
        "ECR-000":  ["ESF-C-AUDIT"],
        "IAM-000":  ["ESF-C-AUDIT"],
        "PBAC-000": ["ESF-C-AUDIT"],
        "S3-000":   ["ESF-C-AUDIT"],
        # ── CodeBuild ──────────────────────────────────────────────
        "CB-001":   ["ESF-D-SECRETS"],
        "CB-002":   ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "CB-003":   ["ESF-D-BUILD-LOGS", "ESF-C-AUDIT"],
        "CB-004":   ["ESF-D-BUILD-TIMEOUT", "ESF-D-BUILD-ENV"],
        "CB-005":   ["ESF-S-VERIFY-DEPS", "ESF-S-PIN-DEPS"],
        "CB-006":   ["ESF-D-TOKEN-HYGIENE"],
        "CB-007":   ["ESF-D-CODE-REVIEW"],
        "CB-011":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        # ── CodePipeline ───────────────────────────────────────────
        "CP-001":   ["ESF-C-APPROVAL", "ESF-D-CODE-REVIEW"],
        "CP-002":   ["ESF-D-SIGN-ARTIFACTS", "ESF-C-ARTIFACT-AUTHZ"],
        "CP-003":   ["ESF-D-CODE-REVIEW"],
        "CP-004":   ["ESF-D-TOKEN-HYGIENE"],
        # ── CodeDeploy ─────────────────────────────────────────────
        "CD-001":   ["ESF-C-ROLLBACK"],
        "CD-002":   ["ESF-C-ENV-SEP", "ESF-C-APPROVAL", "ESF-C-ROLLBACK"],
        "CD-003":   ["ESF-C-DEPLOY-MON"],
        # ── CloudWatch + EventBridge (deploy monitoring) ──────────
        "CW-001":   ["ESF-C-DEPLOY-MON"],   # no FailedBuilds alarm
        "EB-001":   ["ESF-C-DEPLOY-MON"],   # no pipeline-failure event rule
        # ── ECR ────────────────────────────────────────────────────
        "ECR-001":  ["ESF-S-VULN-MGMT", "ESF-S-VERIFY-DEPS"],
        "ECR-002":  ["ESF-S-IMMUTABLE", "ESF-D-SBOM", "ESF-C-ROLLBACK"],   # mutable tags break rollback-by-digest
        "ECR-003":  ["ESF-S-TRUSTED-REG", "ESF-C-ARTIFACT-AUTHZ"],
        "ECR-004":  ["ESF-D-BUILD-ENV"],
        "ECR-005":  ["ESF-D-SIGN-ARTIFACTS"],
        # ── IAM ────────────────────────────────────────────────────
        "IAM-001":  ["ESF-C-LEAST-PRIV"],
        "IAM-002":  ["ESF-C-LEAST-PRIV"],
        "IAM-003":  ["ESF-C-LEAST-PRIV"],
        "IAM-004":  ["ESF-C-LEAST-PRIV"],
        "IAM-005":  ["ESF-C-LEAST-PRIV", "ESF-D-TOKEN-HYGIENE"],
        "IAM-006":  ["ESF-C-LEAST-PRIV"],
        # ── PBAC ───────────────────────────────────────────────────
        "PBAC-001": ["ESF-D-BUILD-ENV"],
        "PBAC-002": ["ESF-C-LEAST-PRIV", "ESF-D-BUILD-TIMEOUT"],
        # ── S3 artifact bucket ─────────────────────────────────────
        "S3-001":   ["ESF-C-ARTIFACT-AUTHZ"],
        "S3-002":   ["ESF-D-SIGN-ARTIFACTS"],
        # versioning = ability to recover previous state
        "S3-003":   ["ESF-S-IMMUTABLE", "ESF-D-SBOM", "ESF-C-ROLLBACK"],
        "S3-004":   ["ESF-C-AUDIT"],
        "S3-005":   ["ESF-C-ARTIFACT-AUTHZ"],
        # ── GitHub Actions ─────────────────────────────────────────
        "GHA-001":  ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "GHA-002":  ["ESF-D-INJECTION", "ESF-D-BUILD-ENV"],
        "GHA-003":  ["ESF-D-INJECTION"],
        "GHA-004":  ["ESF-C-LEAST-PRIV"],
        "GHA-005":  ["ESF-D-TOKEN-HYGIENE"],
        "GHA-006":  ["ESF-D-SIGN-ARTIFACTS"],
        "GHA-007":  ["ESF-D-SBOM"],
        "GHA-008":  ["ESF-D-SECRETS"],
        "GHA-009":  ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "GHA-010":  ["ESF-D-INJECTION", "ESF-S-PIN-DEPS"],
        "GHA-011":  ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "GHA-012":  ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "GHA-013":  ["ESF-D-INJECTION"],
        "GHA-014":  ["ESF-C-APPROVAL", "ESF-C-ENV-SEP"],
        "GHA-015":  ["ESF-D-BUILD-TIMEOUT"],
        "GHA-016":  ["ESF-S-VERIFY-DEPS"],
        "GHA-017":  ["ESF-D-BUILD-ENV"],
        "GHA-018":  ["ESF-S-VERIFY-DEPS"],
        "GHA-019":  ["ESF-D-SECRETS"],
        "GHA-020":  ["ESF-S-VULN-MGMT"],
        "GHA-021":  ["ESF-S-PIN-DEPS"],
        "GHA-022":  ["ESF-S-PIN-DEPS"],
        "GHA-023":  ["ESF-S-VERIFY-DEPS"],
        "GHA-024":  ["ESF-D-SBOM", "ESF-D-SIGN-ARTIFACTS"],
        "GHA-025":  ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "GHA-026":  ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "GHA-027":  ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "GHA-028":  ["ESF-D-INJECTION"],
        "GHA-029":  ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        # ── GitLab CI ──────────────────────────────────────────────
        "GL-001":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "GL-002":   ["ESF-D-INJECTION"],
        "GL-003":   ["ESF-D-SECRETS"],
        "GL-004":   ["ESF-C-APPROVAL", "ESF-C-ENV-SEP"],
        "GL-005":   ["ESF-S-PIN-DEPS", "ESF-S-TRUSTED-REG"],
        "GL-006":   ["ESF-D-SIGN-ARTIFACTS"],
        "GL-007":   ["ESF-D-SBOM"],
        "GL-008":   ["ESF-D-SECRETS"],
        "GL-009":   ["ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"],
        "GL-010":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "GL-011":   ["ESF-D-INJECTION", "ESF-S-PIN-DEPS"],
        "GL-012":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "GL-013":   ["ESF-D-TOKEN-HYGIENE"],
        "GL-014":   ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "GL-015":   ["ESF-D-BUILD-TIMEOUT"],
        "GL-016":   ["ESF-S-VERIFY-DEPS"],
        "GL-017":   ["ESF-D-BUILD-ENV"],
        "GL-018":   ["ESF-S-VERIFY-DEPS"],
        "GL-019":   ["ESF-S-VULN-MGMT"],
        "GL-020":   ["ESF-D-SECRETS"],
        "GL-021":   ["ESF-S-PIN-DEPS"],
        "GL-022":   ["ESF-S-PIN-DEPS"],
        "GL-023":   ["ESF-S-VERIFY-DEPS"],
        "GL-024":   ["ESF-D-SBOM", "ESF-D-SIGN-ARTIFACTS"],
        "GL-025":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "GL-026":   ["ESF-D-INJECTION"],
        "GL-027":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        # ── Bitbucket Pipelines ────────────────────────────────────
        "BB-001":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "BB-002":   ["ESF-D-INJECTION"],
        "BB-003":   ["ESF-D-SECRETS"],
        "BB-004":   ["ESF-C-APPROVAL", "ESF-C-ENV-SEP"],
        "BB-005":   ["ESF-D-BUILD-TIMEOUT"],
        "BB-006":   ["ESF-D-SIGN-ARTIFACTS"],
        "BB-007":   ["ESF-D-SBOM"],
        "BB-008":   ["ESF-D-SECRETS"],
        "BB-009":   ["ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"],
        "BB-010":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "BB-011":   ["ESF-D-TOKEN-HYGIENE"],
        "BB-012":   ["ESF-S-VERIFY-DEPS"],
        "BB-013":   ["ESF-D-BUILD-ENV"],
        "BB-014":   ["ESF-S-VERIFY-DEPS"],
        "BB-015":   ["ESF-S-VULN-MGMT"],
        "BB-016":   ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "BB-017":   ["ESF-D-SECRETS"],
        "BB-018":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "BB-019":   ["ESF-D-SECRETS"],
        "BB-020":   ["ESF-D-BUILD-ENV"],
        "BB-021":   ["ESF-S-PIN-DEPS"],
        "BB-022":   ["ESF-S-PIN-DEPS"],
        "BB-023":   ["ESF-S-VERIFY-DEPS"],
        "BB-024":   ["ESF-D-SBOM", "ESF-D-SIGN-ARTIFACTS"],
        "BB-025":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "BB-026":   ["ESF-D-INJECTION"],
        "BB-027":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        # ── Azure DevOps Pipelines ─────────────────────────────────
        "ADO-001":  ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "ADO-002":  ["ESF-D-INJECTION"],
        "ADO-003":  ["ESF-D-SECRETS"],
        "ADO-004":  ["ESF-C-APPROVAL", "ESF-C-ENV-SEP"],
        "ADO-005":  ["ESF-S-PIN-DEPS", "ESF-S-TRUSTED-REG"],
        "ADO-006":  ["ESF-D-SIGN-ARTIFACTS"],
        "ADO-007":  ["ESF-D-SBOM"],
        "ADO-008":  ["ESF-D-SECRETS"],
        "ADO-009":  ["ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"],
        "ADO-010":  ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "ADO-011":  ["ESF-D-INJECTION", "ESF-S-PIN-DEPS"],
        "ADO-012":  ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "ADO-013":  ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "ADO-014":  ["ESF-D-TOKEN-HYGIENE"],
        "ADO-015":  ["ESF-D-BUILD-TIMEOUT"],
        "ADO-016":  ["ESF-S-VERIFY-DEPS"],
        "ADO-017":  ["ESF-D-BUILD-ENV"],
        "ADO-018":  ["ESF-S-VERIFY-DEPS"],
        "ADO-019":  ["ESF-D-INJECTION", "ESF-S-PIN-DEPS"],
        "ADO-020":  ["ESF-S-VULN-MGMT"],
        "ADO-021":  ["ESF-S-PIN-DEPS"],
        "ADO-022":  ["ESF-S-PIN-DEPS"],
        "ADO-023":  ["ESF-S-VERIFY-DEPS"],
        "ADO-024":  ["ESF-D-SBOM", "ESF-D-SIGN-ARTIFACTS"],
        "ADO-025":  ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "ADO-026":  ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "ADO-027":  ["ESF-D-INJECTION"],
        "ADO-028":  ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        # ── Jenkins ────────────────────────────────────────────────
        "JF-001":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "JF-002":   ["ESF-D-INJECTION"],
        "JF-003":   ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "JF-004":   ["ESF-D-TOKEN-HYGIENE"],
        "JF-005":   ["ESF-C-APPROVAL"],
        "JF-006":   ["ESF-D-SIGN-ARTIFACTS"],
        "JF-007":   ["ESF-D-SBOM"],
        "JF-008":   ["ESF-D-SECRETS"],
        "JF-009":   ["ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"],
        "JF-010":   ["ESF-D-SECRETS", "ESF-D-TOKEN-HYGIENE"],
        "JF-011":   ["ESF-D-BUILD-LOGS", "ESF-C-AUDIT"],
        "JF-012":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "JF-013":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "JF-014":   ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "JF-015":   ["ESF-D-BUILD-TIMEOUT"],
        "JF-016":   ["ESF-S-VERIFY-DEPS"],
        "JF-017":   ["ESF-D-BUILD-ENV"],
        "JF-018":   ["ESF-S-VERIFY-DEPS"],
        "JF-019":   ["ESF-D-INJECTION"],
        "JF-020":   ["ESF-S-VULN-MGMT"],
        "JF-021":   ["ESF-S-PIN-DEPS"],
        "JF-022":   ["ESF-S-PIN-DEPS"],
        "JF-023":   ["ESF-S-VERIFY-DEPS"],
        "JF-024":   ["ESF-C-APPROVAL"],
        "JF-025":   ["ESF-D-BUILD-ENV"],
        "JF-026":   ["ESF-C-APPROVAL"],
        "JF-027":   ["ESF-D-TAMPER"],
        "JF-028":   ["ESF-D-SBOM", "ESF-D-SIGN-ARTIFACTS"],
        "JF-029":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "JF-030":   ["ESF-D-INJECTION"],
        "JF-031":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        # ── CircleCI ───────────────────────────────────────────────
        "CC-001":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "CC-002":   ["ESF-D-INJECTION"],
        "CC-003":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "CC-004":   ["ESF-D-SECRETS"],
        "CC-005":   ["ESF-D-TOKEN-HYGIENE"],
        "CC-006":   ["ESF-D-SIGN-ARTIFACTS"],
        "CC-007":   ["ESF-D-SBOM"],
        "CC-008":   ["ESF-D-SECRETS"],
        "CC-009":   ["ESF-C-APPROVAL", "ESF-C-ENV-SEP"],
        "CC-010":   ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "CC-011":   ["ESF-D-BUILD-LOGS", "ESF-C-AUDIT"],
        "CC-012":   ["ESF-D-INJECTION"],
        "CC-013":   ["ESF-C-APPROVAL"],
        "CC-014":   ["ESF-D-BUILD-ENV"],
        "CC-015":   ["ESF-D-BUILD-TIMEOUT"],
        "CC-016":   ["ESF-S-VERIFY-DEPS"],
        "CC-017":   ["ESF-D-BUILD-ENV"],
        "CC-018":   ["ESF-S-VERIFY-DEPS"],
        "CC-019":   ["ESF-D-SECRETS"],
        "CC-020":   ["ESF-S-VULN-MGMT"],
        "CC-021":   ["ESF-S-PIN-DEPS"],
        "CC-022":   ["ESF-S-PIN-DEPS"],
        "CC-023":   ["ESF-S-VERIFY-DEPS"],
        "CC-024":   ["ESF-D-SBOM", "ESF-D-SIGN-ARTIFACTS"],
        "CC-025":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "CC-026":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "CC-027":   ["ESF-D-INJECTION"],
        "CC-028":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        # ── Buildkite ─────────────────────────────────────────────
        "BK-001":   ["ESF-S-PIN-DEPS"],                            # plugin not pinned
        "BK-002":   ["ESF-D-SECRETS"],                             # secret in env
        "BK-003":   ["ESF-D-INJECTION"],                           # untrusted variable injection
        "BK-004":   ["ESF-S-VERIFY-DEPS"],                         # curl | bash
        "BK-005":   ["ESF-D-PRIV-BUILD"],                          # Docker privileged
        "BK-006":   ["ESF-D-BUILD-TIMEOUT"],                       # no timeout
        "BK-007":   ["ESF-C-APPROVAL"],                            # deploy not gated
        "BK-008":   ["ESF-S-TRUSTED-REG"],                         # TLS bypass
        "BK-009":   ["ESF-D-SIGN-ARTIFACTS"],                      # artifact signing
        "BK-010":   ["ESF-D-SBOM"],                                # SBOM
        "BK-011":   ["ESF-S-PROVENANCE", "ESF-D-SIGN-ARTIFACTS"],  # SLSA provenance
        "BK-012":   ["ESF-S-VULN-MGMT"],                           # vuln scanning
        "BK-013":   ["ESF-C-ENV-SEP"],                             # deploy without branch filter
        # ── Tekton ────────────────────────────────────────────────
        "TKN-001":  ["ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"],         # step image not digest-pinned
        "TKN-002":  ["ESF-D-PRIV-BUILD"],                          # step privileged
        "TKN-003":  ["ESF-D-INJECTION"],                           # param injection
        "TKN-004":  ["ESF-D-PRIV-BUILD", "ESF-D-BUILD-ENV"],       # hostPath / namespaces
        "TKN-005":  ["ESF-D-SECRETS"],                             # leaked creds
        "TKN-006":  ["ESF-D-BUILD-TIMEOUT"],                       # no timeout
        "TKN-007":  ["ESF-C-LEAST-PRIV"],                          # default SA
        "TKN-008":  ["ESF-S-VERIFY-DEPS", "ESF-S-TRUSTED-REG"],    # remote install / TLS
        "TKN-009":  ["ESF-D-SIGN-ARTIFACTS"],                      # artifact signing
        "TKN-010":  ["ESF-D-SBOM"],                                # SBOM
        "TKN-011":  ["ESF-S-PROVENANCE", "ESF-D-SIGN-ARTIFACTS"],  # SLSA provenance
        "TKN-012":  ["ESF-S-VULN-MGMT"],                           # vuln scanning
        "TKN-013":  ["ESF-D-PRIV-BUILD"],                          # sidecar privileged
        # ── Argo Workflows ────────────────────────────────────────
        "ARGO-001": ["ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"],         # template image not pinned
        "ARGO-002": ["ESF-D-PRIV-BUILD"],                          # template privileged
        "ARGO-003": ["ESF-C-LEAST-PRIV"],                          # default SA
        "ARGO-004": ["ESF-D-PRIV-BUILD", "ESF-D-BUILD-ENV"],       # hostPath / namespaces
        "ARGO-005": ["ESF-D-INJECTION"],                           # parameter injection
        "ARGO-006": ["ESF-D-SECRETS"],                             # leaked creds
        "ARGO-007": ["ESF-D-BUILD-TIMEOUT"],                       # no activeDeadlineSeconds
        "ARGO-008": ["ESF-S-VERIFY-DEPS", "ESF-S-TRUSTED-REG"],    # remote install / TLS
        "ARGO-009": ["ESF-D-SIGN-ARTIFACTS"],                      # artifact signing
        "ARGO-010": ["ESF-D-SBOM"],                                # SBOM
        "ARGO-011": ["ESF-S-PROVENANCE", "ESF-D-SIGN-ARTIFACTS"],  # SLSA provenance
        "ARGO-012": ["ESF-S-VULN-MGMT"],                           # vuln scanning
        "ARGO-013": ["ESF-C-LEAST-PRIV"],                          # SA token automount
        # ── Helm chart-supply-chain ───────────────────────────────
        # Helm chart deps are exactly the Supplier-side controls'
        # use case: third-party charts pulled from registries.
        "HELM-001": ["ESF-S-PIN-DEPS"],                            # legacy v1 (no in-tree lock)
        "HELM-002": ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],       # missing Chart.lock digests
        "HELM-003": ["ESF-S-TRUSTED-REG"],                         # non-HTTPS dep repo
        "HELM-004": ["ESF-S-PIN-DEPS"],                            # version range
        "HELM-005": ["ESF-S-VERIFY-DEPS"],                         # maintainers chain-of-custody
        "HELM-006": ["ESF-D-CODE-REVIEW"],                         # missing kubeVersion
        "HELM-007": ["ESF-S-VERIFY-DEPS"],                         # description metadata
        "HELM-008": ["ESF-S-PIN-DEPS"],                            # stale Chart.lock
        "HELM-009": ["ESF-S-TRUSTED-REG"],                         # non-HTTPS home/sources
        "HELM-010": ["ESF-S-VERIFY-DEPS"],                         # appVersion
        # ── Dockerfile (image build supply chain) ──────────────────
        "DF-001": ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],         # FROM not digest-pinned
        "DF-002": ["ESF-D-PRIV-BUILD"],                            # runs as root
        "DF-003": ["ESF-S-VERIFY-DEPS"],                           # ADD remote no integrity
        "DF-004": ["ESF-S-VERIFY-DEPS", "ESF-S-TRUSTED-REG"],      # curl-pipe
        "DF-005": ["ESF-D-INJECTION"],                             # shell-eval
        "DF-006": ["ESF-D-SECRETS"],                               # ENV credential
        "DF-007": ["ESF-C-DEPLOY-MON"],                            # no HEALTHCHECK = no container-level health probe
        "DF-008": ["ESF-D-PRIV-BUILD"],                            # docker --privileged
        "DF-010": ["ESF-S-PIN-DEPS"],                              # apt upgrade
        "DF-012": ["ESF-D-PRIV-BUILD"],                            # RUN sudo
        "DF-013": ["ESF-D-PRIV-BUILD"],                            # sensitive port
        "DF-014": ["ESF-D-PRIV-BUILD"],                            # WORKDIR /etc
        "DF-015": ["ESF-D-PRIV-BUILD"],                            # chmod 777
        "DF-016": ["ESF-D-SBOM"],                                  # OCI provenance labels
        "DF-019": ["ESF-D-SECRETS"],                               # COPY credential file
        "DF-020": ["ESF-D-SECRETS"],                               # credential ARG
        # ── Cloud Build ────────────────────────────────────────────
        "GCB-001": ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "GCB-002": ["ESF-D-SECRETS"],
        "GCB-003": ["ESF-D-SECRETS"],
        "GCB-004": ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "GCB-005": ["ESF-D-SECRETS"],
        "GCB-006": ["ESF-D-BUILD-LOGS"],
        "GCB-007": ["ESF-S-PIN-DEPS"],
        "GCB-008": ["ESF-D-SIGN-ARTIFACTS"],
        "GCB-009": ["ESF-D-SBOM"],
        "GCB-010": ["ESF-D-BUILD-ENV"],
        "GCB-011": ["ESF-S-VERIFY-DEPS"],
        "GCB-012": ["ESF-S-VULN-MGMT"],
        "GCB-013": ["ESF-D-TOKEN-HYGIENE"],
        "GCB-014": ["ESF-D-INJECTION"],
        "GCB-015": ["ESF-D-SBOM"],
        "GCB-016": ["ESF-D-BUILD-TIMEOUT"],
        "GCB-017": ["ESF-D-BUILD-LOGS"],
        "GCB-018": ["ESF-S-TRUSTED-REG"],
        "GCB-019": ["ESF-D-PRIV-BUILD"],
        "GCB-020": ["ESF-D-TOKEN-HYGIENE"],
        "GCB-021": ["ESF-D-BUILD-ENV"],
        "GCB-022": ["ESF-D-INJECTION"],
        "GCB-023": ["ESF-D-SIGN-ARTIFACTS"],
        "GCB-024": ["ESF-D-SBOM"],
        "GCB-025": ["ESF-S-PIN-DEPS"],
        "GCB-026": ["ESF-C-ARTIFACT-AUTHZ"],
        # ── SCM posture (governance via the platform REST API) ──────
        # The SCM provider evidences the platform-side controls that
        # gate code into the build pipeline. Map to the Developer
        # guide's "peer review of source and pipeline configuration"
        # (ESF-D-CODE-REVIEW) for branch-protection / review-control
        # rules, the Supplier guide for actions-as-dependencies, and
        # the Customer guide for environment / deployment governance.
        "SCM-001":  ["ESF-D-CODE-REVIEW"],          # default branch unprotected
        "SCM-002":  ["ESF-D-CODE-REVIEW"],          # required reviews missing
        "SCM-004":  ["ESF-D-SECRETS"],              # secret scanning disabled
        "SCM-005":  ["ESF-S-VULN-MGMT"],            # Dependabot security updates off
        "SCM-007":  ["ESF-D-CODE-REVIEW"],          # force-push allowed (history bypass)
        "SCM-008":  ["ESF-D-CODE-REVIEW"],          # required status checks missing
        "SCM-009":  ["ESF-D-CODE-REVIEW"],          # branch deletions allowed
        "SCM-010":  ["ESF-D-CODE-REVIEW"],          # admin bypass allowed
        "SCM-011":  ["ESF-D-CODE-REVIEW"],          # CODEOWNERS reviews not required
        "SCM-012":  ["ESF-D-CODE-REVIEW"],          # stale reviews not dismissed
        "SCM-013":  ["ESF-D-CODE-REVIEW"],          # conversation resolution not required
        "SCM-014":  ["ESF-D-CODE-REVIEW"],          # last-push approval not required
        "SCM-015":  ["ESF-D-SECRETS"],              # secret scanning push protection off
        "SCM-017":  ["ESF-D-CODE-REVIEW"],          # CODEOWNERS file missing
        "SCM-018":  ["ESF-D-CODE-REVIEW"],          # PR review bypass allowed
        "SCM-019":  ["ESF-D-CODE-REVIEW"],          # push-restriction allowlist names users
        # Actions governance + environments + deploy keys
        "SCM-020":  ["ESF-C-LEAST-PRIV", "ESF-D-TOKEN-HYGIENE"],   # workflow_token default write
        "SCM-021":  ["ESF-D-CODE-REVIEW"],          # Actions can approve PRs (self-approval)
        "SCM-022":  ["ESF-S-VERIFY-DEPS", "ESF-S-TRUSTED-REG"],    # allowed_actions unrestricted
        "SCM-023":  ["ESF-C-APPROVAL"],             # env missing reviewers
        "SCM-024":  ["ESF-C-ENV-SEP"],              # env branch policy missing
        "SCM-025":  ["ESF-D-TOKEN-HYGIENE"],        # deploy keys write-enabled
        "SCM-027":  ["ESF-C-LEAST-PRIV"],           # outside collaborator elevated
        # Ruleset enforcement (modern variant of branch protection)
        "SCM-029":  ["ESF-D-CODE-REVIEW"],          # ruleset not enforced
        "SCM-030":  ["ESF-D-CODE-REVIEW"],          # ruleset always-bypass
        "SCM-031":  ["ESF-D-CODE-REVIEW"],          # auto-merge enabled
        "SCM-032":  ["ESF-D-CODE-REVIEW"],          # ruleset lacks PR review
        "SCM-033":  ["ESF-D-CODE-REVIEW"],          # ruleset lacks status_checks
        "SCM-034":  ["ESF-D-CODE-REVIEW"],          # ruleset allows force_push
        "SCM-035":  ["ESF-D-CODE-REVIEW"],          # ruleset allows deletion
        "SCM-037":  ["ESF-D-CODE-REVIEW"],          # ruleset stale-review dismissal
        "SCM-038":  ["ESF-D-CODE-REVIEW"],          # ruleset lacks linear_history
        "SCM-039":  ["ESF-D-CODE-REVIEW"],          # ruleset lacks required_workflows
        "SCM-041":  ["ESF-C-APPROVAL", "ESF-C-ENV-SEP"],  # ruleset lacks deployment-env gate
        "SCM-042":  ["ESF-D-CODE-REVIEW"],          # ruleset lacks merge queue
        # ── SCM extras (signed commits + vuln intake + code scanning) ─
        # On reflection, these source-side controls do have ESF
        # analogs: SCM-003/040/044/045/046/047 evidence the upstream
        # signal that ESF-S-VULN-MGMT and ESF-D-CODE-REVIEW depend
        # on; SCM-006/036/043 commit-signing supports ESF-D-TAMPER
        # (artifact integrity from source forward); SCM-016 vuln
        # intake feeds ESF-S-VULN-MGMT; SCM-026 webhook insecurity
        # is a code-review/integrity bypass and maps to ESF-D-CODE-
        # REVIEW; SCM-028 forking widens the contribution surface
        # and maps to ESF-D-CODE-REVIEW.
        "SCM-003":  ["ESF-S-VULN-MGMT"],            # default code scanning disabled
        "SCM-006":  ["ESF-D-TAMPER"],               # signed commits not required
        "SCM-016":  ["ESF-S-VULN-MGMT"],            # private vuln reporting off
        "SCM-026":  ["ESF-D-CODE-REVIEW"],          # webhook insecure / no HMAC
        "SCM-028":  ["ESF-D-CODE-REVIEW"],          # private repo allows forking
        "SCM-036":  ["ESF-D-TAMPER"],               # ruleset lacks signed_commits
        "SCM-040":  ["ESF-S-VULN-MGMT"],            # ruleset lacks code_scanning gate
        "SCM-043":  ["ESF-D-TAMPER"],               # tag-ruleset lacks signed_commits
        "SCM-044":  ["ESF-D-TAMPER"],               # required_signatures bypassed for admins
        "SCM-045":  ["ESF-S-VULN-MGMT"],            # default code scanning limited query suite
        "SCM-046":  ["ESF-S-VULN-MGMT"],            # default code scanning paused
        "SCM-047":  ["ESF-S-VULN-MGMT"],            # repo language not covered
        # ── AWS extras ───────────────────────────────────────────
        "CB-008":   ["ESF-D-CODE-REVIEW"],          # inline buildspec, not from protected repo
        "CB-009":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # build image not digest-pinned
        "CB-010":   ["ESF-D-CODE-REVIEW"],          # fork-PR webhook unfiltered
        "CP-005":   ["ESF-C-APPROVAL"],             # prod Deploy stage no manual approval
        "CP-007":   ["ESF-D-CODE-REVIEW"],          # v2 PR trigger accepts all branches
        "CCM-001":  ["ESF-D-CODE-REVIEW"],          # CodeCommit no approval rule
        "CCM-002":  ["ESF-C-ARTIFACT-AUTHZ"],       # CodeCommit repo not CMK
        "CCM-003":  ["ESF-C-ARTIFACT-AUTHZ"],       # CodeCommit cross-account trigger
        "CA-001":   ["ESF-C-ARTIFACT-AUTHZ"],       # CodeArtifact domain not CMK
        "CA-002":   ["ESF-S-TRUSTED-REG"],          # CodeArtifact public upstream
        "CA-003":   ["ESF-C-ARTIFACT-AUTHZ"],       # CodeArtifact cross-account wildcard
        "CA-004":   ["ESF-C-ARTIFACT-AUTHZ"],       # CodeArtifact wildcard codeartifact:*
        "ECR-006":  ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],   # pull-through untrusted upstream
        "ECR-007":  ["ESF-S-VULN-MGMT"],            # Inspector v2 enhanced scanning
        "IAM-007":  ["ESF-D-TOKEN-HYGIENE"],        # access key > 90 days
        "IAM-008":  ["ESF-D-TOKEN-HYGIENE", "ESF-C-LEAST-PRIV"],   # OIDC trust missing aud/sub pin
        "PBAC-003": ["ESF-D-BUILD-ENV"],            # SG 0.0.0.0/0 egress
        "PBAC-005": ["ESF-C-LEAST-PRIV"],           # stage roles mirror pipeline
        "KMS-001":  ["ESF-C-ARTIFACT-AUTHZ"],       # CMK rotation disabled
        "KMS-002":  ["ESF-C-LEAST-PRIV"],           # KMS policy wildcard
        "SM-001":   ["ESF-D-TOKEN-HYGIENE"],        # Secrets Manager no rotation
        "SM-002":   ["ESF-C-LEAST-PRIV"],           # Secrets Manager wildcard principal
        "SSM-001":  ["ESF-D-SECRETS"],              # SSM secret-like name not SecureString
        "SSM-002":  ["ESF-C-ARTIFACT-AUTHZ"],       # SSM SecureString default key
        "LMB-001":  ["ESF-D-SIGN-ARTIFACTS"],       # Lambda code-signing config
        "LMB-002":  ["ESF-C-ARTIFACT-AUTHZ"],       # Lambda function URL AuthType=NONE
        "LMB-003":  ["ESF-D-SECRETS"],              # Lambda plaintext env secrets
        "LMB-004":  ["ESF-C-ARTIFACT-AUTHZ"],       # Lambda resource policy wildcard principal
        "SIGN-001": ["ESF-D-SIGN-ARTIFACTS"],       # no AWS Signer profile
        "SIGN-002": ["ESF-D-SIGN-ARTIFACTS"],       # Signer profile revoked / inactive
        "CT-001":   ["ESF-C-AUDIT"],                # no active CloudTrail
        "CT-002":   ["ESF-C-AUDIT"],                # log-file validation disabled
        "CT-003":   ["ESF-C-AUDIT"],                # trail not multi-region
        "CWL-001":  ["ESF-C-AUDIT"],                # CW Logs no retention
        "CWL-002":  ["ESF-C-AUDIT"],                # CW Logs not KMS-encrypted
        "EB-002":   ["ESF-C-LEAST-PRIV"],           # EventBridge wildcard target
        # ── Terraform / CloudFormation (IaC-native) ──────────────
        "TF-001":   ["ESF-D-TOKEN-HYGIENE"],        # aws_iam_access_key as code (long-lived)
        "TF-002":   ["ESF-D-SECRETS"],              # hard-coded secret in resource attr
        "TF-003":   ["ESF-D-BUILD-ENV"],            # CodeBuild VPC shares public subnet
        "CF-001":   ["ESF-D-TOKEN-HYGIENE"],        # AWS::IAM::AccessKey as code
        "CF-002":   ["ESF-D-SECRETS"],              # hard-coded secret in resource property
        "CF-003":   ["ESF-D-BUILD-ENV"],            # CodeBuild VPC shares public subnet
        # ── GitHub Actions worm-mitigation + advanced-PPE pack ───
        "GHA-030":  ["ESF-D-TOKEN-HYGIENE", "ESF-C-APPROVAL"],   # OIDC w/o env-protected job
        "GHA-031":  ["ESF-D-INJECTION"],            # retired set-output / save-state
        "GHA-032":  ["ESF-D-INJECTION"],            # local script on untrusted trigger
        "GHA-033":  ["ESF-D-SECRETS"],              # secret echoed in run:
        "GHA-034":  ["ESF-D-SECRETS", "ESF-C-LEAST-PRIV"],   # secrets: inherit
        "GHA-035":  ["ESF-D-INJECTION"],            # github-script untrusted context
        "GHA-036":  ["ESF-D-INJECTION"],            # runs-on untrusted context
        "GHA-037":  ["ESF-D-TOKEN-HYGIENE"],        # checkout persists GITHUB_TOKEN
        "GHA-038":  ["ESF-D-INJECTION"],            # ACTIONS_ALLOW_UNSECURE_COMMANDS
        "GHA-039":  ["ESF-D-SECRETS"],              # services / container creds literal
        "GHA-040":  ["ESF-S-VERIFY-DEPS", "ESF-S-VULN-MGMT"],   # known-compromised action ref
        "GHA-041":  ["ESF-S-VERIFY-DEPS"],          # single-maintainer action (reputation)
        "GHA-042":  ["ESF-S-VERIFY-DEPS"],          # very-young action repo
        "GHA-043":  ["ESF-S-VERIFY-DEPS", "ESF-C-LEAST-PRIV"],   # low-star + sensitive perms
        "GHA-044":  ["ESF-D-INJECTION"],            # build-tool PPE on untrusted trigger
        "GHA-045":  ["ESF-D-INJECTION"],            # caller-ref input drives checkout
        "GHA-046":  ["ESF-D-INJECTION"],            # manual PR-head fetch
        "GHA-047":  ["ESF-S-VERIFY-DEPS"],          # fresh-ref cooldown
        "GHA-048":  ["ESF-D-TAMPER"],               # workflow self-mutation
        "GHA-049":  ["ESF-C-LEAST-PRIV"],           # cross-repo push from CI
        "GHA-050":  ["ESF-D-TOKEN-HYGIENE"],        # long-lived registry publish token
        "GHA-051":  ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # services / container image unpinned
        "GHA-052":  ["ESF-D-INJECTION"],            # cache key untrusted-input poisoning
        "GHA-053":  ["ESF-D-INJECTION"],            # if: predicate untrusted-context
        "GHA-054":  ["ESF-D-TOKEN-HYGIENE"],        # checkout ssh-key persists
        "GHA-055":  ["ESF-D-SECRETS"],              # reusable outputs leak secret
        "GHA-056":  ["ESF-S-VERIFY-DEPS"],          # worm IOC strings
        "GHA-057":  ["ESF-D-SECRETS"],              # secret-scanner output → egress
        "GHA-058":  ["ESF-D-INJECTION"],            # agentic CLI permission-bypass
        "GHA-059":  ["ESF-S-VERIFY-DEPS"],          # npm install without audit signatures
        "GHA-060":  ["ESF-S-VERIFY-DEPS"],          # pip install without --require-hashes
        "GHA-061":  ["ESF-C-LEAST-PRIV", "ESF-D-TOKEN-HYGIENE"],  # App token without permissions filter
        "GHA-062":  ["ESF-C-LEAST-PRIV"],            # OIDC trust subject in sibling IaC is overly broad
        # ── GitLab CI extras ─────────────────────────────────────
        "GL-028":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # services: image not pinned
        "GL-029":   ["ESF-C-APPROVAL"],             # manual deploy allow_failure
        "GL-030":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # trigger: include w/o pinned ref
        "GL-031":   ["ESF-D-TOKEN-HYGIENE", "ESF-C-APPROVAL"],  # id_tokens missing audience pin
        "GL-032":   ["ESF-D-INJECTION"],            # tags interpolates untrusted
        "GL-033":   ["ESF-D-INJECTION"],            # global before_script taint
        "GL-034":   ["ESF-S-VERIFY-DEPS"],          # npm install without audit signatures
        "GL-035":   ["ESF-S-VERIFY-DEPS"],          # pip install without --require-hashes
        # ── Bitbucket Pipelines extras ───────────────────────────
        "BB-028":   ["ESF-D-TOKEN-HYGIENE", "ESF-C-APPROVAL"],  # OIDC step w/o env gate
        "BB-029":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # step + service image not pinned
        "BB-030":   ["ESF-S-VERIFY-DEPS"],          # npm install without audit signatures
        "BB-031":   ["ESF-S-VERIFY-DEPS"],          # pip install without --require-hashes
        # ── Azure DevOps Pipelines extras ────────────────────────
        "ADO-029":  ["ESF-C-APPROVAL"],             # service-conn job w/o env gate
        "ADO-030":  ["ESF-D-INJECTION"],            # pool interpolates untrusted
        # ── CircleCI extras ──────────────────────────────────────
        "CC-029":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # machine executor image not pinned
        "CC-030":   ["ESF-C-APPROVAL"],             # job w/o branch filter / approval gate
        "CC-031":   ["ESF-D-TOKEN-HYGIENE", "ESF-C-APPROVAL"],  # OIDC role w/o branch filter
        # ── Jenkins extras ───────────────────────────────────────
        "JF-032":   ["ESF-D-INJECTION"],            # agent label interpolates untrusted
        "JF-033":   ["ESF-D-SECRETS"],              # withCredentials leaked via Groovy ${}
        "JF-034":   ["ESF-D-SECRETS"],              # password() build parameter
        "JF-035":   ["ESF-S-TRUSTED-REG"],          # httpRequest SSL off
        # ── Buildkite + Tekton + Argo extras ─────────────────────
        "BK-014":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # unpinned package install
        "BK-015":   ["ESF-D-INJECTION"],            # agents map untrusted interpolation
        "TKN-014":  ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # unpinned package install
        "TKN-015":  ["ESF-D-INJECTION"],            # workspace subPath param injection
        "ARGO-014": ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # unpinned package install
        "ARGO-015": ["ESF-S-TRUSTED-REG"],          # insecure (non-HTTPS) artifact URL
        # ── Argo CD ──────────────────────────────────────────────
        "ARGOCD-001": ["ESF-C-LEAST-PRIV"],                          # AppProject sourceRepos wildcard
        "ARGOCD-002": ["ESF-C-LEAST-PRIV", "ESF-C-ENV-SEP"],         # AppProject destinations wildcard
        "ARGOCD-003": ["ESF-C-APPROVAL"],                            # auto-prune without selfHeal
        "ARGOCD-004": ["ESF-C-LEAST-PRIV"],                          # RBAC wildcard policy
        "ARGOCD-005": ["ESF-D-SECRETS"],                             # repo plaintext credentials
        "ARGOCD-006": ["ESF-D-CODE-REVIEW", "ESF-C-LEAST-PRIV"],     # ApplicationSet PR/SCM no allowlist
        "ARGOCD-007": ["ESF-D-INJECTION"],                           # Helm generator interpolation
        "ARGOCD-008": ["ESF-S-VERIFY-DEPS"],                         # CMP plugin invocation
        "ARGOCD-009": ["ESF-C-LEAST-PRIV"],                          # anonymous access enabled
        # ── Drone CI ─────────────────────────────────────────────
        "DR-001":   ["ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"],     # step image not digest-pinned
        "DR-002":   ["ESF-D-PRIV-BUILD"],           # privileged step
        "DR-003":   ["ESF-D-INJECTION"],            # Drone variable injection
        "DR-004":   ["ESF-D-SECRETS"],              # literal credential
        "DR-005":   ["ESF-S-PIN-DEPS"],             # plugin floating tag
        "DR-006":   ["ESF-S-TRUSTED-REG"],          # TLS bypass in commands
        "DR-007":   ["ESF-D-PRIV-BUILD", "ESF-D-BUILD-ENV"],   # sensitive host-path mount
        "DR-008":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # pull: never
        "DR-009":   ["ESF-D-INJECTION"],            # cache key tainted
        "DR-010":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # unpinned package install
        "DR-011":   ["ESF-D-INJECTION"],            # node map interpolates untrusted
        # ── NPM / PyPI / Maven dep supply-chain ──────────────────
        # Per-package pinning / integrity / non-registry source →
        # ESF-S-PIN-DEPS (+ ESF-S-VERIFY-DEPS). Compromised pkgs add
        # ESF-S-VULN-MGMT. HTTP / wildcard / extra-index → ESF-S-
        # TRUSTED-REG. Install-time lifecycle scripts → ESF-D-BUILD-
        # ENV. Secret-shaped paths → ESF-D-SECRETS.
        "NPM-001":  ["ESF-S-PIN-DEPS"],
        "NPM-002":  ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "NPM-003":  ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],
        "NPM-004":  ["ESF-D-BUILD-ENV"],
        "NPM-005":  ["ESF-S-PIN-DEPS"],
        "NPM-006":  ["ESF-S-VERIFY-DEPS", "ESF-S-VULN-MGMT"],
        "NPM-007":  ["ESF-D-BUILD-ENV"],
        "NPM-011":  ["ESF-D-SECRETS"],
        "PYPI-001": ["ESF-S-PIN-DEPS"],
        "PYPI-002": ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "PYPI-003": ["ESF-S-TRUSTED-REG"],
        "PYPI-004": ["ESF-S-PIN-DEPS"],
        "PYPI-005": ["ESF-S-TRUSTED-REG"],
        "PYPI-006": ["ESF-S-VERIFY-DEPS", "ESF-S-VULN-MGMT"],
        "MVN-001":  ["ESF-S-PIN-DEPS"],
        "MVN-002":  ["ESF-S-PIN-DEPS"],
        "MVN-003":  ["ESF-S-TRUSTED-REG"],
        "MVN-004":  ["ESF-S-PIN-DEPS"],
        "MVN-005":  ["ESF-S-VERIFY-DEPS"],
        "MVN-006":  ["ESF-S-VERIFY-DEPS", "ESF-S-VULN-MGMT"],
        "MVN-007":  ["ESF-S-TRUSTED-REG"],
        # ── OCI image manifest gaps ──────────────────────────────
        # Provenance metadata + integrity → ESF-S-PROVENANCE +
        # ESF-D-SBOM. Foreign-layer URL → ESF-S-TRUSTED-REG. Schema
        # / digest → ESF-S-IMMUTABLE + ESF-S-VERIFY-DEPS.
        "OCI-001":  ["ESF-D-SBOM"],                # provenance annotations missing
        "OCI-002":  ["ESF-S-PROVENANCE", "ESF-D-SIGN-ARTIFACTS"],   # build attestation missing
        "OCI-003":  ["ESF-D-SBOM"],                # missing image.created
        "OCI-004":  ["ESF-S-TRUSTED-REG"],         # foreign-layer URL reference
        "OCI-005":  ["ESF-D-SBOM"],                # missing image.licenses
        "OCI-006":  ["ESF-D-BUILD-ENV"],           # excessive layer count
        "OCI-007":  ["ESF-S-IMMUTABLE", "ESF-S-VERIFY-DEPS"],   # legacy schemaVersion 1
        "OCI-008":  ["ESF-S-IMMUTABLE", "ESF-S-VERIFY-DEPS"],   # weak digest algorithm
        # ── SLSA / in-toto attestation content ───────────────────
        "ATTEST-001": ["ESF-S-PROVENANCE", "ESF-D-SIGN-ARTIFACTS"],   # untrusted SLSA builder identity
        "ATTEST-002": ["ESF-S-PROVENANCE"],         # source-repo claim unverifiable
        "ATTEST-003": ["ESF-D-SBOM"],               # SBOM floating versions
        "ATTEST-004": ["ESF-S-PROVENANCE"],         # provenance lacks materials
        "ATTEST-005": ["ESF-S-PROVENANCE", "ESF-S-IMMUTABLE"],   # in-toto subject digest unpinned
        "ATTEST-006": ["ESF-S-PROVENANCE"],         # buildType missing
        "ATTEST-007": ["ESF-D-SBOM"],               # SBOM missing supplier
        # ── Cross-cutting dataflow / taint engine ────────────────
        # Cross-step / cross-job untrusted-data flow into a privileged
        # sink is the canonical ESF-D-INJECTION shape.
        "TAINT-001": ["ESF-D-INJECTION"],
        "TAINT-002": ["ESF-D-INJECTION"],
        "TAINT-003": ["ESF-D-INJECTION"],
        "TAINT-004": ["ESF-D-INJECTION"],
        "TAINT-005": ["ESF-D-INJECTION"],
        "TAINT-006": ["ESF-D-INJECTION"],
        "TAINT-007": ["ESF-D-INJECTION"],
        "TAINT-008": ["ESF-D-INJECTION"],
        # ── Dockerfile extras ───────────────────────────────────
        "DF-009":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # ADD where COPY suffices
        "DF-011":   ["ESF-D-BUILD-ENV"],            # apt cache not cleaned
        "DF-017":   ["ESF-D-PRIV-BUILD"],           # ENV PATH writable prefix
        "DF-018":   ["ESF-D-PRIV-BUILD"],           # RUN chown system path
        "DF-021":   ["ESF-S-TRUSTED-REG"],          # pip TLS bypass / http index
        "DF-022":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # npm install (not npm ci)
        "DF-023":   ["ESF-D-PRIV-BUILD"],           # LD_PRELOAD / LD_LIBRARY_PATH
        "DF-024":   ["ESF-D-BUILD-ENV"],            # npm install runs lifecycle scripts
        "DF-025":   ["ESF-D-SECRETS"],              # registry token in image layer
        "DF-026":   ["ESF-S-TRUSTED-REG"],          # NODE_TLS_REJECT_UNAUTHORIZED=0
        "DF-027":   ["ESF-S-TRUSTED-REG"],          # PYTHONHTTPSVERIFY=0
        "DF-028":   ["ESF-S-TRUSTED-REG"],          # GIT_SSL_NO_VERIFY=1
        "DF-029":   ["ESF-S-TRUSTED-REG"],          # REQUESTS_CA_BUNDLE neutered
        "DF-030":   ["ESF-D-PRIV-BUILD"],           # NODE_OPTIONS --require / --inspect
        # ── Degraded-mode findings (API access failures) ─────────
        # Already partially mapped at the top of the file. Adding
        # the remaining surfaces (CT/CWL/EB/KMS/SM/SSM/CA/CCM/LMB
        # discovery failures) to ESF-C-AUDIT, mirroring the existing
        # AWS-discovery-failure precedent.
        "CT-000":   ["ESF-C-AUDIT"],
        "CWL-000":  ["ESF-C-AUDIT"],
        "EB-000":   ["ESF-C-AUDIT"],
        "KMS-000":  ["ESF-C-AUDIT"],
        "SM-000":   ["ESF-C-AUDIT"],
        "SSM-000":  ["ESF-C-AUDIT"],
        "CA-000":   ["ESF-C-AUDIT"],
        "CCM-000":  ["ESF-C-AUDIT"],
        "LMB-000":  ["ESF-C-AUDIT"],
        # ── Kubernetes manifests (deployment payload) ───────────
        # K8s workload manifests are the Customer-side deployment
        # surface. Image-pinning → ESF-S-PIN-DEPS + ESF-S-VERIFY-DEPS;
        # privileged / runtime / network → ESF-D-PRIV-BUILD +
        # ESF-D-BUILD-ENV; RBAC / SA → ESF-C-LEAST-PRIV; secret
        # exposure → ESF-D-SECRETS; deployment-env separation →
        # ESF-C-ENV-SEP.
        "K8S-001":  ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # image not digest-pinned
        "K8S-002":  ["ESF-D-BUILD-ENV"],            # hostNetwork
        "K8S-003":  ["ESF-D-BUILD-ENV"],            # hostPID
        "K8S-004":  ["ESF-D-BUILD-ENV"],            # hostIPC
        "K8S-005":  ["ESF-D-PRIV-BUILD"],           # privileged container
        "K8S-006":  ["ESF-D-PRIV-BUILD"],           # allowPrivilegeEscalation
        "K8S-007":  ["ESF-D-PRIV-BUILD"],           # runAsNonRoot missing
        "K8S-008":  ["ESF-D-PRIV-BUILD"],           # readOnlyRootFilesystem missing
        "K8S-009":  ["ESF-D-PRIV-BUILD"],           # added capabilities
        "K8S-010":  ["ESF-D-PRIV-BUILD"],           # seccompProfile missing
        "K8S-011":  ["ESF-C-LEAST-PRIV"],           # default ServiceAccount
        "K8S-012":  ["ESF-C-LEAST-PRIV"],           # automountServiceAccountToken
        "K8S-013":  ["ESF-D-PRIV-BUILD"],           # hostPath volume
        "K8S-014":  ["ESF-D-PRIV-BUILD"],           # sensitive hostPath
        "K8S-015":  ["ESF-D-BUILD-ENV"],            # no memory limit
        "K8S-016":  ["ESF-D-BUILD-ENV"],            # no CPU limit
        "K8S-017":  ["ESF-D-SECRETS"],              # credential literal in env
        "K8S-018":  ["ESF-D-SECRETS"],              # Secret data plaintext
        "K8S-019":  ["ESF-C-ENV-SEP"],              # default namespace
        "K8S-020":  ["ESF-C-LEAST-PRIV"],           # cluster-admin RoleBinding
        "K8S-021":  ["ESF-C-LEAST-PRIV"],           # wildcard RBAC verbs
        "K8S-022":  ["ESF-D-BUILD-ENV"],            # SSH service exposed
        "K8S-023":  ["ESF-D-PRIV-BUILD"],           # PSA enforce missing
        "K8S-024":  ["ESF-C-DEPLOY-MON"],           # missing health probes
        "K8S-025":  ["ESF-D-BUILD-ENV"],            # system priority class
        "K8S-026":  ["ESF-D-BUILD-ENV"],            # LB without source ranges
        "K8S-027":  ["ESF-S-TRUSTED-REG"],          # Ingress without TLS
        "K8S-028":  ["ESF-D-BUILD-ENV"],            # container hostPort
        "K8S-029":  ["ESF-C-LEAST-PRIV"],           # default-SA RoleBinding
        "K8S-030":  ["ESF-D-BUILD-ENV"],            # control-plane scheduling
        "K8S-031":  ["ESF-D-PRIV-BUILD"],           # PSA warn missing
        "K8S-032":  ["ESF-D-BUILD-ENV"],            # NetworkPolicy default-deny missing
        "K8S-033":  ["ESF-D-BUILD-ENV"],            # ResourceQuota / LimitRange missing
        "K8S-034":  ["ESF-C-LEAST-PRIV"],           # SA token automount default
        "K8S-035":  ["ESF-D-PRIV-BUILD"],           # runAsUser: 0
        "K8S-036":  ["ESF-S-PIN-DEPS"],             # SA imagePullSecret missing
        "K8S-037":  ["ESF-D-SECRETS"],              # ConfigMap credential
        "K8S-038":  ["ESF-D-BUILD-ENV"],            # NetworkPolicy allow-all
        "K8S-039":  ["ESF-D-PRIV-BUILD"],           # shareProcessNamespace
        "K8S-040":  ["ESF-D-PRIV-BUILD"],           # procMount: Unmasked
        "K8S-041":  ["ESF-D-BUILD-ENV"],            # Service externalIPs
        "K8S-042":  ["ESF-C-LEAST-PRIV"],           # anonymous RoleBinding
        "K8S-043":  ["ESF-D-BUILD-ENV"],            # Ingress wildcard host
        # S3-000 is already mapped above (line 60) as part of the
        # original ``-000`` block at the top of the dict.
    },
)
