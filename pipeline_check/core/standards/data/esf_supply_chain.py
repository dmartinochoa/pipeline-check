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
        "GHA-110": ["ESF-S-VERIFY-DEPS"],  # CI env disables Go module verification
        "GHA-002":  ["ESF-D-INJECTION", "ESF-D-BUILD-ENV"],
        "GHA-003":  ["ESF-D-INJECTION"],
        "GHA-119":  ["ESF-D-INJECTION"],# untrusted context into an agentic AI CLI
        "GHA-120":  ["ESF-D-INJECTION"],# trust_remote_code model load = code exec
        "GHA-122":  ["ESF-D-INJECTION"],# unsafe pickle deser of fetched artifact = code exec
        "GHA-121":  ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],# unpinned model registry ref
        "GHA-117":  ["ESF-D-INJECTION"],# IaC apply on untrusted PR trigger
        "GHA-118":  ["ESF-D-INJECTION"],# untrusted content into $GITHUB_ENV / $GITHUB_PATH
        "GHA-004":  ["ESF-C-LEAST-PRIV"],
        "GHA-005":  ["ESF-D-TOKEN-HYGIENE"],
        "GHA-006":  ["ESF-D-SIGN-ARTIFACTS"],
        "GHA-007":  ["ESF-D-SBOM"],
        "GHA-008":  ["ESF-D-SECRETS"],
        "GHA-009":  ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "GHA-010":  ["ESF-D-INJECTION", "ESF-S-PIN-DEPS"],
        "GHA-011":  ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "GHA-012":  ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "GHA-105":  ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "GHA-013":  ["ESF-D-INJECTION"],
        "GHA-014":  ["ESF-C-APPROVAL", "ESF-C-ENV-SEP"],
        "GHA-123":  ["ESF-C-APPROVAL"],# agentic CLI output lands without review
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
        "GL-037": ["ESF-S-VERIFY-DEPS"],  # CI env disables Go module verification
        "GL-002":   ["ESF-D-INJECTION"],
        "GL-045":   ["ESF-D-INJECTION"],   # trust_remote_code model load = code exec
        "GL-046":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # unpinned model registry ref
        "GL-047":   ["ESF-D-INJECTION"],   # unsafe pickle deser of fetched artifact = code exec
        "GL-048":   ["ESF-D-INJECTION"],   # untrusted MR context into agentic CLI = prompt injection
        "GL-049":   ["ESF-C-APPROVAL"],   # agentic CLI output lands without review
        "GL-003":   ["ESF-D-SECRETS"],
        "GL-004":   ["ESF-C-APPROVAL", "ESF-C-ENV-SEP"],
        "GL-044":   ["ESF-C-APPROVAL", "ESF-C-ENV-SEP"],  # auto production deploy on an MR pipeline
        "GL-005":   ["ESF-S-PIN-DEPS", "ESF-S-TRUSTED-REG"],
        "GL-042":   ["ESF-S-PIN-DEPS", "ESF-S-TRUSTED-REG"],    # include: component unpinned
        "GL-006":   ["ESF-D-SIGN-ARTIFACTS"],
        "GL-007":   ["ESF-D-SBOM"],
        "GL-008":   ["ESF-D-SECRETS"],
        "DEV-008":   ["ESF-D-SECRETS"],   # literal secret in a devenv config
        "GL-009":   ["ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"],
        "GL-010":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "GL-011":   ["ESF-D-INJECTION", "ESF-S-PIN-DEPS"],
        "GL-012":   ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],
        "GL-013":   ["ESF-D-TOKEN-HYGIENE"],
        "GL-014":   ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "GL-015":   ["ESF-D-BUILD-TIMEOUT"],
        "GL-016":   ["ESF-S-VERIFY-DEPS"],
        "GL-017":   ["ESF-D-BUILD-ENV"],
        "GL-039":   ["ESF-D-BUILD-ENV"],# dind daemon TLS disabled / exposed on 2375
        "GL-018":   ["ESF-S-VERIFY-DEPS"],
        "GL-019":   ["ESF-S-VULN-MGMT"],
        "GL-043":   ["ESF-S-VULN-MGMT"],
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
        "BB-035":   ["ESF-D-INJECTION"],   # trust_remote_code model load = code exec
        "BB-036":   ["ESF-D-INJECTION"],   # untrusted PR context into agentic CLI = prompt injection
        "BB-037":   ["ESF-D-INJECTION"],   # unsafe pickle deser of fetched artifact = code exec
        "BB-038":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # unpinned model registry ref
        "BB-039":   ["ESF-C-APPROVAL"],   # agentic CLI output lands without review
        "JF-038":   ["ESF-C-APPROVAL"],   # agentic CLI output lands without review
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
        "ADO-034":  ["ESF-D-INJECTION"],   # trust_remote_code model load = code exec
        "ADO-035":  ["ESF-D-INJECTION"],   # untrusted PR context into agentic CLI = prompt injection
        "ADO-036":  ["ESF-D-INJECTION"],   # unsafe pickle deser of fetched artifact = code exec
        "ADO-037":  ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # unpinned model registry ref
        "ADO-038":  ["ESF-C-APPROVAL"],   # agentic CLI output lands without review
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
        "JF-037":   ["ESF-D-INJECTION"],   # agentic CLI ingests untrusted context (prompt injection)
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
        "CC-033": ["ESF-S-VERIFY-DEPS"],  # CI env disables Go module verification
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
        "TKN-016": ["ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"],  # remote resolver / bundle task body not pinned
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
        "ARGO-016": ["ESF-C-LEAST-PRIV"],                          # cluster-admin / over-privileged ServiceAccount
        "ARGO-004": ["ESF-D-PRIV-BUILD", "ESF-D-BUILD-ENV"],       # hostPath / namespaces
        "ARGO-005": ["ESF-D-INJECTION"],                           # parameter injection
        "ARGO-017": ["ESF-D-INJECTION"],                           # resource template manifest injection
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
        # ── Helm extended pack ──
        "HELM-011": ["ESF-D-SECRETS"],
        "HELM-012": ["ESF-S-VERIFY-DEPS"],
        "HELM-013": ["ESF-S-VERIFY-DEPS"],
        "HELM-014": ["ESF-S-VERIFY-DEPS"],
        "HELM-015": ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],  # oci:// dependency not digest-pinned
        "HELM-016": ["ESF-D-SECRETS"],  # default secret in values.yaml
        "HELM-017": ["ESF-S-VERIFY-DEPS"],  # tpl of an untrusted .Values value
        # ── Dockerfile (image build supply chain) ──────────────────
        "DF-001": ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],         # FROM not digest-pinned
        "MODEL-001": ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],      # unpinned base model
        "MODEL-002": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],   # third-party hub base model
        "MODEL-003": ["ESF-S-VERIFY-DEPS"],                        # local unverified weights blob
        "MODEL-004": ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],      # remote LoRA adapter
        "MODEL-005": ["ESF-S-VERIFY-DEPS"],                        # config auto_map = custom loader code
        "DF-031": ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],         # COPY --from external image not digest-pinned
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
        "GCB-027": ["ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"],  # malicious-activity
        # ── SCM posture (governance via the platform REST API) ──────
        # The SCM provider evidences the platform-side controls that
        # gate code into the build pipeline. Map to the Developer
        # guide's "peer review of source and pipeline configuration"
        # (ESF-D-CODE-REVIEW) for branch-protection / review-control
        # rules, the Supplier guide for actions-as-dependencies, and
        # the Customer guide for environment / deployment governance.
        "SCM-001":  ["ESF-D-CODE-REVIEW"],          # default branch unprotected
        "ORG-001":  ["ESF-C-LEAST-PRIV"],           # org: 2FA not required org-wide
        "ORG-002":  ["ESF-C-LEAST-PRIV"],           # org: default member permission too broad
        "ORG-003":  ["ESF-S-VERIFY-DEPS"],          # org: no Actions allow-list (any action runs)
        "ORG-004":  ["ESF-C-LEAST-PRIV", "ESF-D-TOKEN-HYGIENE"],  # org: default workflow token is write
        "ORG-005":  ["ESF-D-CODE-REVIEW"],          # org: Actions can approve PRs (review bypass)
        "ORG-006":  ["ESF-D-SECRETS"],              # org: Actions secret scoped to all repos
        "ORG-007":  ["ESF-C-LEAST-PRIV"],           # org: private-repo forking allowed (code exfiltration)
        "GLGRP-001":  ["ESF-C-LEAST-PRIV"],  # gitlab group: 2FA not required
        "GLGRP-002":  ["ESF-C-LEAST-PRIV"],  # gitlab group: forking outside group allowed
        "GLGRP-003":  ["ESF-C-LEAST-PRIV"],  # gitlab group: sharing projects outside the hierarchy
        "GLGRP-004":  ["ESF-D-CODE-REVIEW"],  # gitlab group: default branch protection disabled for new projects
        "ORG-008":  ["ESF-C-LEAST-PRIV"],           # org: members can create public repos (code exposure)
        "ORG-009":  ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],  # org: self-hosted runner group exposed to public repos
        "ORG-010":  ["ESF-D-SECRETS"],              # org: new-repo secret-scanning push-protection default off
        "ORG-011":  ["ESF-D-SECRETS"],              # org: org webhook over insecure transport
        "ORG-012":  ["ESF-S-VULN-MGMT"],            # org: new-repo Dependabot security-updates default off
        "ORG-013":  ["ESF-D-CODE-REVIEW"],          # org: org ruleset not enforced (evaluate/disabled)
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
        "IAM-009":  ["ESF-D-TOKEN-HYGIENE", "ESF-C-LEAST-PRIV"],   # Azure WIF broad subject
        "IAM-010":  ["ESF-D-TOKEN-HYGIENE", "ESF-C-LEAST-PRIV"],   # GCP WIF no repo condition
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
        "GHA-106":  ["ESF-C-LEAST-PRIV", "ESF-D-TOKEN-HYGIENE"],  # AI agent with write-scoped token
        "GHA-111":  ["ESF-C-LEAST-PRIV", "ESF-D-PRIV-BUILD"],  # AI agent edits IaC applied in the same job
        "GHA-112":  ["ESF-C-APPROVAL", "ESF-D-PRIV-BUILD"],  # self-hosted deploy with no environment gate
        "GHA-113":  ["ESF-D-TOKEN-HYGIENE", "ESF-C-APPROVAL"],  # OIDC trusted-publish w/o env gate
        "GHA-114":  ["ESF-D-TOKEN-HYGIENE", "ESF-C-APPROVAL"],  # publish workflow on an unrestricted push trigger
        "GHA-115":  ["ESF-C-LEAST-PRIV"],            # id-token granted workflow-wide, not job-scoped
        "GHA-116":  ["ESF-D-SECRETS"],               # bulk secrets serialization
        "GHA-107":  ["ESF-D-BUILD-ENV"],             # harden-runner in audit mode (egress not blocked)
        "GHA-108":  ["ESF-D-BUILD-ENV"],             # no runtime egress control on OIDC/deploy workflow
        "GHA-109":  ["ESF-D-BUILD-ENV"],             # harden-runner not the first step
        "GHA-062":  ["ESF-C-LEAST-PRIV"],            # OIDC trust subject in sibling IaC is overly broad
        "GHA-063":  ["ESF-D-INJECTION"],             # spoofable bot-actor if-predicate
        "GHA-064":  ["ESF-D-INJECTION"],             # unsound contains() with comma-string operand
        "GHA-065":  ["ESF-D-INJECTION"],             # zero-width / bidi unicode in workflow body
        "GHA-066":  ["ESF-D-SECRETS"],               # upload-artifact wildcard sweeps workspace
        "GHA-067":  ["ESF-D-SECRETS"],               # cache step publishes credential-shaped paths
        "GHA-068":  ["ESF-D-BUILD-ENV"],             # runs-on targets a deprecated hosted runner
        "GHA-069":  ["ESF-C-LEAST-PRIV"],            # orphan id-token: write scope
        "GHA-070":  ["ESF-S-VERIFY-DEPS"],           # ssh-keyscan / host-key check TOFU
        "GHA-071":  ["ESF-D-INJECTION"],             # powershell on Linux / macOS step
        "GHA-072":  ["ESF-D-SECRETS", "ESF-C-LEAST-PRIV"],  # secret env: at wider scope than consumer
        "GHA-073":  ["ESF-D-SECRETS"],               # unused workflow_call.secrets declaration
        "GHA-086":  ["ESF-C-APPROVAL", "ESF-C-ENV-SEP"],  # wildcard branch trigger gates env-bound deploy
        "GHA-087":  ["ESF-D-SECRETS"],               # derived-value of secret printed to log
        "GHA-088":  ["ESF-S-VERIFY-DEPS"],           # typosquat uses: near-edit of top action
        "GHA-089":  ["ESF-S-VERIFY-DEPS"],           # archived upstream repo
        "GHA-090":  ["ESF-S-VERIFY-DEPS"],           # impostor-commit: SHA absent from repo
        "GHA-091":  ["ESF-S-VERIFY-DEPS"],           # repojacking: action upstream missing
        "GHA-092":  ["ESF-D-CODE-REVIEW"],            # TOCTOU PR head SHA force-push race
        "GHA-093":  ["ESF-D-SECRETS", "ESF-D-INJECTION"],  # LOTP indicators
        "GHA-094":  ["ESF-S-VERIFY-DEPS"],            # stale-action-refs
        "GHA-096":  ["ESF-S-VERIFY-DEPS", "ESF-S-VULN-MGMT"],   # known-vulnerable action ref (GHSA)
        # ── GitLab CI extras ─────────────────────────────────────
        "GL-028":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # services: image not pinned
        "GL-029":   ["ESF-C-APPROVAL"],             # manual deploy allow_failure
        "GL-030":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # trigger: include w/o pinned ref
        "GL-031":   ["ESF-D-TOKEN-HYGIENE", "ESF-C-APPROVAL"],  # id_tokens missing audience pin
        "GL-040":   ["ESF-D-TOKEN-HYGIENE", "ESF-C-APPROVAL"],  # CI_JOB_TOKEN used for cross-project access
        "GL-041":   ["ESF-D-INJECTION"],  # IaC apply on an untrusted MR trigger
        "GL-050":   ["ESF-D-TOKEN-HYGIENE"],  # publish job long-lived registry token (GHA-050 analog)
        "BB-033":   ["ESF-D-INJECTION"],  # IaC apply on a pull-request pipeline
        "BB-034":   ["ESF-C-APPROVAL", "ESF-C-ENV-SEP"],  # production deploy on a pull-request pipeline
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
        "JF-036":   ["ESF-D-INJECTION"],            # sh body interpolates params.*
        # ── Buildkite + Tekton + Argo extras ─────────────────────
        "BK-014":   ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],   # unpinned package install
        "BK-015":   ["ESF-D-INJECTION"],            # agents map untrusted interpolation
        "BK-016":   ["ESF-D-INJECTION"],            # dangerous shell idiom
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
        "ARGOCD-015": ["ESF-S-VERIFY-DEPS"],  # kustomize --enable-helm
        "ARGOCD-009": ["ESF-C-LEAST-PRIV"],                          # anonymous access enabled
        "ARGOCD-014": ["ESF-C-LEAST-PRIV"],  # web terminal exec.enabled
        # ── ArgoCD extended pack ──
        "ARGOCD-010": ["ESF-S-PIN-DEPS"],
        "ARGOCD-017": ["ESF-S-PIN-DEPS", "ESF-C-LEAST-PRIV"],  # in-cluster mutable source
        "ARGOCD-019": ["ESF-C-LEAST-PRIV"],  # drift detection disabled on a sensitive field
        "ARGOCD-016": ["ESF-S-VERIFY-DEPS"],  # Helm valueFiles from a remote URL
        "ARGOCD-018": ["ESF-C-LEAST-PRIV"],  # custom resource health / action Lua
        "ARGOCD-011": ["ESF-C-LEAST-PRIV"],
        "ARGOCD-012": ["ESF-C-APPROVAL"],
        "ARGOCD-013": ["ESF-C-AUDIT"],
        # ── Drone CI ─────────────────────────────────────────────
        "DR-001":   ["ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"],     # step image not digest-pinned
        "HARNESS-001":   ["ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"],  # Harness step image not digest-pinned
        "HARNESS-002":   ["ESF-D-INJECTION"],  # Harness expression injection in step command
        "HARNESS-003":   ["ESF-D-PRIV-BUILD"],  # Harness privileged step
        "HARNESS-004":   ["ESF-D-SECRETS"],  # Harness literal credential in variable
        "HARNESS-005":   ["ESF-S-VERIFY-DEPS"],  # Harness pipe-to-shell
        "HARNESS-006":   ["ESF-S-TRUSTED-REG"],  # Harness TLS bypass in commands
        "HARNESS-007":   ["ESF-D-PRIV-BUILD", "ESF-D-BUILD-ENV"],  # Harness sensitive host-path mount
        "HARNESS-008":   ["ESF-D-INJECTION"],  # Harness agentic-CLI prompt injection
        "HARNESS-010":   ["ESF-D-INJECTION"],  # Harness model trust_remote_code (code exec)
        "HARNESS-011":   ["ESF-D-INJECTION"],  # Harness unsafe model deser (pickle RCE)
        "HARNESS-009":   ["ESF-C-APPROVAL"],  # Harness agentic-CLI output autolands without review
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
        # ── Drone extended pack ──
        "DR-012":   ["ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE"],   # service image not pinned
        "DR-013":   ["ESF-C-APPROVAL"],             # no trigger event filter
        "DR-014":   ["ESF-S-VERIFY-DEPS"],          # pipe-to-shell
        "DR-015":   ["ESF-S-VERIFY-DEPS"],          # clone recursive
        "DR-016":   ["ESF-D-INJECTION", "ESF-S-PIN-DEPS"],   # image field interpolation
        "DR-017":   ["ESF-D-INJECTION"],            # dangerous shell idiom
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
        "NPM-013":  ["ESF-D-SECRETS"],
        "PYPI-001": ["ESF-S-PIN-DEPS"],
        "PYPI-002": ["ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"],
        "PYPI-003": ["ESF-S-TRUSTED-REG"],
        "PYPI-018": ["ESF-S-VERIFY-DEPS"],  # --no-binary forces sdist build
        "PYPI-019": ["ESF-S-VERIFY-DEPS"],  # missing PEP 740 build provenance
        "PYPI-020": ["ESF-S-VERIFY-DEPS"],  # low OpenSSF Scorecard upstream
        "PYPI-021": ["ESF-S-VERIFY-DEPS"],  # provenance built from a non-release ref
        "PYPI-004": ["ESF-S-PIN-DEPS"],
        "PYPI-015": ["ESF-S-VERIFY-DEPS"],  # direct artifact URL
        "PYPI-005": ["ESF-S-TRUSTED-REG"],
        "PYPI-017": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],  # remote --find-links
        "PYPI-016": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],  # primary index repointed
        "PYPI-006": ["ESF-S-VERIFY-DEPS", "ESF-S-VULN-MGMT"],
        "MVN-001":  ["ESF-S-PIN-DEPS"],
        "MVN-002":  ["ESF-S-PIN-DEPS"],
        "MVN-003":  ["ESF-S-TRUSTED-REG"],
        "MVN-004":  ["ESF-S-PIN-DEPS"],
        "MVN-005":  ["ESF-S-VERIFY-DEPS"],
        "MVN-006":  ["ESF-S-VERIFY-DEPS", "ESF-S-VULN-MGMT"],
        "MVN-007":  ["ESF-S-TRUSTED-REG"],
        "MVN-008":  ["ESF-S-VERIFY-DEPS"],
        "MVN-009":  ["ESF-S-VERIFY-DEPS"],
        # ── Maven extended pack ──
        "MVN-010":  ["ESF-D-SECRETS"],
        "MVN-011":  ["ESF-D-SECRETS"],
        "MVN-012":  ["ESF-S-VERIFY-DEPS"],
        "MVN-013":  ["ESF-S-VERIFY-DEPS"],
        "MVN-014":  ["ESF-S-VERIFY-DEPS"],
        "MVN-015": ["ESF-S-VERIFY-DEPS"],  # build-time plugin exec bound to lifecycle
        "MVN-016": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],  # gradle allowInsecureProtocol
        "MVN-017": ["ESF-D-SECRETS"],  # settings.xml privateKey + plaintext passphrase
        "MVN-018": ["ESF-S-VERIFY-DEPS"],  # distributionManagement release accepts snapshots
        "NPM-008":  ["ESF-S-VERIFY-DEPS"],
        "NPM-009":  ["ESF-S-VERIFY-DEPS"],
        "NPM-010":  ["ESF-S-VERIFY-DEPS"],
        "NPM-014":  ["ESF-S-VERIFY-DEPS"],
        "NPM-015":  ["ESF-S-VERIFY-DEPS"],
        "NPM-017":  ["ESF-S-VERIFY-DEPS"],  # provenance built from a non-release ref
        "NPM-018":  ["ESF-S-VERIFY-DEPS"],  # latest release from a new publisher
        "NPM-019":  ["ESF-S-VERIFY-DEPS"],  # overrides / resolutions redirect
        "NPM-020":  ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],  # .npmrc registry repoint
        "NPM-016":  ["ESF-S-VERIFY-DEPS"],
        "PYPI-008": ["ESF-S-VERIFY-DEPS"],
        "PYPI-009": ["ESF-S-VERIFY-DEPS"],
        # ── PyPI extended pack ──
        "PYPI-010": ["ESF-D-SECRETS"],
        "PYPI-011": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],
        "PYPI-012": ["ESF-S-VERIFY-DEPS"],
        "PYPI-013": ["ESF-S-VERIFY-DEPS"],
        "PYPI-014": ["ESF-S-TRUSTED-REG"],
        # nuget (csproj + NuGet.config static analysis)
        "NUGET-001": ["ESF-S-VERIFY-DEPS"],
        "NUGET-002": ["ESF-S-VERIFY-DEPS"],
        "NUGET-003": ["ESF-S-VERIFY-DEPS"],
        "NUGET-004": ["ESF-S-VERIFY-DEPS"],
        "NUGET-005": ["ESF-S-VERIFY-DEPS"],
        "NUGET-006": ["ESF-S-VERIFY-DEPS"],
        "NUGET-007": ["ESF-S-VERIFY-DEPS"],
        "NUGET-008": ["ESF-S-VERIFY-DEPS"],
        "NUGET-009": ["ESF-S-VERIFY-DEPS"],
        "NUGET-010": ["ESF-D-SECRETS"],
        # ── NuGet extended pack ──
        "NUGET-011": ["ESF-S-VERIFY-DEPS"],
        "NUGET-012": ["ESF-S-VERIFY-DEPS", "ESF-S-PROVENANCE"],
        "NUGET-013": ["ESF-S-VERIFY-DEPS"],
        "NUGET-014": ["ESF-D-SECRETS"],
        "NUGET-015": ["ESF-S-VERIFY-DEPS"],
        "NUGET-016": ["ESF-S-VERIFY-DEPS"],  # missing <clear/> inherits public gallery
        "NUGET-017": ["ESF-S-VERIFY-DEPS"],  # public gallery active alongside private feed, not disabled
        "NUGET-018": ["ESF-S-VERIFY-DEPS"],  # build-time MSBuild execution
        "NUGET-019": ["ESF-S-VERIFY-DEPS", "ESF-S-PROVENANCE"],  # require mode, no trusted signers
        # ── Go modules ──
        "GOMOD-001": ["ESF-S-VERIFY-DEPS"],
        "GOMOD-002": ["ESF-S-VERIFY-DEPS"],
        "GOMOD-003": ["ESF-S-VERIFY-DEPS"],
        "GOMOD-004": ["ESF-S-VERIFY-DEPS"],
        "GOMOD-005": ["ESF-S-VERIFY-DEPS"],
        "GOMOD-006": ["ESF-S-VERIFY-DEPS"],
        # ── Go modules extended pack ──
        "GOMOD-007": ["ESF-S-VERIFY-DEPS"],
        "GOMOD-008": ["ESF-S-VERIFY-DEPS"],
        "GOMOD-009": ["ESF-S-VERIFY-DEPS"],
        "GOMOD-010": ["ESF-S-VERIFY-DEPS"],
        "GOMOD-011": ["ESF-S-VERIFY-DEPS"],  # tool directive build-time exec
        "GOMOD-012": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],  # insecure / non-canonical module host
        # ── Cargo ──
        "CARGO-001": ["ESF-S-VERIFY-DEPS"],
        "CARGO-002": ["ESF-S-VERIFY-DEPS"],
        "CARGO-003": ["ESF-S-VERIFY-DEPS"],
        "CARGO-004": ["ESF-S-VERIFY-DEPS"],
        "CARGO-005": ["ESF-S-VERIFY-DEPS"],
        "CARGO-006": ["ESF-S-VERIFY-DEPS"],
        # ── Cargo extended pack ──
        "CARGO-007": ["ESF-S-VERIFY-DEPS"],
        "CARGO-008": ["ESF-S-VERIFY-DEPS"],
        "CARGO-009": ["ESF-S-VERIFY-DEPS"],
        "CARGO-010": ["ESF-S-VERIFY-DEPS"],
        "CARGO-011": ["ESF-S-VERIFY-DEPS"],  # build.rs compile-time egress / exec
        "CARGO-012": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],  # .cargo/config.toml source override / build flags
        "CARGO-013": ["ESF-S-VERIFY-DEPS"],  # Cargo.lock off-crates.io source
        "CARGO-014": ["ESF-S-VERIFY-DEPS"],  # no supply-chain audit-gate config
        # ── Composer / PHP ──
        "COMPOSER-001": ["ESF-S-VERIFY-DEPS"],
        "COMPOSER-002": ["ESF-S-VERIFY-DEPS"],
        "COMPOSER-003": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],
        "COMPOSER-012": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],  # disables Packagist / marks custom repo canonical
        "COMPOSER-011": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],  # external VCS repository re-points a package
        "COMPOSER-004": ["ESF-D-SECRETS"],
        "COMPOSER-005": ["ESF-S-VERIFY-DEPS"],
        "COMPOSER-014": ["ESF-S-VERIFY-DEPS"],  # minimum-stability without prefer-stable
        "COMPOSER-006": ["ESF-S-VERIFY-DEPS"],
        "COMPOSER-007": ["ESF-S-VERIFY-DEPS"],
        "COMPOSER-008": ["ESF-S-VERIFY-DEPS"],
        "COMPOSER-009": ["ESF-D-SECRETS"],
        "COMPOSER-010": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],
        "COMPOSER-013": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],  # config.disable-tls
        # ── RubyGems / Bundler ──
        "GEM-001": ["ESF-S-VERIFY-DEPS"],
        "GEM-002": ["ESF-S-VERIFY-DEPS"],
        "GEM-003": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],
        "GEM-004": ["ESF-D-SECRETS"],
        "GEM-005": ["ESF-S-VERIFY-DEPS"],
        "GEM-006": ["ESF-S-VERIFY-DEPS"],
        "GEM-007": ["ESF-S-TRUSTED-REG"],
        "GEM-008": ["ESF-S-VERIFY-DEPS"],
        "GEM-009": ["ESF-D-SECRETS"],
        "GEM-010": ["ESF-S-VERIFY-DEPS"],
        "GEM-011": ["ESF-S-VERIFY-DEPS"],  # Bundler plugin install-time exec
        "GEM-012": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],  # per-gem :source override
        "GEM-013": ["ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"],  # insecure git transport
        # ── Pulumi ──
        "PULUMI-001": ["ESF-D-SECRETS"],
        "PULUMI-002": ["ESF-D-SECRETS"],
        "PULUMI-003": ["ESF-D-SECRETS"],
        "PULUMI-011": ["ESF-S-PROVENANCE"],  # plugin from custom download server
        "PULUMI-004": ["ESF-S-PROVENANCE"],
        "PULUMI-005": ["ESF-C-LEAST-PRIV"],
        "PULUMI-006": ["ESF-C-LEAST-PRIV"],
        # ── Pulumi extended pack ──
        "PULUMI-007": ["ESF-C-LEAST-PRIV"],
        "PULUMI-008": ["ESF-C-LEAST-PRIV"],
        "PULUMI-013": ["ESF-D-INJECTION"],  # dynamic provider deploy-time code
        "PULUMI-014": ["ESF-S-VERIFY-DEPS"],  # ESC environment imported without a qualifier
        "PULUMI-009": ["ESF-S-VERIFY-DEPS"],
        "PULUMI-012": ["ESF-S-PROVENANCE"],  # plugin version unpinned
        "PULUMI-010": ["ESF-D-SECRETS"],
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
        "OCI-009":  ["ESF-S-PROVENANCE"],                      # missing base-image annotations
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
        "TAINT-009": ["ESF-D-SECRETS"],            # env-protected secret flows to unprotected job
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
        "K8S-044":  ["ESF-D-PRIV-BUILD"],           # admission webhook fail-open / unscoped mutating
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
        # supply-chain posture pack
        "GHA-097":  ["ESF-D-CODE-REVIEW"],           # recursive PR auto-merge loop
        "GHA-098":  ["ESF-D-BUILD-ENV"],            # deploy without security scan gate
        "GHA-099":  ["ESF-D-SECRETS"],             # deploy env plaintext secret
        "GHA-100":  ["ESF-D-SIGN-ARTIFACTS"],     # cosign verify no identity binding
        "GHA-102":  ["ESF-D-INJECTION"],           # submodule checkout on PR trigger
        "GHA-103":  ["ESF-D-CODE-REVIEW", "ESF-D-INJECTION"],  # AI review bot on untrusted trigger
        "GHA-104":  ["ESF-D-CODE-REVIEW"],        # AI agent auto-push without PR review
        # Secrets-in-logs (cross-provider)
        "GL-036":   ["ESF-D-SECRETS"],             # secret echoed to GitLab CI log
        "GL-038":   ["ESF-D-SECRETS"],             # CI_DEBUG_TRACE dumps secrets to GitLab CI log
        "BB-032":   ["ESF-D-SECRETS"],             # secret echoed to Bitbucket log
        "ADO-031":  ["ESF-D-SECRETS"],             # secret echoed to Azure DevOps log
        "ADO-032":  ["ESF-D-SECRETS"],             # checkout persistCredentials leaks token to .git/config
        "ADO-033":  ["ESF-D-INJECTION"],           # IaC apply on a PR-validated pipeline
        "CC-032":   ["ESF-D-SECRETS"],             # secret echoed to CircleCI log
        "SCM-048":  ["ESF-D-SECRETS"],             # org codespace secret scoped to all repos
        "SCM-049":  ["ESF-D-SECRETS"],             # classic PAT where fine-grained suffices
        "NPM-012":  ["ESF-D-SECRETS", "ESF-S-VERIFY-DEPS"],  # publish token lacking restrictions
        # ── Azure Cloud (Entra ID / Storage / Key Vault / ACR / Monitor) ──
        "ENTRA-001": ["ESF-C-LEAST-PRIV"],                 # SP assigned Global Administrator
        "ENTRA-002": ["ESF-D-TOKEN-HYGIENE"],              # app credential beyond 180 days
        "ENTRA-003": ["ESF-D-TOKEN-HYGIENE"],              # SP uses password credential
        "AZST-001":  ["ESF-C-ARTIFACT-AUTHZ"],             # public blob access
        "AZST-002":  ["ESF-S-TRUSTED-REG"],                # non-HTTPS traffic
        "AZST-003":  ["ESF-C-ARTIFACT-AUTHZ"],             # no CMK encryption
        "AKV-001":   ["ESF-C-ARTIFACT-AUTHZ"],             # soft delete not enabled
        "AKV-002":   ["ESF-C-ARTIFACT-AUTHZ"],             # purge protection not enabled
        "AKV-003":   ["ESF-C-ARTIFACT-AUTHZ"],             # network ACLs allow all
        "ACR-001":   ["ESF-C-LEAST-PRIV"],                 # admin user enabled
        "ACR-002":   ["ESF-C-ARTIFACT-AUTHZ"],             # public network access
        "ACR-003":   ["ESF-D-SIGN-ARTIFACTS"],             # content trust not enabled
        "AZMON-001": ["ESF-C-AUDIT"],                      # no diagnostic setting
        "AZMON-002": ["ESF-C-AUDIT"],                      # log retention < 365 days
        "AZMON-003": ["ESF-C-DEPLOY-MON"],                 # no alert rule
        # ── GCP (IAM / GCS / KMS / Artifact Registry / Cloud Logging) ────
        "GCIAM-001": ["ESF-C-LEAST-PRIV"],                 # SA has Owner/Editor role
        "GCIAM-002": ["ESF-D-TOKEN-HYGIENE"],              # user-managed SA key
        "GCIAM-003": ["ESF-C-LEAST-PRIV"],                 # token creator without condition
        "GCS-001":   ["ESF-C-ARTIFACT-AUTHZ"],             # public bucket
        "GCS-002":   ["ESF-C-ARTIFACT-AUTHZ"],             # no uniform access
        "GCS-003":   ["ESF-S-IMMUTABLE"],                  # versioning not enabled
        "GCKMS-001": ["ESF-C-ARTIFACT-AUTHZ"],             # key rotation > 365 days
        "GCKMS-002": ["ESF-C-LEAST-PRIV"],                 # public KMS key access
        "GCKMS-003": ["ESF-C-ARTIFACT-AUTHZ"],             # no HSM protection
        "GAR-001":   ["ESF-S-VULN-MGMT"],                  # no vulnerability scanning
        "GAR-002":   ["ESF-C-ARTIFACT-AUTHZ"],             # publicly readable repo
        "GAR-003":   ["ESF-D-BUILD-ENV"],                  # no cleanup policy
        "GCLOG-001": ["ESF-C-AUDIT"],                      # audit logs not enabled
        "GCLOG-002": ["ESF-C-AUDIT"],                      # no log sink
        "GCLOG-003": ["ESF-C-AUDIT"],                      # log retention < 365 days
        # ── Azure Cloud phase-2 ──────────────────────────────────────
        "ENTRA-004": ["ESF-D-TOKEN-HYGIENE"],              # cond access MFA
        "ENTRA-005": ["ESF-C-LEAST-PRIV"],                 # ext user restrict
        "ENTRA-006": ["ESF-C-AUDIT"],                      # risky signin
        "AZST-004":  ["ESF-S-TRUSTED-REG"],                # min TLS
        "AZST-005":  ["ESF-D-BUILD-ENV"],                  # lifecycle
        "AZST-006":  ["ESF-D-TOKEN-HYGIENE"],              # key rotation
        "AKV-004":   ["ESF-D-TOKEN-HYGIENE"],              # key expiry
        "AKV-005":   ["ESF-D-TOKEN-HYGIENE"],              # secret expiry
        "AKV-006":   ["ESF-C-LEAST-PRIV"],                 # RBAC
        "ACR-004":   ["ESF-S-VULN-MGMT"],                  # defender scan
        "ACR-005":   ["ESF-S-IMMUTABLE"],                   # tag immutability
        "AZMON-004": ["ESF-C-AUDIT"],                      # KV diagnostics
        "AZMON-005": ["ESF-C-AUDIT"],                      # NSG flow retention
        "AZMON-006": ["ESF-C-AUDIT"],                      # LAW retention
        "AZMON-007": ["ESF-C-DEPLOY-MON"],                 # svc health alert
        "AZNW-001":  ["ESF-D-BUILD-ENV"],                  # SSH/RDP internet (CRITICAL)
        "AZNW-002":  ["ESF-C-AUDIT"],                      # flow logs
        "AZNW-003":  ["ESF-D-BUILD-ENV"],                  # WAF
        "AZNW-004":  ["ESF-D-BUILD-ENV"],                  # deny-all
        "AZNW-005":  ["ESF-D-BUILD-ENV"],                  # public IP VM
        "AZAPP-001": ["ESF-S-TRUSTED-REG"],                # HTTPS
        "AZAPP-002": ["ESF-S-TRUSTED-REG"],                # TLS
        "AZAPP-003": ["ESF-D-TOKEN-HYGIENE"],              # managed identity
        "AZAPP-004": ["ESF-D-BUILD-ENV"],                  # remote debug
        "AZAPP-005": ["ESF-D-BUILD-ENV"],                  # FTP
        "AZSQL-001": ["ESF-C-ARTIFACT-AUTHZ"],             # TDE CMK
        "AZSQL-002": ["ESF-C-AUDIT"],                      # auditing
        "AZSQL-003": ["ESF-D-BUILD-ENV"],                  # public access
        "AZSQL-004": ["ESF-C-LEAST-PRIV"],                 # AAD admin
        "AZSQL-005": ["ESF-S-VULN-MGMT"],                  # threat detect
        "AZVM-001":  ["ESF-C-ARTIFACT-AUTHZ"],             # disk encrypt
        "AZVM-002":  ["ESF-D-BUILD-ENV"],                  # public IP
        "AZVM-003":  ["ESF-D-BUILD-ENV"],                  # JIT
        "AZVM-004":  ["ESF-S-VULN-MGMT"],                  # OS patch
        "AZVM-005":  ["ESF-D-TOKEN-HYGIENE"],              # managed identity
        # ── GCP phase-2 ──────────────────────────────────────────────
        "GCIAM-004": ["ESF-C-LEAST-PRIV"],                 # default SA
        "GCIAM-005": ["ESF-C-LEAST-PRIV"],                 # domain restrict
        "GCIAM-006": ["ESF-D-TOKEN-HYGIENE"],              # SA key age
        "GCS-004":   ["ESF-C-ARTIFACT-AUTHZ"],             # CMEK
        "GCS-005":   ["ESF-C-AUDIT"],                      # access logging
        "GCLOG-004": ["ESF-C-AUDIT"],                      # VPC flow logs
        "GCLOG-005": ["ESF-C-AUDIT"],                      # firewall logging
        "GCLOG-006": ["ESF-C-AUDIT"],                      # data access
        "GCLOG-007": ["ESF-C-AUDIT"],                      # metric filter IAM
        "GCLOG-008": ["ESF-C-AUDIT"],                      # metric filter firewall
        "GCLOG-009": ["ESF-C-AUDIT"],                      # metric filter route
        "GCLOG-010": ["ESF-C-AUDIT"],                      # metric filter SQL
        "GCLOG-011": ["ESF-C-AUDIT"],                      # metric filter custom role
        "GCNET-001": ["ESF-D-BUILD-ENV"],                  # default network
        "GCNET-002": ["ESF-D-BUILD-ENV"],                  # deny-all
        "GCNET-003": ["ESF-D-BUILD-ENV"],                  # SSH/RDP (CRITICAL)
        "GCNET-004": ["ESF-D-BUILD-ENV"],                  # private access
        "GCNET-005": ["ESF-D-BUILD-ENV"],                  # Cloud NAT
        "GCCE-001":  ["ESF-D-BUILD-ENV"],                  # shielded VM
        "GCCE-002":  ["ESF-D-TOKEN-HYGIENE"],              # OS Login
        "GCCE-003":  ["ESF-D-BUILD-ENV"],                  # serial port
        "GCCE-004":  ["ESF-D-BUILD-ENV"],                  # public IP
        "GCCE-005":  ["ESF-D-BUILD-ENV"],                  # project SSH keys
        "GCSQL-001": ["ESF-D-BUILD-ENV"],                  # public IP
        "GCSQL-002": ["ESF-C-ROLLBACK"],                   # backups
        "GCSQL-003": ["ESF-S-TRUSTED-REG"],                # SSL
        "GCSQL-004": ["ESF-C-LEAST-PRIV"],                 # IAM auth
        "GCSQL-005": ["ESF-C-ROLLBACK"],                   # PITR
        "GCRUN-001": ["ESF-D-BUILD-ENV"],                  # unauth
        "GCRUN-002": ["ESF-C-LEAST-PRIV"],                 # custom SA
        "GCRUN-003": ["ESF-C-DEPLOY-MON"],                 # min instances
        "GCRUN-004": ["ESF-D-BUILD-ENV"],                  # VPC connector
        "GCKMS-004": ["ESF-C-LEAST-PRIV"],                 # keyring IAM
        "GCKMS-005": ["ESF-C-ARTIFACT-AUTHZ"],             # destroy sched
        "GCKMS-006": ["ESF-C-ARTIFACT-AUTHZ"],             # imported key
        # Developer-environment auto-execution
        "DEV-001":   ["ESF-D-INJECTION"],                  # vscode folderOpen task
        "DEV-006":   ["ESF-D-INJECTION"],                  # vscode settings exec-path / env injection
        "DEV-007":   ["ESF-D-INJECTION"],                  # committed MCP config auto-launches a command server
        "DEV-002":   ["ESF-D-INJECTION"],                  # devcontainer lifecycle
        "DEV-003":   ["ESF-D-INJECTION"],                  # committed claude hook
        "DEV-004":   ["ESF-S-VERIFY-DEPS", "ESF-D-INJECTION"],  # remote fetch+exec
        "DEV-005":   ["ESF-D-INJECTION"],                  # initializeCommand on host
    },
)
