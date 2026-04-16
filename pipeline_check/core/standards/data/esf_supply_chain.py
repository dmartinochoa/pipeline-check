"""NSA/CISA Enduring Security Framework — Securing the Software Supply Chain.

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
    title="NSA/CISA ESF — Securing the Software Supply Chain",
    version="2022",
    url="https://www.cisa.gov/resources-tools/resources/securing-software-supply-chain-recommended-practices-guide-developers",
    controls={
        # Developer guide — secure development & build
        "ESF-D-BUILD-ENV":       "Harden the build environment (isolated, minimal, ephemeral workers)",
        "ESF-D-BUILD-LOGS":      "Generate and preserve build audit logs",
        "ESF-D-BUILD-TIMEOUT":   "Enforce bounded build execution (single-use, time-limited)",
        "ESF-D-SECRETS":         "Protect secrets used during build; no secrets in source or env",
        "ESF-D-PRIV-BUILD":      "Avoid privileged / host-networked build workers",
        "ESF-D-SIGN-ARTIFACTS":  "Sign build artifacts and verify signatures before release",
        "ESF-D-SBOM":            "Produce SBOM / provenance metadata with every build",
        "ESF-D-CODE-REVIEW":     "Require peer review of source and pipeline configuration",
        "ESF-D-TOKEN-HYGIENE":   "Use short-lived, federated credentials (OIDC) — not long-lived tokens",
        "ESF-D-INJECTION":       "Prevent script / template injection from untrusted pipeline context",
        # Supplier guide — verify and gate third-party inputs
        "ESF-S-VERIFY-DEPS":     "Verify third-party and open-source dependencies before use",
        "ESF-S-PIN-DEPS":        "Pin dependencies / actions / images to immutable digests",
        "ESF-S-TRUSTED-REG":     "Use only trusted, authenticated package and image registries",
        "ESF-S-VULN-MGMT":       "Scan inbound artifacts (images, packages) for known vulnerabilities",
        "ESF-S-IMMUTABLE":       "Enforce artifact / tag immutability to preserve provenance",
        # Customer guide — deployment & runtime governance
        "ESF-C-APPROVAL":        "Require explicit approval before production deployment",
        "ESF-C-ROLLBACK":        "Automated rollback on deployment failure or alarm",
        "ESF-C-DEPLOY-MON":      "Monitor deployments with alarms / health checks",
        "ESF-C-ENV-SEP":         "Separate deployment environments (dev / staging / prod)",
        "ESF-C-ARTIFACT-AUTHZ":  "Restrict access to artifact storage and deployment pipelines",
        "ESF-C-LEAST-PRIV":      "Apply least-privilege to CI/CD service roles and pipelines",
        "ESF-C-AUDIT":           "Audit deployment / pipeline activity and retain logs",
    },
    mappings={
        # ── CodeBuild ──────────────────────────────────────────────
        "CB-001":   ["ESF-D-SECRETS"],
        "CB-002":   ["ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"],
        "CB-003":   ["ESF-D-BUILD-LOGS", "ESF-C-AUDIT"],
        "CB-004":   ["ESF-D-BUILD-TIMEOUT", "ESF-D-BUILD-ENV"],
        "CB-005":   ["ESF-S-VERIFY-DEPS", "ESF-S-PIN-DEPS"],
        "CB-006":   ["ESF-D-TOKEN-HYGIENE"],
        "CB-007":   ["ESF-D-CODE-REVIEW"],
        # ── CodePipeline ───────────────────────────────────────────
        "CP-001":   ["ESF-C-APPROVAL", "ESF-D-CODE-REVIEW"],
        "CP-002":   ["ESF-D-SIGN-ARTIFACTS", "ESF-C-ARTIFACT-AUTHZ"],
        "CP-003":   ["ESF-D-CODE-REVIEW"],
        "CP-004":   ["ESF-D-TOKEN-HYGIENE"],
        # ── CodeDeploy ─────────────────────────────────────────────
        "CD-001":   ["ESF-C-ROLLBACK"],
        "CD-002":   ["ESF-C-ENV-SEP", "ESF-C-APPROVAL"],
        "CD-003":   ["ESF-C-DEPLOY-MON"],
        # ── ECR ────────────────────────────────────────────────────
        "ECR-001":  ["ESF-S-VULN-MGMT", "ESF-S-VERIFY-DEPS"],
        "ECR-002":  ["ESF-S-IMMUTABLE", "ESF-D-SBOM"],
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
        "S3-003":   ["ESF-S-IMMUTABLE", "ESF-D-SBOM"],
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
    },
)
