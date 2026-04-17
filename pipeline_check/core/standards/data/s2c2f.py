"""S2C2F — Secure Supply Chain Consumption Framework (OpenSSF / Microsoft).

S2C2F is a purpose-built framework for how an organization *consumes*
open-source software in its CI/CD pipeline. It's organized into 8
practices (Ingest, Scan, Inventory, Update, Enforce, Audit, Rebuild,
Fix) with requirements at maturity levels L1–L4.

This scanner evidences a focused subset — the requirements that show
up as pipeline configuration (not the ones that require org-level
process or external tooling visibility). Level 4 rebuild requirements
(REB-1: rebuild on trusted infra, REB-2/3/4: sign + SBOM the rebuild)
overlap the signing / SBOM / SLSA-attestation rules directly.

Unmapped practices (require introspection outside this scanner):
  ING-2 (binary repo manager), ING-4 (source mirror), INV-1 (component
  inventory registry), AUD-1/2 (per-PR evidence), SCA-2 (license
  scanning), SCA-4 (EOL tracking), FIX-1/2/3 (incident process).
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="s2c2f",
    title="Secure Supply Chain Consumption Framework",
    version="2024-05",
    url="https://github.com/ossf/s2c2f/blob/main/specification/framework.md",
    controls={
        # ── Ingest ─────────────────────────────────────────────────
        "ING-1": "L1: Use package managers trusted by your organization",
        "ING-3": "L1: Have the capability to deny-list specific vulnerable / malicious OSS",
        # ── Scan ───────────────────────────────────────────────────
        "SCA-1": "L1: Scan OSS for known vulnerabilities",
        "SCA-3": "L2: Scan OSS for malware",
        # ── Update ─────────────────────────────────────────────────
        "UPD-1": "L1: Update vulnerable OSS manually (pin + track versions)",
        "UPD-2": "L3: Enable automated OSS updates (Dependabot / Renovate)",
        # ── Enforce ────────────────────────────────────────────────
        "ENF-1": "L2: Enforce security policy of OSS usage (block on violation)",
        "ENF-2": "L2: Break the build when a violation is detected",
        # ── Rebuild ────────────────────────────────────────────────
        "REB-2": "L4: Digitally sign rebuilt / produced OSS artifacts",
        "REB-3": "L4: Generate SBOMs for artifacts produced",
        "REB-4": "L4: Digitally sign SBOMs produced (attested provenance)",
    },
    mappings={
        # ── ING-1 / ING-3: trusted sources, deny-listable ──────────
        "GHA-018":  ["ING-1"],
        "GL-018":   ["ING-1"],
        "BB-014":   ["ING-1"],
        "ADO-018":  ["ING-1"],
        "JF-018":   ["ING-1"],
        "CC-018":   ["ING-1"],
        "CA-002":   ["ING-1", "ING-3"],    # public upstream = no deny-list gate
        "ECR-006":  ["ING-1"],             # untrusted pull-through upstream
        "GHA-029":  ["ING-1"],             # package source bypasses lockfile
        "GL-027":   ["ING-1"],
        "BB-027":   ["ING-1"],
        "ADO-028":  ["ING-1"],
        "JF-031":   ["ING-1"],
        "CC-028":   ["ING-1"],

        # ── SCA-1: scan for known vulns ────────────────────────────
        "GHA-020":  ["SCA-1"],
        "GL-019":   ["SCA-1"],
        "BB-015":   ["SCA-1"],
        "ADO-020":  ["SCA-1"],
        "JF-020":   ["SCA-1"],
        "CC-020":   ["SCA-1"],
        "GCB-008":  ["SCA-1"],
        "ECR-001":  ["SCA-1"],
        "ECR-007":  ["SCA-1"],             # Inspector v2 enhanced scanning

        # ── SCA-3: scan for malware / malicious activity ───────────
        "CB-011":   ["SCA-3"],
        "GHA-027":  ["SCA-3"],
        "GL-025":   ["SCA-3"],
        "BB-025":   ["SCA-3"],
        "ADO-026":  ["SCA-3"],
        "JF-029":   ["SCA-3"],
        "CC-026":   ["SCA-3"],

        # ── UPD-1: pin + track (pinning rules evidence manual mgmt) ─
        "GHA-001":  ["UPD-1"],
        "GHA-025":  ["UPD-1"],
        "GHA-021":  ["UPD-1"],             # lockfile present = tracked versions
        "GL-001":   ["UPD-1"],
        "GL-005":   ["UPD-1"],
        "GL-009":   ["UPD-1"],
        "GL-021":   ["UPD-1"],
        "GL-028":   ["UPD-1"],
        "GL-030":   ["UPD-1"],
        "BB-001":   ["UPD-1"],
        "BB-009":   ["UPD-1"],
        "BB-021":   ["UPD-1"],
        "ADO-001":  ["UPD-1"],
        "ADO-005":  ["UPD-1"],
        "ADO-009":  ["UPD-1"],
        "ADO-021":  ["UPD-1"],
        "ADO-025":  ["UPD-1"],
        "JF-001":   ["UPD-1"],
        "JF-009":   ["UPD-1"],
        "JF-021":   ["UPD-1"],
        "CC-001":   ["UPD-1"],
        "CC-003":   ["UPD-1"],
        "CC-021":   ["UPD-1"],
        "CC-029":   ["UPD-1"],
        "GCB-001":  ["UPD-1"],
        "CB-005":   ["UPD-1"],
        "CB-009":   ["UPD-1"],
        "ECR-002":  ["UPD-1"],

        # ── UPD-2: automated update tool ───────────────────────────
        "GHA-022":  ["UPD-2"],
        "GL-022":   ["UPD-2"],
        "BB-022":   ["UPD-2"],
        "ADO-022":  ["UPD-2"],
        "JF-022":   ["UPD-2"],
        "CC-022":   ["UPD-2"],

        # ── ENF-1 / ENF-2: enforce policy, break build on violation ─
        # Approval-gate and deploy-env rules evidence the "stop" step.
        "CP-001":   ["ENF-1", "ENF-2"],
        "CP-005":   ["ENF-1", "ENF-2"],
        "CD-002":   ["ENF-1"],
        "GHA-014":  ["ENF-1"],
        "GL-004":   ["ENF-1", "ENF-2"],
        "GL-029":   ["ENF-2"],
        "BB-004":   ["ENF-1"],
        "ADO-004":  ["ENF-1"],
        "JF-005":   ["ENF-1"],
        "JF-024":   ["ENF-1"],
        "CC-009":   ["ENF-1"],
        "CB-008":   ["ENF-1"],

        # ── REB-2: digital signing of artifacts ────────────────────
        "SIGN-001": ["REB-2"],
        "SIGN-002": ["REB-2"],
        "LMB-001":  ["REB-2"],
        "CP-002":   ["REB-2"],
        "ECR-005":  ["REB-2"],
        "CA-001":   ["REB-2"],
        "GHA-006":  ["REB-2"],
        "GL-006":   ["REB-2"],
        "BB-006":   ["REB-2"],
        "ADO-006":  ["REB-2"],
        "JF-006":   ["REB-2"],
        "CC-006":   ["REB-2"],
        "GCB-009":  ["REB-2"],

        # ── REB-3: SBOM generation ─────────────────────────────────
        "GHA-007":  ["REB-3"],
        "GL-007":   ["REB-3"],
        "BB-007":   ["REB-3"],
        "ADO-007":  ["REB-3"],
        "JF-007":   ["REB-3"],
        "CC-007":   ["REB-3"],

        # ── REB-4: signed-SBOM / attested provenance ───────────────
        "GHA-024":  ["REB-4"],
        "GL-024":   ["REB-4"],
        "BB-024":   ["REB-4"],
        "ADO-024":  ["REB-4"],
        "JF-028":   ["REB-4"],
        "CC-024":   ["REB-4"],
    },
)
