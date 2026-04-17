"""NIST SP 800-190 — Application Container Security Guide (2017).

Purpose-built for container-based workloads. Section 4 enumerates
*risks* across images, registries, orchestrators, containers, and the
host OS. Section 5 enumerates *countermeasures*. This scanner's
container-adjacent rules (image pinning, privileged-mode, TLS bypass,
vulnerability scanning, embedded secrets) give direct evidence of
the Section 4 risk set.

Control IDs here use the SP 800-190 section numbering (e.g. "4.1.5"
for "Use of untrusted images"). The guide is not a formal control
list, but the numbered subsections are how compliance teams cite it.

Out of scope: orchestrator risks (4.3) and host OS risks (4.5) require
runtime-environment visibility the scanner does not have. Risks 4.3.1
(unbounded admin access to orchestrator) and 4.3.3 (workload sensitivity
mixing) are architectural concerns outside pipeline config.
"""
from __future__ import annotations

from ..base import Standard

STANDARD = Standard(
    name="nist_800_190",
    title="NIST SP 800-190 Application Container Security",
    version="1.0 (Sep 2017)",
    url="https://doi.org/10.6028/NIST.SP.800-190",
    controls={
        # ── 4.1 — Image risks ───────────────────────────────────────
        "4.1.1": "Image vulnerabilities — unpatched CVEs baked into images",
        "4.1.2": "Image configuration defects — privileged flags, insecure runtime settings",
        "4.1.3": "Embedded malware in images",
        "4.1.4": "Embedded clear-text secrets in images",
        "4.1.5": "Use of untrusted images — unpinned tags, unknown provenance",
        # ── 4.2 — Registry risks ────────────────────────────────────
        "4.2.1": "Insecure connections to registries (no TLS / cert validation bypassed)",
        "4.2.2": "Stale images in registries — drift and unpatched images",
        "4.2.3": "Insufficient authentication and authorization restrictions on registries",
        # ── 4.4 — Container risks ───────────────────────────────────
        "4.4.3": "Unbounded network access from containers — egress not restricted",
        "4.4.4": "Insecure container runtime configurations — privileged flag, host namespace sharing",
        "4.4.5": "App vulnerabilities — untrusted code paths reached at runtime",
        "4.4.6": "Rogue containers — unvetted images executed inside pipeline",
    },
    mappings={
        # ── 4.1.1 — Image vulnerabilities ───────────────────────────
        # CB-005 / ECR-002 / GCB-007 also evidence 4.2.2 (stale/drift).
        "CB-005":   ["4.1.1", "4.2.2"],
        "ECR-001":  ["4.1.1"],
        "ECR-007":  ["4.1.1"],
        "GHA-020":  ["4.1.1"],
        "GL-019":   ["4.1.1"],
        "BB-015":   ["4.1.1"],
        "ADO-020":  ["4.1.1"],
        "JF-020":   ["4.1.1"],
        "CC-020":   ["4.1.1"],
        "GCB-008":  ["4.1.1"],

        # ── 4.1.2 — Image configuration defects ─────────────────────
        "CB-002":   ["4.1.2", "4.4.4"],
        "GHA-017":  ["4.1.2", "4.4.4"],
        "GHA-026":  ["4.1.2", "4.4.3"],
        "GL-017":   ["4.1.2", "4.4.4"],
        "BB-013":   ["4.1.2", "4.4.4"],
        "ADO-017":  ["4.1.2", "4.4.4"],
        "JF-017":   ["4.1.2", "4.4.4"],
        "JF-025":   ["4.1.2", "4.4.4"],
        "CC-017":   ["4.1.2", "4.4.4"],

        # ── 4.1.3 — Embedded malware ────────────────────────────────
        "CB-011":   ["4.1.3"],
        "GHA-003":  ["4.1.3"],
        "GHA-016":  ["4.1.3"],
        "GHA-027":  ["4.1.3"],
        "GHA-028":  ["4.1.3"],
        "GL-002":   ["4.1.3"],
        "GL-016":   ["4.1.3"],
        "GL-025":   ["4.1.3"],
        "GL-026":   ["4.1.3"],
        "BB-002":   ["4.1.3"],
        "BB-012":   ["4.1.3"],
        "BB-025":   ["4.1.3"],
        "BB-026":   ["4.1.3"],
        "ADO-002":  ["4.1.3"],
        "ADO-016":  ["4.1.3"],
        "ADO-026":  ["4.1.3"],
        "ADO-027":  ["4.1.3"],
        "JF-002":   ["4.1.3"],
        "JF-016":   ["4.1.3"],
        "JF-029":   ["4.1.3"],
        "JF-030":   ["4.1.3"],
        "CC-002":   ["4.1.3"],
        "CC-016":   ["4.1.3"],
        "CC-026":   ["4.1.3"],
        "CC-027":   ["4.1.3"],
        "GCB-004":  ["4.1.3"],
        "GCB-006":  ["4.1.3"],

        # ── 4.1.4 — Embedded clear-text secrets ─────────────────────
        "CB-001":   ["4.1.4"],
        "GHA-005":  ["4.1.4"],
        "GHA-008":  ["4.1.4"],
        "GL-003":   ["4.1.4"],
        "GL-008":   ["4.1.4"],
        "GL-013":   ["4.1.4"],
        "BB-003":   ["4.1.4"],
        "BB-008":   ["4.1.4"],
        "BB-011":   ["4.1.4"],
        "BB-019":   ["4.1.4"],
        "ADO-003":  ["4.1.4"],
        "ADO-008":  ["4.1.4"],
        "ADO-014":  ["4.1.4"],
        "JF-008":   ["4.1.4"],
        "JF-010":   ["4.1.4"],
        "CC-005":   ["4.1.4"],
        "CC-008":   ["4.1.4"],
        "GCB-003":  ["4.1.4"],
        "LMB-003":  ["4.1.4"],

        # ── 4.1.5 — Use of untrusted images (pinning + provenance) ──
        "CB-009":   ["4.1.5"],
        "ECR-002":  ["4.1.5", "4.2.2"],
        "ECR-006":  ["4.1.5"],
        "CA-002":   ["4.1.5"],
        "GHA-001":  ["4.1.5"],
        "GHA-018":  ["4.1.5"],
        "GHA-021":  ["4.1.5"],
        "GHA-025":  ["4.1.5"],
        "GHA-029":  ["4.1.5"],
        "GL-001":   ["4.1.5"],
        "GL-005":   ["4.1.5"],
        "GL-009":   ["4.1.5"],
        "GL-018":   ["4.1.5"],
        "GL-021":   ["4.1.5"],
        "GL-027":   ["4.1.5"],
        "GL-028":   ["4.1.5"],
        "GL-030":   ["4.1.5"],
        "BB-001":   ["4.1.5"],
        "BB-009":   ["4.1.5"],
        "BB-014":   ["4.1.5"],
        "BB-021":   ["4.1.5"],
        "BB-027":   ["4.1.5"],
        "ADO-001":  ["4.1.5"],
        "ADO-005":  ["4.1.5"],
        "ADO-009":  ["4.1.5"],
        "ADO-018":  ["4.1.5"],
        "ADO-021":  ["4.1.5"],
        "ADO-025":  ["4.1.5"],
        "ADO-028":  ["4.1.5"],
        "JF-001":   ["4.1.5"],
        "JF-009":   ["4.1.5"],
        "JF-018":   ["4.1.5"],
        "JF-021":   ["4.1.5"],
        "JF-031":   ["4.1.5"],
        "CC-001":   ["4.1.5"],
        "CC-003":   ["4.1.5"],
        "CC-018":   ["4.1.5"],
        "CC-021":   ["4.1.5"],
        "CC-028":   ["4.1.5"],
        "CC-029":   ["4.1.5"],
        "GCB-001":  ["4.1.5"],
        "GCB-007":  ["4.1.5", "4.2.2"],

        # ── 4.2.1 — Insecure connections to registries ──────────────
        "GHA-023":  ["4.2.1"],
        "GL-023":   ["4.2.1"],
        "BB-023":   ["4.2.1"],
        "ADO-023":  ["4.2.1"],
        "JF-023":   ["4.2.1"],
        "CC-023":   ["4.2.1"],
        "S3-005":   ["4.2.1"],

        # ── 4.2.2 — Stale images / drift ────────────────────────────
        # CB-005 / ECR-002 / GCB-007 co-map up in 4.1.1 / 4.1.5 to
        # preserve a single dict-key per check_id.
        "ECR-004":  ["4.2.2"],

        # ── 4.2.3 — Registry auth/authz restrictions ────────────────
        "ECR-003":  ["4.2.3"],
        "CA-004":   ["4.2.3"],
        "ECR-005":  ["4.2.3"],             # KMS-encrypted = authz to decrypt

        # ── 4.4.3 — Unbounded container network access ──────────────
        "PBAC-001": ["4.4.3"],
        "PBAC-003": ["4.4.3"],
        "GHA-012":  ["4.4.3"],             # self-hosted runner = uncontrolled net
        "GL-014":   ["4.4.3"],
        "BB-016":   ["4.4.3"],
        "ADO-013":  ["4.4.3"],
        "JF-014":   ["4.4.3"],
        "CC-010":   ["4.4.3"],

        # ── 4.4.5 — App vulnerabilities reached at runtime ──────────
        # Untrusted trigger paths that run untrusted code against
        # pipeline identity — poisoned pipeline execution.
        "CB-010":   ["4.4.5"],
        "GHA-002":  ["4.4.5"],
        "GHA-009":  ["4.4.5"],
        "GHA-010":  ["4.4.5"],
        "GHA-013":  ["4.4.5"],
        "GL-010":   ["4.4.5"],
        "GL-011":   ["4.4.5"],
        "BB-010":   ["4.4.5"],
        "ADO-010":  ["4.4.5"],
        "ADO-011":  ["4.4.5"],
        "ADO-019":  ["4.4.5"],
        "JF-012":   ["4.4.5"],
        "JF-013":   ["4.4.5"],
        "JF-019":   ["4.4.5"],
        "CC-012":   ["4.4.5"],

        # ── 4.4.6 — Rogue / unvetted containers ─────────────────────
        "CP-003":   ["4.4.6"],             # polling source = rogue-commit window
        "CP-007":   ["4.4.6"],
        "GHA-011":  ["4.4.6"],             # poisoned cache
        "GL-012":   ["4.4.6"],
        "BB-018":   ["4.4.6"],
        "ADO-012":  ["4.4.6"],
        "CC-025":   ["4.4.6"],
        "CC-013":   ["4.4.6"],             # no branch filter = rogue input
    },
)
