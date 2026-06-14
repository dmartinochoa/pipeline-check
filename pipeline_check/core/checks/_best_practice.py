"""Classification of best-practice / missing-control rules.

These rules fire on the ABSENCE of a maturity control: an unbounded
build (no timeout), no artifact signing, no SBOM, no SLSA provenance,
no vulnerability-scan step, etc. They are structurally true (correctly
HIGH confidence) and correctly low / medium severity, but they fire on
most pipelines regardless of whether the pipeline carries the SPECIFIC
vulnerability under review, so they dominate the findings list as
low-signal noise. ``--no-best-practice`` drops them so the output (and
the gate) focus on active-vulnerability findings.

This is a curated central registry rather than a per-rule field on
purpose: the whole classification is auditable in one place, and adding
a rule needs no edit to the rule module (and so no provider-doc
regeneration). It is deliberately conservative, only the
missing-control hygiene family that fires on nearly every build is
listed; rules that flag an active misconfiguration / vulnerability
(unpinned actions, persisted credentials, injection, a present-but-weak
attestation, cloud / SCM posture) are NOT here. Extend ``BEST_PRACTICE_IDS``
as more missing-control rules are identified.
"""
from __future__ import annotations

BEST_PRACTICE_IDS: frozenset[str] = frozenset({
    # Build-time hygiene: timeout / deadline / retention / resource.
    "GHA-015", "GL-015", "JF-015", "JF-011", "BB-005", "CC-011",
    "CC-014", "CC-015", "TKN-006", "GCB-005", "CB-004", "ARGO-007",
    # Artifact signing absent (no cosign / sigstore step).
    "GHA-006", "GL-006", "BB-006", "JF-006", "ADO-006", "CC-006",
    "GCB-009", "ARGO-009", "BK-009", "TKN-009", "DR-019", "HARNESS-015",
    # SBOM not produced.
    "GHA-007", "GL-007", "BB-007", "JF-007", "ADO-007", "CC-007",
    "GCB-015", "ARGO-010", "BK-010", "TKN-010", "DR-020", "HARNESS-016",
    # SLSA provenance attestation not produced.
    "GHA-024", "GL-024", "BB-024", "JF-028", "ADO-024", "CC-024",
    "GCB-017", "ARGO-011", "BK-011", "TKN-011", "DR-021", "HARNESS-017",
    # Vulnerability-scan step absent (+ deploy without a scan gate).
    "GHA-020", "GL-019", "BB-015", "JF-020", "ADO-020", "CC-020",
    "GCB-008", "ARGO-012", "TKN-012", "BK-012", "GHA-098", "DR-022",
    "HARNESS-018",
})


def is_best_practice(check_id: str) -> bool:
    """True if *check_id* is a best-practice / missing-control rule."""
    return check_id in BEST_PRACTICE_IDS
