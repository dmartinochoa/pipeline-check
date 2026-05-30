"""CARGO-014. No supply-chain audit-gate config (cargo-deny / vet / audit)."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CargoFile

RULE = Rule(
    id="CARGO-014",
    title="No supply-chain audit-gate config (cargo-deny / cargo-vet / cargo-audit)",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add a committed supply-chain audit gate so dependency "
        "advisories, license drift, and untrusted sources fail the "
        "build instead of going unnoticed. Pick one (or more) and "
        "wire it into CI:\n\n"
        "* cargo-deny: a ``deny.toml`` (advisory DB, license "
        "allowlist, banned crates, source allowlist), run with "
        "``cargo deny check``.\n"
        "* cargo-vet: a ``supply-chain/`` directory (``config.toml`` "
        "+ ``audits.toml``) recording who reviewed each dependency, "
        "run with ``cargo vet``.\n"
        "* cargo-audit: ``cargo audit`` against the RustSec advisory "
        "DB (optionally an ``audit.toml`` to tune it).\n\n"
        "This is a posture signal (LOW): it doesn't prove a "
        "vulnerable dependency exists, only that the repo carries no "
        "committed gate to catch one. Parallel to CARGO-010 "
        "(missing ``rust-version``)."
    ),
    docs_note=(
        "Fires when a manifest declares dependencies but no "
        "committed audit-gate config is found at or above the "
        "manifest directory (bounded by the scan root): cargo-deny's "
        "``deny.toml``, cargo-vet's ``supply-chain/config.toml``, or "
        "cargo-audit's ``audit.toml`` / ``.cargo/audit.toml``. A "
        "dependency-free manifest passes (nothing to gate).\n\n"
        "LOW severity, below the default gate: it's a "
        "completeness / posture nudge, not a finding about a "
        "specific bad dependency (CARGO-006 / CARGO-013 cover those)."
    ),
    known_fp=(
        "A repo that runs ``cargo audit`` purely as a CI step with no "
        "committed config file leaves nothing on disk for this rule "
        "to detect, so it fires as a false positive. Suppress per "
        "repo with a rationale naming the CI gate, or commit a "
        "minimal ``deny.toml`` / ``audit.toml`` so the gate is "
        "visible in the tree.",
    ),
    exploit_example=None,
)


def check(manifest: CargoFile) -> Finding:
    # A dependency-free manifest (or a workspace root that only
    # aggregates members) has nothing to gate.
    if not manifest.dependencies:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description="Manifest declares no dependencies to gate.",
            recommendation=RULE.recommendation, passed=True,
        )
    if manifest.has_audit_gate:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "A supply-chain audit-gate config (cargo-deny / "
                "cargo-vet / cargo-audit) is present."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path,
        description=(
            "No committed supply-chain audit-gate config "
            "(cargo-deny deny.toml, cargo-vet supply-chain/, or "
            "cargo-audit audit.toml) found for this crate. Dependency "
            "advisories and untrusted sources go uncaught without a "
            "gate."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
