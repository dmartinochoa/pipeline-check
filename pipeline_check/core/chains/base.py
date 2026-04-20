"""Data classes for attack-chain detection."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..checks.base import Confidence, Finding, Severity


@dataclass(frozen=True)
class ChainRule:
    """Static metadata for an attack-chain detector.

    Paired 1:1 with a ``match(findings) -> list[Chain]`` callable in the
    same module. The match function decides when the chain fires; this
    dataclass carries the human-readable prose and external-framework
    mappings the reporter renders.
    """

    id: str                       # stable identifier, e.g. "AC-001"
    title: str                    # short headline
    severity: Severity            # composite severity (often CRITICAL)
    summary: str                  # one-paragraph description
    #: MITRE ATT&CK technique IDs (e.g. ``("T1195.002", "T1078.004")``).
    #: Surfaced in SARIF properties + terminal output.
    mitre_attack: tuple[str, ...] = ()
    #: Kill-chain phase label, e.g. ``"initial-access -> exfiltration"``.
    kill_chain_phase: str = ""
    #: External references (URLs, CVE IDs, real-world incident write-ups).
    references: tuple[str, ...] = ()
    #: Cross-finding remediation guidance — what to fix to break the chain.
    recommendation: str = ""
    #: Provider scoping. Empty means provider-agnostic. Used by
    #: ``--list-chains`` to filter and by the engine to short-circuit
    #: when the scan provider can't possibly produce a triggering finding.
    providers: tuple[str, ...] = ()


@dataclass
class Chain:
    """An attack-chain instance — a concrete correlation of findings.

    Built by a :class:`ChainRule`'s ``match()`` callable when the
    underlying findings line up. Carries both the rule's static prose
    and per-instance details (the actual triggering findings, the
    resource(s) involved, a narrative interpolated with concrete names).
    """

    chain_id: str
    title: str
    severity: Severity
    confidence: Confidence
    summary: str
    narrative: str
    mitre_attack: list[str]
    kill_chain_phase: str
    triggering_check_ids: list[str]
    triggering_findings: list[Finding]
    resources: list[str]
    references: list[str]
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "summary": self.summary,
            "narrative": self.narrative,
            "mitre_attack": list(self.mitre_attack),
            "kill_chain_phase": self.kill_chain_phase,
            "triggering_check_ids": list(self.triggering_check_ids),
            "triggering_findings": [
                {"check_id": f.check_id, "resource": f.resource}
                for f in self.triggering_findings
            ],
            "resources": list(self.resources),
            "references": list(self.references),
            "recommendation": self.recommendation,
        }


# ── Helpers shared by chain rules ────────────────────────────────────


def failing(findings: list[Finding], *check_ids: str) -> list[Finding]:
    """Return failing findings whose check_id is in *check_ids*."""
    wanted = set(check_ids)
    return [f for f in findings if (not f.passed) and f.check_id in wanted]


def has_failing(findings: list[Finding], check_id: str) -> bool:
    """Return True if any failing finding matches *check_id*."""
    return any((not f.passed) and f.check_id == check_id for f in findings)


def group_by_resource(
    findings: list[Finding], required: list[str],
) -> dict[str, dict[str, Finding]]:
    """Group failing findings by resource, keep only resources where
    *every* check_id in *required* fired.

    Returned shape: ``{resource: {check_id: Finding}}``. Useful when a
    chain must fire on a *single* workflow file or AWS resource — e.g.
    GHA-002 and GHA-005 must both fire on the *same* workflow for the
    fork-PR chain to be real (a different-workflow combo is not the
    same threat).
    """
    by_res: dict[str, dict[str, Finding]] = defaultdict(dict)
    needed = set(required)
    for f in findings:
        if f.passed or f.check_id not in needed:
            continue
        # If multiple findings of the same check_id fire on the same
        # resource (rare — usually one per resource), keep the first;
        # the chain only needs evidence that the check fired at all.
        if f.check_id not in by_res[f.resource]:
            by_res[f.resource][f.check_id] = f
    return {
        r: ckmap for r, ckmap in by_res.items()
        if all(c in ckmap for c in required)
    }


def min_confidence(findings: list[Finding]) -> Confidence:
    """Return the lowest confidence among *findings* (LOW > MEDIUM > HIGH).

    A chain is only as trustworthy as its weakest leg — if one leg is
    a heuristic blob match, the chain shouldn't claim HIGH confidence.
    """
    from ..checks.base import confidence_rank
    if not findings:
        return Confidence.HIGH
    return min(
        (f.confidence for f in findings),
        key=lambda c: confidence_rank(c),
    )
