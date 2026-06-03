"""Data classes for attack-chain detection."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from ..checks.base import Confidence, Finding, Severity, confidence_rank


@dataclass(frozen=True, slots=True)
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
    #: Cross-finding remediation guidance, what to fix to break the chain.
    recommendation: str = ""
    #: Provider scoping. Empty means provider-agnostic. Used by
    #: ``--list-chains`` to filter and by the engine to short-circuit
    #: when the scan provider can't possibly produce a triggering finding.
    providers: tuple[str, ...] = ()
    #: The check_ids whose findings this chain's ``match()`` correlates.
    #: Cross-references the rule layer: ``--explain CHECK_ID`` looks up
    #: every chain whose ``triggering_check_ids`` contains the rule's
    #: id and surfaces them under a "Triggers attack chains" section.
    #: Each chain rule should declare this; ``match()`` callbacks
    #: typically hard-code the same list when constructing ``Chain``
    #: instances.
    triggering_check_ids: tuple[str, ...] = ()


@dataclass(slots=True)
class Chain:
    """An attack-chain instance, a concrete correlation of findings.

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
    #: True when a chain rule intersected the triggering findings'
    #: ``Finding.job_anchors`` and confirmed an executable connection
    #: (e.g. the same job both interpolates untrusted input and
    #: performs an ungated deploy). False is the default: the chain
    #: still fired (typically on resource co-occurrence) but no
    #: dataflow link between the legs has been confirmed. Reporters
    #: render reachable chains with a distinct badge and CI consumers
    #: can filter on this via ``--chains-require-reachability``.
    confirmed_reachable: bool = False
    #: Short human-readable rationale for ``confirmed_reachable``,
    #: e.g. ``"injection and deploy share job 'release'"``. Empty
    #: string when no per-instance evidence applies. Reporters surface
    #: this alongside the badge so a reader sees *why* the chain is
    #: reachable, not just that it is.
    reachability_note: str = ""
    #: True when ``confirmed_reachable`` was established by a real
    #: source-to-sink taint path (phase-2 dataflow reachability), as
    #: opposed to the weaker phase-1 shared-job co-location signal. A
    #: chain can be ``confirmed_reachable`` (co-located) without being
    #: ``via_dataflow`` (a proven executable path). CI consumers can
    #: gate on the stronger tier with ``--chains-require-dataflow``.
    via_dataflow: bool = False
    #: For cross-repo (CXPC) chains, the repo coordinates the chain
    #: spans, in ``[source, target]`` order (the producer repo that
    #: carries the risk, then the consumer / partner repo that inherits
    #: it). Empty for single-repo chains, whose footprint is
    #: ``resources`` (file paths within one repo). The fleet posture
    #: graph reads this to draw repo-to-repo edges; ``resources`` alone
    #: can't, since it holds file paths, not repo coordinates.
    repos: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
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
            "confirmed_reachable": self.confirmed_reachable,
        }
        if self.via_dataflow:
            out["via_dataflow"] = True
        if self.reachability_note:
            out["reachability_note"] = self.reachability_note
        if self.repos:
            out["repos"] = list(self.repos)
        return out


# ── Helpers shared by chain rules ────────────────────────────────────


def failing(findings: list[Finding], *check_ids: str) -> list[Finding]:
    """Return failing findings whose check_id is in *check_ids*."""
    wanted = set(check_ids)
    return [f for f in findings if (not f.passed) and f.check_id in wanted]


def failing_prefix(
    findings: list[Finding], *prefixes: str,
) -> list[Finding]:
    """Return failing findings whose check_id starts with any of
    *prefixes* (case-sensitive).

    Built for cross-tool chains that fire on *any* finding from a
    given source — e.g., a chain that wants "any Trivy CVE
    finding" pairs ``failing_prefix(findings, "INGEST-trivy-CVE-")``
    with a native check. Native rules use exact-match
    :func:`failing`; the prefix variant is reserved for ingested
    findings where the per-rule cardinality can be high (one
    SARIF feed can carry hundreds of distinct CVE IDs)."""
    return [
        f for f in findings
        if (not f.passed)
        and any(f.check_id.startswith(p) for p in prefixes)
    ]


def has_failing(findings: list[Finding], check_id: str) -> bool:
    """Return True if any failing finding matches *check_id*."""
    return any((not f.passed) and f.check_id == check_id for f in findings)


def group_by_resource(
    findings: list[Finding], required: list[str],
) -> dict[str, dict[str, Finding]]:
    """Group failing findings by resource, keep only resources where
    *every* check_id in *required* fired.

    Returned shape: ``{resource: {check_id: Finding}}``. Useful when a
    chain must fire on a *single* workflow file or AWS resource, e.g.
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
        # resource (rare, usually one per resource), keep the first;
        # the chain only needs evidence that the check fired at all.
        if f.check_id not in by_res[f.resource]:
            by_res[f.resource][f.check_id] = f
    return {
        r: ckmap for r, ckmap in by_res.items()
        if all(c in ckmap for c in required)
    }


def group_by_anchor(
    findings: list[Finding], required: list[str], kind: str,
) -> dict[str, dict[str, Finding]]:
    """Cross-provider counterpart to :func:`group_by_resource`.

    Walks failing findings, groups by the ``ResourceAnchor.identity``
    of every anchor with the matching *kind* the finding carries,
    and keeps groups where every check_id in *required* fired.

    Returned shape: ``{anchor_identity: {check_id: Finding}}``.

    Where ``group_by_resource`` answers "did both legs fire on the
    same file?", this answers "did both legs reference the same
    external resource (role / repo / SA / image / function)?". A
    GitHub workflow whose ``role-to-assume`` ARN matches the role
    IAM-002 flagged as wildcard would group here under the role's
    ARN as the key.

    A single finding can carry multiple anchors (a workflow that
    pushes to three ECR repos emits three ``ecr_repo`` anchors); we
    record the finding under every identity it names, so any
    matching repo composes the chain. Findings whose anchor set
    doesn't include *kind* are ignored — chain rules using this
    helper opt in to one taxonomy per chain rather than mixing
    kinds.

    The first finding per ``(identity, check_id)`` wins for the
    description rendering; the chain only needs evidence the leg
    fired, not every hit on the same resource.
    """
    by_id: dict[str, dict[str, Finding]] = defaultdict(dict)
    needed = set(required)
    for f in findings:
        if f.passed or f.check_id not in needed:
            continue
        for anchor in f.resource_anchors:
            if anchor.kind != kind:
                continue
            slot = by_id[anchor.identity]
            if f.check_id not in slot:
                slot[f.check_id] = f
    return {
        identity: ckmap for identity, ckmap in by_id.items()
        if all(c in ckmap for c in required)
    }


def group_cross_repo(
    findings_by_repo: dict[str, list[Finding]],
    check_ids: list[str],
) -> list[tuple[str, Finding]]:
    """Return ``(repo_coord, finding)`` pairs for failing findings matching *check_ids*."""
    wanted = set(check_ids)
    out: list[tuple[str, Finding]] = []
    for repo, findings in findings_by_repo.items():
        for f in findings:
            if (not f.passed) and f.check_id in wanted:
                out.append((repo, f))
    return out


def min_confidence(findings: list[Finding]) -> Confidence:
    """Return the lowest confidence among *findings* (LOW > MEDIUM > HIGH).

    A chain is only as trustworthy as its weakest leg, if one leg is
    a heuristic blob match, the chain shouldn't claim HIGH confidence.
    """
    if not findings:
        return Confidence.HIGH
    return min(
        (f.confidence for f in findings),
        key=lambda c: confidence_rank(c),
    )
