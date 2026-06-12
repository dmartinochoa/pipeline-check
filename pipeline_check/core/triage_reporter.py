"""Advisory rendering of local-LLM triage verdicts.

Kept as its own reporter (issue #167): triage labels are shown in a
dedicated section and never folded into a finding's severity or
confidence, so the rule-engine signal and the model's advisory signal
stay visually distinct. Plain text, deterministic, so it's stable across
runs and easy to test.
"""
from __future__ import annotations

from .checks.base import Finding
from .triage import TriageLabel, TriageVerdict

#: Render order (worst-actionable first) and the display text per label.
_LABEL_ORDER = (
    TriageLabel.CONFIRMED,
    TriageLabel.NEEDS_REVIEW,
    TriageLabel.LIKELY_FP,
    TriageLabel.UNAVAILABLE,
)
_LABEL_TEXT = {
    TriageLabel.CONFIRMED: "confirmed",
    TriageLabel.NEEDS_REVIEW: "needs_review",
    TriageLabel.LIKELY_FP: "likely_fp",
    TriageLabel.UNAVAILABLE: "unavailable",
}


def _loc(finding: Finding) -> str:
    for loc in finding.locations:
        if loc.path:
            line = f":{loc.start_line}" if loc.start_line else ""
            return f"{loc.path}{line}"
    return finding.resource


def report_triage(
    results: list[tuple[Finding, TriageVerdict]],
    *,
    endpoint: str,
    model: str,
) -> str:
    """Render *results* (finding, verdict pairs) as an advisory section."""
    if not results:
        return ""
    rank = {lbl: i for i, lbl in enumerate(_LABEL_ORDER)}
    counts: dict[TriageLabel, int] = {lbl: 0 for lbl in _LABEL_ORDER}
    for _, verdict in results:
        counts[verdict.label] = counts.get(verdict.label, 0) + 1

    width = max(len(text) for text in _LABEL_TEXT.values())
    ordered = sorted(
        results,
        key=lambda r: (rank.get(r[1].label, 99), r[0].check_id),
    )
    lines = [
        "LLM triage (advisory -- does not affect grade or gate)",
        f"  endpoint: {endpoint} - model: {model}",
        "",
    ]
    for finding, verdict in ordered:
        label = _LABEL_TEXT.get(verdict.label, verdict.label.value).ljust(width)
        rationale = f"  -- {verdict.rationale}" if verdict.rationale else ""
        lines.append(f"  {label}  {finding.check_id}  {_loc(finding)}{rationale}")
    summary = " - ".join(
        f"{counts[lbl]} {_LABEL_TEXT[lbl]}"
        for lbl in _LABEL_ORDER
        if counts.get(lbl)
    )
    lines.extend(["", f"  {summary}"])
    return "\n".join(lines) + "\n"
