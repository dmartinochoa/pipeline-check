"""Markdown rendering for :class:`pipeline_check.core.pr_diff.DeltaReport`.

The output is shaped for a single PR-review comment body on GitHub or
GitLab: Markdown-only (no ANSI), no inline HTML except the
``<details>`` collapse for the preserved-findings tail (universally
rendered by both platforms), and no link references that would force
the reader to bounce off-page to interpret a finding.

The headline always quantifies the delta (``+3 / -1 / =7``) so a
reader skimming a noisy PR thread sees the shape of the change before
reading any prose.
"""
from __future__ import annotations

from collections import defaultdict

from .pr_diff import DeltaReport, FindingRef

_SEVERITY_BADGE: dict[str, str] = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🔵 LOW",
    "INFO": "⚪ INFO",
}

# Sort order for severity sections in the output. Higher severity
# renders first; an unknown severity is bucketed at the end.
_SECTION_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _badge(severity: str) -> str:
    return _SEVERITY_BADGE.get(severity.upper(), severity.upper())


def _location(f: FindingRef) -> str:
    """Render the ``resource[:line]`` suffix for one finding.

    Resources without a usable line number (AWS ARNs, SCM resources)
    just render the resource. Backticks are escaped only if they
    appear inside the resource string itself; the surrounding pair
    is consumed literally by GitHub's parser.
    """
    if f.location_line is not None and f.location_line > 0:
        return f"`{f.resource}:{f.location_line}`"
    return f"`{f.resource}`"


def _group_by_severity(refs: list[FindingRef]) -> dict[str, list[FindingRef]]:
    buckets: dict[str, list[FindingRef]] = defaultdict(list)
    for f in refs:
        buckets[f.severity.upper()].append(f)
    return buckets


def _render_introduced_section(introduced: list[FindingRef]) -> list[str]:
    """Build the ``### New findings`` body, grouped by severity.

    Each finding renders as a two-line block: the title row carries
    badge + check_id + title + location; the indented row carries the
    recommendation. The recommendation is the single most useful field
    for a PR reviewer ("what should the contributor change?") so it
    earns its own row rather than getting buried in collapsed prose.
    """
    if not introduced:
        return []
    out: list[str] = ["### New findings", ""]
    grouped = _group_by_severity(introduced)
    for sev in _SECTION_ORDER:
        items = grouped.get(sev) or []
        if not items:
            continue
        out.append(f"#### {_badge(sev)}  ({len(items)})")
        out.append("")
        for f in items:
            title = f.title or (f.description.splitlines()[0] if f.description else "")
            out.append(f"- **{f.check_id}** {title}")
            out.append(f"  - Location: {_location(f)}")
            if f.recommendation:
                out.append(f"  - Fix: {f.recommendation}")
        out.append("")
    # Catch-all bucket for any severity the canonical order didn't list
    # (custom rules can legally introduce a new severity name).
    other_keys = [k for k in grouped if k not in _SECTION_ORDER]
    for sev in sorted(other_keys):
        items = grouped[sev]
        out.append(f"#### {sev}  ({len(items)})")
        out.append("")
        for f in items:
            title = f.title or ""
            out.append(f"- **{f.check_id}** {title}")
            out.append(f"  - Location: {_location(f)}")
            if f.recommendation:
                out.append(f"  - Fix: {f.recommendation}")
        out.append("")
    return out


def _render_resolved_section(resolved: list[FindingRef]) -> list[str]:
    """Build the ``### Resolved`` block.

    Resolved findings get a flat, single-line treatment per row, no
    severity grouping: they're not actionable by the reviewer, and
    they're an unambiguously good thing. Compact rendering keeps the
    PR comment focused on what the contributor needs to *do*.
    """
    if not resolved:
        return []
    out: list[str] = [
        f"### Resolved ({len(resolved)})", "",
        "Findings present in base but gone in HEAD:", "",
    ]
    for f in resolved:
        title = f.title or ""
        out.append(f"- **{f.check_id}** {title} {_badge(f.severity)} {_location(f)}")
    out.append("")
    return out


def _render_preserved_section(preserved: list[FindingRef]) -> list[str]:
    """Build the collapsible ``Preserved findings`` block.

    Wrapped in ``<details>`` because the preserved set is, by
    definition, *not* the reviewer's problem on this PR. Hiding it
    keeps the visible comment body short on long-running branches
    that accumulate many preserved findings, while still allowing
    expansion when someone wants the full picture.
    """
    if not preserved:
        return []
    out: list[str] = [
        f"<details><summary>Preserved findings ({len(preserved)}) "
        f"— present in both base and HEAD</summary>",
        "",
    ]
    grouped = _group_by_severity(preserved)
    for sev in _SECTION_ORDER:
        items = grouped.get(sev) or []
        if not items:
            continue
        out.append(f"**{_badge(sev)}**")
        out.append("")
        for f in items:
            title = f.title or ""
            out.append(f"- **{f.check_id}** {title} {_location(f)}")
        out.append("")
    other_keys = sorted(k for k in grouped if k not in _SECTION_ORDER)
    for sev in other_keys:
        items = grouped[sev]
        out.append(f"**{sev}**")
        out.append("")
        for f in items:
            title = f.title or ""
            out.append(f"- **{f.check_id}** {title} {_location(f)}")
        out.append("")
    out.append("</details>")
    out.append("")
    return out


def _render_warnings(delta: DeltaReport) -> list[str]:
    if not delta.warnings:
        return []
    out: list[str] = ["> [!WARNING]", "> Diff produced with degraded base data:", ">"]
    for w in delta.warnings:
        out.append(f"> - {w}")
    out.append("")
    return out


def _footer(delta: DeltaReport, tool_version: str) -> list[str]:
    base_label = delta.base_ref
    if delta.base_commit:
        base_label = f"{delta.base_ref} ({delta.base_commit})"
    head_label = delta.head_commit or "HEAD"
    return [
        "---",
        (
            f"_Pipeline-Check {tool_version or ''} - Scanned base "
            f"`{base_label}` vs HEAD ({head_label}). The fingerprint "
            f"is `(check_id, resource)`; line shifts on unchanged "
            f"findings do not produce false 'introduced' rows._"
        ).strip(),
    ]


def report_pr_diff(delta: DeltaReport, *, tool_version: str = "") -> str:
    """Render the delta as a single Markdown string.

    The string is safe to drop straight into a GitHub PR comment, a
    GitLab merge-request note, or a markdown file. No trailing
    newline is added, callers append one when piping to a file or
    redirecting to stdout if their downstream expects POSIX
    behavior.
    """
    intro = len(delta.introduced)
    resolved = len(delta.resolved)
    preserved = len(delta.preserved)
    if intro == 0 and resolved == 0:
        verdict_line = (
            f"This PR does not change the failing-finding set "
            f"(preserved: {preserved})."
        )
    elif intro == 0:
        verdict_line = (
            f"This PR resolves {resolved} finding(s) and introduces none."
        )
    else:
        verdict_line = (
            f"This PR introduces **{intro} new finding(s)**, resolves "
            f"{resolved}, and preserves {preserved}."
        )

    lines: list[str] = [
        f"## Pipeline-Check diff vs `{delta.base_ref}`",
        "",
        verdict_line,
        "",
        f"`+{intro}` introduced · `-{resolved}` resolved · `={preserved}` preserved",
        "",
    ]
    lines.extend(_render_warnings(delta))
    lines.extend(_render_introduced_section(delta.introduced))
    lines.extend(_render_resolved_section(delta.resolved))
    lines.extend(_render_preserved_section(delta.preserved))
    lines.extend(_footer(delta, tool_version=tool_version))
    return "\n".join(lines)
