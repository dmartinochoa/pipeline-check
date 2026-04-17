"""GitHub-Flavored Markdown reporter.

Built for two consumers:

1. **GitHub Actions step summary** — writing to ``$GITHUB_STEP_SUMMARY``
   surfaces the report directly on the workflow run page. Supports
   tables, ``<details>``, and inline HTML. GFM is the spec.
2. **PR / MR comment bots** — a compact, ranked table posts cleanly as
   a single comment from any bot that speaks the GitHub or GitLab API.

Shape:

- H1 header + a single-line summary row (grade / score / counts).
- Failures section with a sortable table: severity, ID, title, resource.
- Passes section collapsed inside ``<details>`` so the comment stays
  short but full data is one click away.

Design calls:

- Severity is rendered as a badge-style emoji prefix (🔴 CRITICAL /
  🟠 HIGH / 🟡 MEDIUM / 🔵 LOW) — helps skimming and works in
  terminal Markdown viewers too.
- Pipe characters (``|``) inside table cells are escaped as ``\\|`` so
  a check title containing a pipe can't break the row.
- Controls are rendered as an inline list of standard:control_id pairs,
  not grouped by standard — keeps each row compact for PR comments.
"""
from __future__ import annotations

from .checks.base import Finding, Severity, severity_rank

_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}

_GRADE_EMOJI: dict[str, str] = {
    "A": "🟢",
    "B": "🟢",
    "C": "🟡",
    "D": "🔴",
}


def _esc(s: str) -> str:
    """Escape characters that would corrupt a Markdown table row."""
    if not s:
        return ""
    # Backslash-escape pipes; collapse newlines to a single space so
    # the row doesn't wrap across table cells.
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", "")


def _row(f: Finding) -> str:
    sev = f"{_SEVERITY_EMOJI.get(f.severity, '')} {f.severity.value}".strip()
    title = _esc(f.title)[:120]
    resource = _esc(f.resource or "")[:80]
    controls = ""
    if f.controls:
        tags = [f"`{c.standard}:{c.control_id}`" for c in f.controls[:6]]
        controls = " ".join(tags)
        if len(f.controls) > 6:
            controls += f" +{len(f.controls) - 6}"
    return f"| {sev} | `{f.check_id}` | {title} | {resource} | {controls} |"


def report_markdown(findings: list[Finding], score_result: dict) -> str:
    """Render *findings* as a GitHub-Flavored Markdown report string."""
    grade = score_result.get("grade", "?")
    total_score = score_result.get("total", 0)
    max_score = score_result.get("max", score_result.get("total_possible", 0))
    failed = score_result.get("failed", sum(1 for f in findings if not f.passed))
    passed = score_result.get("passed", sum(1 for f in findings if f.passed))

    grade_emoji = _GRADE_EMOJI.get(grade, "")
    # Sort: failures first, then by severity rank desc, then by check_id.
    sorted_findings = sorted(
        findings,
        key=lambda f: (f.passed, -severity_rank(f.severity), f.check_id),
    )
    fails = [f for f in sorted_findings if not f.passed]
    passes = [f for f in sorted_findings if f.passed]

    score_suffix = f"/{max_score}" if max_score else ""
    lines: list[str] = [
        "# Pipeline Security Report",
        "",
        f"**Grade:** {grade_emoji} {grade} &nbsp;·&nbsp; "
        f"**Score:** {total_score}{score_suffix} &nbsp;·&nbsp; "
        f"**Failed:** {failed} &nbsp;·&nbsp; "
        f"**Passed:** {passed}",
        "",
    ]

    if fails:
        lines.append(f"## Failures ({len(fails)})")
        lines.append("")
        lines.append("| Severity | Check | Title | Resource | Controls |")
        lines.append("|---|---|---|---|---|")
        for f in fails:
            lines.append(_row(f))
        lines.append("")
    else:
        lines.append("## No failures")
        lines.append("")
        lines.append("All checks passed. 🎉")
        lines.append("")

    if passes:
        lines.append(f"<details><summary>Passing checks ({len(passes)})</summary>")
        lines.append("")
        lines.append("| Severity | Check | Title | Resource | Controls |")
        lines.append("|---|---|---|---|---|")
        for f in passes:
            lines.append(_row(f))
        lines.append("")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines)
