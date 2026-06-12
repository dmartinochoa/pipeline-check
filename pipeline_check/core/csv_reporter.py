"""CSV findings export for spreadsheet triage.

A flat, one-row-per-location dump of the failing findings, meant to be
opened in a spreadsheet: filter by severity, sort by resource, assign
owners, track remediation. Only failing findings are emitted (passing
findings aren't actionable), mirroring the SARIF / Code Quality
reporters. The stdlib ``csv`` writer handles quoting / escaping, so a
comma, quote, or newline inside a description or recommendation can't
break the column layout. A cell whose value begins with a spreadsheet
formula trigger (``= + - @`` or a tab / carriage return) is prefixed with
a single quote so Excel / Sheets / LibreOffice treat it as text rather
than evaluating it (CSV formula injection): finding fields can carry
attacker-influenced scanned content, and this is a triage artifact a
human opens in a spreadsheet.
"""
from __future__ import annotations

import csv
import io

from .checks.base import Finding, inline_exploit
from .report_view import ReportView

#: Leading characters a spreadsheet interprets as the start of a formula.
_FORMULA_LEADERS = frozenset("=+-@\t\r")


def _csv_safe(value: object) -> str:
    """Neutralize CSV formula injection by prefixing a dangerous leader."""
    s = "" if value is None else str(value)
    if s and s[0] in _FORMULA_LEADERS:
        return "'" + s
    return s

#: Column order. Stable so a downstream sheet / import template can rely
#: on it; new columns should be appended, not inserted.
_COLUMNS = [
    "check_id",
    "severity",
    "confidence",
    "resource",
    "file",
    "line",
    "title",
    "description",
    "recommendation",
    "cwe",
]


def report_csv(findings: list[Finding], inline_explain: bool = False) -> str:
    """Render failing *findings* as a CSV string (one row per location).

    A finding with multiple locations produces one row per location (the
    same shape the SARIF / Code Quality reporters use), so each
    offending file:line is its own triage row. A finding with no resolved
    location falls back to a single row keyed on its ``resource``. With
    *inline_explain*, the finding's ``exploit_example`` is appended to the
    description cell.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(_COLUMNS)
    for f in ReportView(findings).failed:
        desc = (f.description or f.title).strip()
        exploit = inline_exploit(f, inline_explain)
        if exploit:
            desc = f"{desc}\n\nProof of exploit:\n{exploit}"
        confidence = f.confidence.value if f.confidence is not None else ""
        cwe = ";".join(f.cwe) if f.cwe else ""
        locations = list(f.locations) if f.locations else [None]
        for loc in locations:
            writer.writerow([_csv_safe(v) for v in (
                f.check_id,
                f.severity.value,
                confidence,
                f.resource,
                loc.path if loc is not None else "",
                "" if loc is None or loc.start_line is None else loc.start_line,
                f.title,
                desc,
                f.recommendation or "",
                cwe,
            )])
    return buf.getvalue()
