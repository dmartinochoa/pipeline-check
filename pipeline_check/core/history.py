"""Findings-history dashboard renderer.

Reads a directory of timestamped scan-output JSON files and produces
a single self-contained HTML page that visualizes posture over time:

* Per-severity finding counts as inline SVG line charts (one line per
  severity, CRITICAL / HIGH / MEDIUM / LOW).
* Score-over-time trace (0-100).
* Top-N firing rules table (which rules accumulate the most failed
  findings across the history window).

No JavaScript, no CDN, no runtime web server. The output is a single
static ``.html`` file the user can open locally, email, or commit
into a posture-history branch. A live-reload FastAPI variant is a
phase-2 follow-up.

Input shape
-----------
Each ``*.json`` under the input directory is the JSON written by
``pipeline_check ... --output json``, i.e. the payload
:func:`pipeline_check.core.reporter.report_json` produces:

::

    {
        "schema_version": ...,
        "tool_version": "...",
        "score": {"grade": "A", "score": 95,
                  "summary": {"CRITICAL": {"passed": ..., "failed": ...},
                              ...}},
        "findings": [{"check_id": "...", "passed": bool, ...}, ...]
    }

Timestamp extraction order
--------------------------
1. ``YYYYMMDD-HHMMSS`` substring anywhere in the filename
   (matches the convention ``scan-20260519-120000.json``).
2. ``YYYY-MM-DD`` or ``YYYY-MM-DDTHH-MM-SS`` substring (the
   ISO-style alternative).
3. File modification time.

Files without a recoverable timestamp via (1)/(2) fall back to
mtime; files whose JSON can't be parsed are skipped with a warning
returned alongside the snapshot list, so the dashboard renders the
clean history and the caller can surface skips.
"""
from __future__ import annotations

import datetime as _dt
import html
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_TS_COMPACT_RE = re.compile(r"(\d{8})[-_]?(\d{6})")
_TS_ISO_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})(?:[T_-](\d{2})-?(\d{2})-?(\d{2}))?"
)

_SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#b91c1c",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#65a30d",
}

#: Default top-N rule cardinality on the burn-down table.
_TOP_RULES_DEFAULT: int = 15


@dataclass(frozen=True, slots=True)
class HistorySnapshot:
    """One historical scan in the dashboard's view."""

    path: str
    timestamp: _dt.datetime
    score: int
    grade: str
    #: Per-severity failed-finding counts. Missing severities default to 0.
    failed_by_severity: dict[str, int] = field(default_factory=dict)
    #: Total failed findings across all severities.
    total_failed: int = 0
    #: ``Counter`` of failed-finding ``check_id`` occurrences in this
    #: snapshot. Used to compute the top-N rules burn-down.
    rule_counts: Counter[str] = field(default_factory=Counter)


@dataclass(frozen=True, slots=True)
class HistoryReport:
    """The complete dataset the renderer consumes."""

    snapshots: tuple[HistorySnapshot, ...]
    warnings: tuple[str, ...] = ()


def _file_mtime(path: Path) -> _dt.datetime:
    """Return a file's mtime as a naive datetime.

    Split out so tests can monkeypatch the stat without tripping
    pathlib's ``is_file()`` upstream — patching ``Path.stat``
    directly would short-circuit the loader's earlier ``is_file()``
    filter on every platform whose pathlib re-raises non-ENOENT
    OSError out of ``is_file()`` (Linux 3.12+).
    """
    return _dt.datetime.fromtimestamp(path.stat().st_mtime)


def _parse_timestamp_from_name(name: str) -> _dt.datetime | None:
    """Return a parsed timestamp extracted from a filename, or None."""
    m = _TS_COMPACT_RE.search(name)
    if m is not None:
        d, t = m.group(1), m.group(2)
        try:
            return _dt.datetime.strptime(d + t, "%Y%m%d%H%M%S")
        except ValueError:
            pass
    m = _TS_ISO_RE.search(name)
    if m is not None:
        y, mo, da = m.group(1), m.group(2), m.group(3)
        h, mi, s = (m.group(4) or "00"), (m.group(5) or "00"), (m.group(6) or "00")
        try:
            return _dt.datetime(
                int(y), int(mo), int(da), int(h), int(mi), int(s),
            )
        except ValueError:
            pass
    return None


def _snapshot_from_json(
    path: Path, doc: dict[str, Any], ts: _dt.datetime,
) -> HistorySnapshot:
    """Project a parsed scan-output JSON onto a :class:`HistorySnapshot`.

    Defensive about missing fields: a JSON file lacking ``score`` or
    ``findings`` produces a snapshot with zeros rather than raising,
    so a partially-written file doesn't break the dashboard render.
    """
    score_block = doc.get("score") or {}
    score = score_block.get("score") if isinstance(score_block, dict) else None
    grade = score_block.get("grade") if isinstance(score_block, dict) else None
    summary = score_block.get("summary") if isinstance(score_block, dict) else None
    failed: dict[str, int] = dict.fromkeys(_SEVERITIES, 0)
    if isinstance(summary, dict):
        for sev in _SEVERITIES:
            entry = summary.get(sev)
            if isinstance(entry, dict):
                f = entry.get("failed")
                if isinstance(f, int):
                    failed[sev] = f
    rule_counts: Counter[str] = Counter()
    findings = doc.get("findings")
    if isinstance(findings, list):
        for f in findings:
            if not isinstance(f, dict):
                continue
            if f.get("passed") is True:
                continue
            check_id = f.get("check_id")
            if isinstance(check_id, str) and check_id:
                rule_counts[check_id] += 1
    total = sum(failed.values())
    return HistorySnapshot(
        path=str(path),
        timestamp=ts,
        score=score if isinstance(score, int) else 0,
        grade=grade if isinstance(grade, str) else "?",
        failed_by_severity=failed,
        total_failed=total,
        rule_counts=rule_counts,
    )


def load_history(directory: Path | str) -> HistoryReport:
    """Walk *directory* and return a :class:`HistoryReport`.

    Every ``*.json`` is considered; non-scan JSON (missing the
    expected top-level keys) still produces a snapshot — the
    defensive zeros mean nothing renders catastrophically — but a
    file that's outright malformed JSON, unreadable, or non-dict at
    the top level surfaces as a warning and is dropped.
    """
    root = Path(directory)
    if not root.exists():
        raise ValueError(
            f"history directory {root} does not exist. Pass the "
            "``--dir`` pointing at a directory of scan-output JSON "
            "files (e.g. ``.pipeline-check-history/``)."
        )
    if not root.is_dir():
        raise ValueError(
            f"history path {root} is not a directory; pass a "
            "directory containing scan-output JSON files."
        )
    snapshots: list[HistorySnapshot] = []
    warnings: list[str] = []
    for f in sorted(root.glob("*.json")):
        # ``is_file()`` and ``read_text()`` both touch the
        # filesystem; either can raise OSError mid-iteration on a
        # rotation / deletion (Linux pathlib re-raises non-ENOENT
        # OSError out of is_file()). Wrap both together so a mid-
        # scan churn surfaces as a per-file warning rather than
        # aborting the whole load.
        try:
            if not f.is_file():
                continue
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            warnings.append(f"{f.name}: read error: {exc}")
            continue
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            warnings.append(
                f"{f.name}: JSON decode error: "
                f"{str(exc).split(chr(10), 1)[0]}"
            )
            continue
        if not isinstance(doc, dict):
            warnings.append(f"{f.name}: top-level JSON is not an object")
            continue
        ts = _parse_timestamp_from_name(f.name)
        if ts is None:
            # File rotated / deleted between read and stat: log a
            # warning and skip rather than abort the whole load.
            # The directory is user-managed, mid-scan churn is
            # plausible (CI writes a fresh scan while the dashboard
            # is being rendered).
            try:
                ts = _file_mtime(f)
            except OSError as exc:
                warnings.append(
                    f"{f.name}: stat error during mtime fallback: {exc}"
                )
                continue
        snapshots.append(_snapshot_from_json(f, doc, ts))
    snapshots.sort(key=lambda s: s.timestamp)
    return HistoryReport(
        snapshots=tuple(snapshots), warnings=tuple(warnings),
    )


# ── HTML rendering ──────────────────────────────────────────────────


_HTML_HEAD = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>pipeline-check history</title>
  <style>
    :root {
      --bg: #0f172a;
      --panel: #1e293b;
      --border: #334155;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 24px;
      font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    h1 { margin: 0 0 4px; font-size: 22px; }
    h2 { margin: 24px 0 12px; font-size: 16px; color: var(--accent); }
    .sub { color: var(--muted); font-size: 13px; }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      margin: 12px 0;
    }
    svg { display: block; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      text-align: left;
      padding: 6px 8px;
      border-bottom: 1px solid var(--border);
    }
    th { color: var(--muted); font-weight: 500; }
    .legend {
      display: flex; gap: 16px; font-size: 12px;
      color: var(--muted); margin-top: 8px;
    }
    .swatch {
      display: inline-block; width: 10px; height: 10px;
      border-radius: 2px; margin-right: 4px; vertical-align: middle;
    }
    .empty { color: var(--muted); padding: 24px; text-align: center; }
    .warn {
      background: #422006; border: 1px solid #ca8a04; color: #fde68a;
      padding: 8px 12px; border-radius: 6px; font-size: 12px;
      margin: 12px 0;
    }
  </style>
</head>
<body>
"""

_HTML_FOOT = """\
</body>
</html>
"""


def _svg_line_chart(
    snapshots: tuple[HistorySnapshot, ...],
    *,
    series: dict[str, list[int]],
    colors: dict[str, str],
    width: int = 720,
    height: int = 220,
    pad: int = 36,
) -> str:
    """Render a tiny multi-series line chart as inline SVG.

    Each *series* value is a list of integers aligned with
    *snapshots* (same length, same order). The X axis is the
    snapshot index (chronological); the Y axis spans 0..max across
    all series. Empty data returns an "empty" SVG placeholder so the
    surrounding HTML stays predictable.
    """
    if not snapshots or not any(series.values()):
        return (
            f'<svg viewBox="0 0 {width} {height}" '
            f'width="{width}" height="{height}">'
            f'<text x="{width // 2}" y="{height // 2}" '
            f'text-anchor="middle" fill="#64748b">'
            f'no history yet</text></svg>'
        )
    inner_w = width - 2 * pad
    inner_h = height - 2 * pad
    n = len(snapshots)
    max_val = max(
        (v for series_values in series.values() for v in series_values),
        default=1,
    )
    if max_val <= 0:
        max_val = 1
    # X positions for each snapshot index (avoid div-by-zero when n == 1).
    def x_for(i: int) -> float:
        if n == 1:
            return pad + inner_w / 2
        return pad + (i * inner_w / (n - 1))

    def y_for(v: float) -> float:
        return pad + inner_h - (v / max_val) * inner_h

    parts: list[str] = []
    parts.append(
        f'<svg viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" '
        f'xmlns="http://www.w3.org/2000/svg">'
    )
    # Background grid (3 horizontal lines).
    for frac in (0.25, 0.5, 0.75):
        y = pad + inner_h * (1 - frac)
        parts.append(
            f'<line x1="{pad}" y1="{y:.1f}" x2="{pad + inner_w}" '
            f'y2="{y:.1f}" stroke="#334155" stroke-dasharray="2 4" />'
        )
    # Axis labels: min (0) at bottom, max at top.
    parts.append(
        f'<text x="{pad - 6}" y="{pad + inner_h + 4}" text-anchor="end" '
        f'fill="#94a3b8" font-size="10">0</text>'
    )
    parts.append(
        f'<text x="{pad - 6}" y="{pad + 4}" text-anchor="end" '
        f'fill="#94a3b8" font-size="10">{max_val}</text>'
    )
    # Series lines.
    for name, values in series.items():
        color = colors.get(name, "#38bdf8")
        if not values:
            continue
        points = " ".join(
            f"{x_for(i):.1f},{y_for(v):.1f}"
            for i, v in enumerate(values)
        )
        parts.append(
            f'<polyline fill="none" stroke="{color}" '
            f'stroke-width="2" stroke-linejoin="round" '
            f'stroke-linecap="round" points="{points}" />'
        )
        # Dot markers for each point.
        for i, v in enumerate(values):
            parts.append(
                f'<circle cx="{x_for(i):.1f}" cy="{y_for(v):.1f}" '
                f'r="3" fill="{color}" />'
            )
    parts.append("</svg>")
    return "".join(parts)


def _format_time_range(snapshots: tuple[HistorySnapshot, ...]) -> str:
    if not snapshots:
        return ""
    first = snapshots[0].timestamp.isoformat(timespec="minutes")
    last = snapshots[-1].timestamp.isoformat(timespec="minutes")
    if first == last:
        return first
    return f"{first} → {last}"


def render_html(report: HistoryReport, *, top_n: int = _TOP_RULES_DEFAULT) -> str:
    """Render a :class:`HistoryReport` to a self-contained HTML page.

    The output is one ``.html`` file with embedded CSS and inline
    SVG charts. No JavaScript, no CDN. Open it locally, email it,
    or commit it to a posture-history branch.
    """
    snapshots = report.snapshots
    parts: list[str] = [_HTML_HEAD]
    parts.append('<h1>pipeline-check history</h1>')
    parts.append(
        '<div class="sub">'
        f'{len(snapshots)} snapshot(s) &middot; '
        f'{html.escape(_format_time_range(snapshots))}'
        '</div>'
    )
    if report.warnings:
        parts.append('<div class="warn">')
        parts.append('Skipped files:<ul style="margin:4px 0 0 18px;padding:0">')
        for w in report.warnings:
            parts.append(f'<li>{html.escape(w)}</li>')
        parts.append('</ul></div>')

    if not snapshots:
        parts.append(
            '<div class="panel empty">'
            'No scan-output JSON files found. Point '
            '<code>pipeline_check history --dir</code> at a directory '
            'of past scans (e.g. produced by '
            '<code>pipeline_check ... --output json --output-file '
            'scan-20260519-120000.json</code>).'
            '</div>'
        )
        parts.append(_HTML_FOOT)
        return "".join(parts)

    # Per-severity failure trend.
    sev_series: dict[str, list[int]] = {
        sev: [s.failed_by_severity.get(sev, 0) for s in snapshots]
        for sev in _SEVERITIES
    }
    parts.append('<h2>Failed findings by severity</h2>')
    parts.append('<div class="panel">')
    parts.append(_svg_line_chart(
        snapshots, series=sev_series, colors=_SEVERITY_COLORS,
    ))
    parts.append('<div class="legend">')
    for sev in _SEVERITIES:
        parts.append(
            f'<span><span class="swatch" '
            f'style="background:{_SEVERITY_COLORS[sev]}"></span>'
            f'{sev.lower()}</span>'
        )
    parts.append('</div></div>')

    # Score trend.
    parts.append('<h2>Score over time</h2>')
    parts.append('<div class="panel">')
    parts.append(_svg_line_chart(
        snapshots,
        series={"score": [s.score for s in snapshots]},
        colors={"score": "#38bdf8"},
    ))
    parts.append(
        '<div class="legend">'
        '<span><span class="swatch" style="background:#38bdf8"></span>'
        'score (0–100)</span></div></div>'
    )

    # Top-N firing rules across the window.
    combined: Counter[str] = Counter()
    for s in snapshots:
        combined.update(s.rule_counts)
    parts.append(f'<h2>Top {top_n} firing rules (across window)</h2>')
    parts.append('<div class="panel">')
    if not combined:
        parts.append('<div class="empty">No failed findings in the window.</div>')
    else:
        parts.append('<table>')
        parts.append(
            '<thead><tr>'
            '<th>check_id</th>'
            '<th style="text-align:right">total failed</th>'
            '<th style="text-align:right">snapshots present</th>'
            '</tr></thead><tbody>'
        )
        for check_id, count in combined.most_common(top_n):
            present = sum(
                1 for s in snapshots if s.rule_counts.get(check_id, 0) > 0
            )
            parts.append(
                f'<tr><td>{html.escape(check_id)}</td>'
                f'<td style="text-align:right">{count}</td>'
                f'<td style="text-align:right">{present}/{len(snapshots)}</td>'
                f'</tr>'
            )
        parts.append('</tbody></table>')
    parts.append('</div>')

    # Per-snapshot table for the raw audit trail.
    parts.append('<h2>Snapshots</h2>')
    parts.append('<div class="panel"><table>')
    parts.append(
        '<thead><tr>'
        '<th>timestamp</th>'
        '<th>file</th>'
        '<th style="text-align:right">grade</th>'
        '<th style="text-align:right">score</th>'
        '<th style="text-align:right">failed</th>'
        '</tr></thead><tbody>'
    )
    for s in snapshots:
        ts = s.timestamp.isoformat(timespec="seconds")
        filename = Path(s.path).name
        parts.append(
            f'<tr><td>{html.escape(ts)}</td>'
            f'<td>{html.escape(filename)}</td>'
            f'<td style="text-align:right">{html.escape(s.grade)}</td>'
            f'<td style="text-align:right">{s.score}</td>'
            f'<td style="text-align:right">{s.total_failed}</td>'
            f'</tr>'
        )
    parts.append('</tbody></table></div>')

    parts.append(_HTML_FOOT)
    return "".join(parts)


__all__ = [
    "HistoryReport",
    "HistorySnapshot",
    "load_history",
    "render_html",
]
