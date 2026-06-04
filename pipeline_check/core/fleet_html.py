"""Fleet posture-graph HTML view.

Renders the cross-repo posture graph (the ``posture_graph`` already
written to ``fleet.json``) as a self-contained HTML file: no external
CDN, no JavaScript, no network. The layout is a static SVG node-link
diagram computed in Python, so the output is deterministic and renders
in any browser (and in print) without a script engine.

Two sections:

  - **Fleet posture** — a ranked grid of repo cards (worst score first),
    each carrying its grade, score, and per-severity failed-finding
    breakdown.
  - **Cross-repo posture graph** — an SVG node-link diagram of the CXPC
    edges (producer -> consumer), nodes colored by grade, edges colored
    by chain severity. Only the repos that participate in an edge are
    drawn here; isolated repos live in the grid above. A chain endpoint
    outside the scanned fleet renders as a dashed, muted node.

The severity / grade / surface palette is the shared
``_design_tokens.css`` (same source the HTML report and the docs site
read), so a palette edit can't desync this view from the rest.
"""
from __future__ import annotations

import html
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .fleet import FleetDigest

# Shared design tokens (severity / grade / surface CSS vars). Read
# defensively: the asset ships in the wheel, but a partial install or a
# test that mocks the package must not crash module import. Missing ->
# empty string; the inline ``<style>`` then omits the cross-surface
# tokens and the per-tier fallbacks below take over.
_DESIGN_TOKENS_PATH = Path(__file__).parent / "_design_tokens.css"
try:
    _DESIGN_TOKENS_CSS = _DESIGN_TOKENS_PATH.read_text(encoding="utf-8")
except OSError:
    _DESIGN_TOKENS_CSS = ""

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Severity / grade names -> the CSS variable that holds their color, so
# the markup references ``var(--sev-high)`` rather than a hardcoded hex
# (single source of truth in _design_tokens.css).
_SEV_VAR = {
    "CRITICAL": "--sev-critical",
    "HIGH": "--sev-high",
    "MEDIUM": "--sev-medium",
    "LOW": "--sev-low",
    "INFO": "--sev-info",
}
_GRADE_VAR = {"A": "--grade-a", "B": "--grade-b", "C": "--grade-c", "D": "--grade-d"}


def _e(text: object) -> str:
    """HTML-escape any value for safe interpolation into markup."""
    return html.escape(str(text), quote=True)


def _grade_fill(grade: str | None) -> str:
    """CSS ``fill`` / ``background`` value for a grade chip."""
    var = _GRADE_VAR.get(grade or "")
    return f"var({var})" if var else "var(--light-muted)"


def _sev_fill(severity: str) -> str:
    return f"var({_SEV_VAR.get(severity, '--sev-info')})"


_CSS = """
__DESIGN_TOKENS__
:root {
  --font-sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --font-mono: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--font-sans);
  background: var(--light-bg); color: var(--light-text);
  font-size: 14px; line-height: 1.5;
}
header {
  background: var(--light-header-bg); color: #fff;
  padding: 20px 28px;
}
header h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.01em; }
header .sub { font-weight: 400; opacity: 0.7; margin-left: 10px; font-size: 14px; }
header .meta { margin-top: 4px; font-size: 12px; opacity: 0.6; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 28px 48px; }
h2 {
  font-size: 15px; text-transform: uppercase; letter-spacing: 0.04em;
  color: var(--light-muted); margin: 32px 0 12px;
}
section:first-of-type h2 { margin-top: 8px; }
.stat-band { display: flex; flex-wrap: wrap; gap: 12px; }
.stat {
  background: var(--light-card); border: 1px solid var(--light-border);
  border-radius: 10px; padding: 14px 18px; min-width: 116px;
}
.stat .n { font-size: 26px; font-weight: 700; line-height: 1; }
.stat .l { font-size: 12px; color: var(--light-muted); margin-top: 6px; }
.sev-chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px; }
.sev-chip {
  display: inline-flex; align-items: center; gap: 6px;
  background: var(--light-card); border: 1px solid var(--light-border);
  border-radius: 999px; padding: 4px 12px; font-size: 13px;
}
.sev-chip .dot { width: 9px; height: 9px; border-radius: 50%; }
.sev-chip .c { font-weight: 700; }
.grid {
  display: grid; gap: 12px; margin-top: 4px;
  grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
}
.card {
  background: var(--light-card); border: 1px solid var(--light-border);
  border-radius: 10px; padding: 14px 16px; display: flex; gap: 14px;
  align-items: flex-start;
}
.card.errored { opacity: 0.75; }
.chip {
  flex: 0 0 auto; width: 42px; height: 42px; border-radius: 9px;
  color: #fff; font-weight: 800; font-size: 20px;
  display: flex; align-items: center; justify-content: center;
}
.card .body { min-width: 0; }
.card .repo {
  font-weight: 600; font-size: 14px; word-break: break-all;
  font-family: var(--font-mono);
}
.card .score { font-size: 12px; color: var(--light-muted); margin: 2px 0 6px; }
.card .mini { display: flex; flex-wrap: wrap; gap: 5px; }
.card .mini span {
  font-size: 11px; font-weight: 700; color: #fff;
  border-radius: 5px; padding: 1px 6px;
}
.card .err { font-size: 12px; color: var(--sev-critical); word-break: break-word; }
.graph-wrap {
  background: var(--light-card); border: 1px solid var(--light-border);
  border-radius: 10px; padding: 8px;
}
.graph-wrap svg { width: 100%; height: auto; display: block; }
svg .node-grade {
  fill: #fff; font-weight: 800; font-size: 15px;
  text-anchor: middle; dominant-baseline: middle;
}
svg .node-label {
  fill: var(--light-text); font-size: 11px; text-anchor: middle;
  font-family: var(--font-mono);
}
svg .edge-label {
  font-size: 10px; text-anchor: middle; font-weight: 700;
  font-family: var(--font-mono); paint-order: stroke;
  stroke: var(--light-card); stroke-width: 3px;
}
.legend { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 10px; font-size: 12px; }
.legend .item { display: inline-flex; align-items: center; gap: 6px; color: var(--light-muted); }
.legend .swatch { width: 12px; height: 12px; border-radius: 3px; }
.note { color: var(--light-muted); font-size: 13px; }
footer {
  max-width: 1100px; margin: 0 auto; padding: 0 28px 32px;
  color: var(--light-muted); font-size: 12px;
}
"""


def render_fleet_html(digest: FleetDigest) -> str:
    """Render a fleet digest's posture graph as a self-contained HTML page.

    Imported lazily from :func:`fleet._write_digest`; takes the live
    :class:`FleetDigest` and returns the HTML string (the caller writes
    it to ``fleet.html``).
    """
    # Imported here (not at module top) to avoid a circular import:
    # ``fleet`` imports this module to write the report.
    from .fleet import build_posture_graph

    graph = build_posture_graph(digest)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    ok = [s for s in digest.snapshots if s.ok]
    errored = [s for s in digest.snapshots if not s.ok]

    style = _CSS.replace("__DESIGN_TOKENS__", _DESIGN_TOKENS_CSS)
    body = (
        _stat_band_html(digest, ok, errored, graph)
        + _graph_section_html(graph)
        + _posture_cards_html(digest)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pipeline-Check Fleet Posture</title>
  <style>{style}</style>
</head>
<body>
<header>
  <h1>Pipeline-Check<span class="sub">Fleet Posture</span></h1>
  <div class="meta">{len(digest.snapshots)} repo(s) scanned &nbsp;·&nbsp; {now}</div>
</header>
<main>
{body}
</main>
<footer>
  Static view of <code>fleet.json</code> &middot; nodes are repos (colored by
  grade), edges are cross-repo (CXPC) attack chains (colored by severity).
  No data leaves this file.
</footer>
</body>
</html>
"""


def _stat_band_html(
    digest: FleetDigest,
    ok: list[Any],
    errored: list[Any],
    graph: dict[str, Any],
) -> str:
    totals: dict[str, int] = dict.fromkeys(_SEVERITIES, 0)
    for s in ok:
        for sev, n in s.failed_by_severity.items():
            if sev in totals:
                totals[sev] += n
    stats = [
        (len(digest.snapshots), "repos"),
        (len(ok), "scanned OK"),
        (len(errored), "errored"),
        (len(graph["edges"]), "cross-repo edges"),
    ]
    stat_html = "".join(
        f'<div class="stat"><div class="n">{n}</div>'
        f'<div class="l">{_e(label)}</div></div>'
        for n, label in stats
    )
    chips = "".join(
        f'<span class="sev-chip"><span class="dot" '
        f'style="background:{_sev_fill(sev)}"></span>'
        f'<span class="c">{totals[sev]}</span> {sev.lower()}</span>'
        for sev in _SEVERITIES
    )
    return (
        '<section><h2>Overview</h2>'
        f'<div class="stat-band">{stat_html}</div>'
        '<h2>Org-wide failed findings</h2>'
        f'<div class="sev-chips">{chips}</div></section>'
    )


def _posture_cards_html(digest: FleetDigest) -> str:
    if not digest.snapshots:
        return '<section><h2>Fleet posture</h2><p class="note">No repositories scanned.</p></section>'
    ranked = sorted(digest.snapshots, key=lambda s: (s.score, s.coord))
    cards: list[str] = []
    for s in ranked:
        if not s.ok:
            cards.append(
                '<div class="card errored">'
                '<div class="chip" style="background:var(--light-muted)">!</div>'
                f'<div class="body"><div class="repo">{_e(s.coord)}</div>'
                f'<div class="err">error: {_e(s.error)}</div></div></div>'
            )
            continue
        mini = "".join(
            f'<span style="background:{_sev_fill(sev)}">{n} {sev[0]}</span>'
            for sev in _SEVERITIES
            if (n := s.failed_by_severity.get(sev, 0))
        )
        if not mini:
            mini = '<span style="background:var(--grade-a)">0 findings</span>'
        cards.append(
            '<div class="card">'
            f'<div class="chip" style="background:{_grade_fill(s.grade)}">'
            f'{_e(s.grade)}</div>'
            f'<div class="body"><div class="repo">{_e(s.coord)}</div>'
            f'<div class="score">score {s.score} &middot; {s.total_failed} failed</div>'
            f'<div class="mini">{mini}</div></div></div>'
        )
    return (
        '<section><h2>Fleet posture (ranked worst &rarr; best)</h2>'
        f'<div class="grid">{"".join(cards)}</div></section>'
    )


def _graph_section_html(graph: dict[str, Any]) -> str:
    edges = graph["edges"]
    if not edges:
        return (
            '<section><h2>Cross-repo posture graph</h2>'
            '<p class="note">No cross-repo attack chains detected, so '
            'there are no edges to draw. Per-repo posture is below.</p>'
            '</section>'
        )
    svg = _posture_graph_svg(graph)
    legend_grades = "".join(
        f'<span class="item"><span class="swatch" '
        f'style="background:{_grade_fill(g)}"></span>grade {g}</span>'
        for g in ("A", "B", "C", "D")
    )
    # Only show severity swatches that actually appear on an edge.
    present = [s for s in _SEVERITIES if any(e["severity"] == s for e in edges)]
    legend_sev = "".join(
        f'<span class="item"><span class="swatch" '
        f'style="background:{_sev_fill(s)}"></span>{s.lower()} edge</span>'
        for s in present
    )
    return (
        '<section><h2>Cross-repo posture graph</h2>'
        f'<div class="graph-wrap">{svg}</div>'
        f'<div class="legend">{legend_grades}{legend_sev}'
        '<span class="item"><span class="swatch" '
        'style="background:var(--light-muted)"></span>not scanned</span>'
        '</div></section>'
    )


def _posture_graph_svg(graph: dict[str, Any]) -> str:
    """Deterministic SVG node-link diagram of the CXPC edges.

    Participating nodes (those on at least one edge) are placed on a
    circle; isolated repos are left to the posture grid. Edges are
    straight arrows trimmed to the node boundary; a bidirectional pair
    (X->Y and Y->X) is split with a small perpendicular offset so both
    directions stay visible.
    """
    edges = graph["edges"]
    nodes_by_id = {n["id"]: n for n in graph["nodes"]}

    # Participating nodes in a stable order (scanned worst-score first,
    # unscanned last, then by id), so the layout is reproducible.
    seen: set[str] = set()
    participating: list[dict[str, Any]] = []
    for e in edges:
        for cid in (e["source"], e["target"]):
            if cid not in seen:
                seen.add(cid)
                participating.append(
                    nodes_by_id.get(
                        cid,
                        {"id": cid, "grade": None, "score": None, "scanned": False},
                    )
                )

    def _key(n: dict[str, Any]) -> tuple[int, int, str]:
        score = n.get("score")
        return (0 if score is not None else 1, score if score is not None else 0, n["id"])

    participating.sort(key=_key)

    w, h = 760, 520
    cx, cy = w / 2, h / 2
    radius = min(w, h) / 2 - 96  # leave room for node labels
    r = 26  # node radius
    n = len(participating)

    pos: dict[str, tuple[float, float]] = {}
    for i, node in enumerate(participating):
        if n == 1:
            pos[node["id"]] = (cx, cy)
            continue
        angle = -math.pi / 2 + i * 2 * math.pi / n  # start at 12 o'clock
        pos[node["id"]] = (cx + radius * math.cos(angle), cy + radius * math.sin(angle))

    # Which unordered pairs carry edges in both directions.
    pair_dirs: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for e in edges:
        key = tuple(sorted((e["source"], e["target"])))
        pair_dirs.setdefault(key, set()).add((e["source"], e["target"]))

    # One arrowhead marker per severity so the head matches the line.
    present = [s for s in _SEVERITIES if any(e["severity"] == s for e in edges)]
    markers = "".join(
        f'<marker id="ar-{s.lower()}" viewBox="0 0 10 10" refX="9" refY="5" '
        f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M0,0 L10,5 L0,10 z" fill="{_sev_fill(s)}"/></marker>'
        for s in present
    )

    edge_svg: list[str] = []
    label_svg: list[str] = []
    for e in edges:
        s, t = e["source"], e["target"]
        if s not in pos or t not in pos:
            continue
        x1, y1 = pos[s]
        x2, y2 = pos[t]
        dx, dy = x2 - x1, y2 - y1
        dist = math.hypot(dx, dy) or 1.0
        ux, uy = dx / dist, dy / dist
        px, py = -uy, ux  # perpendicular unit vector
        key = tuple(sorted((s, t)))
        bidir = len(pair_dirs.get(key, set())) > 1
        # Offset bidirectional edges to opposite sides (stable by name).
        off = 13.0 if bidir else 0.0
        sign = 1.0 if s < t else -1.0
        ox, oy = px * off * sign, py * off * sign
        gap = r + 5  # trim to node boundary so the arrow lands on the rim
        sx, sy = x1 + ux * gap + ox, y1 + uy * gap + oy
        ex, ey = x2 - ux * gap + ox, y2 - uy * gap + oy
        sev = e.get("severity", "INFO")
        color = _sev_fill(sev)
        title = f'{e["chain_id"]}: {e.get("title", "")} ({sev})'
        edge_svg.append(
            f'<line x1="{sx:.1f}" y1="{sy:.1f}" x2="{ex:.1f}" y2="{ey:.1f}" '
            f'stroke="{color}" stroke-width="2.2" opacity="0.9" '
            f'marker-end="url(#ar-{sev.lower()})">'
            f'<title>{_e(title)}</title></line>'
        )
        mx, my = (sx + ex) / 2, (sy + ey) / 2
        label_svg.append(
            f'<text class="edge-label" x="{mx:.1f}" y="{my:.1f}" '
            f'fill="{color}">{_e(e["chain_id"])}</text>'
        )

    node_svg: list[str] = []
    for node in participating:
        x, y = pos[node["id"]]
        scanned = node.get("scanned", False)
        fill = _grade_fill(node.get("grade"))
        dash = "" if scanned else ' stroke-dasharray="5 3"'
        grade_label = node.get("grade") or "?"
        node_svg.append(
            f'<g><circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{fill}" '
            f'stroke="#ffffff" stroke-width="2.5"{dash}/>'
            f'<text class="node-grade" x="{x:.1f}" y="{y:.1f}">'
            f'{_e(grade_label)}</text>'
            f'<text class="node-label" x="{x:.1f}" y="{y + r + 14:.1f}">'
            f'{_e(node["id"])}</text></g>'
        )

    return (
        f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" '
        f'role="img" aria-label="Cross-repo posture graph">'
        f'<defs>{markers}</defs>'
        f'{"".join(edge_svg)}{"".join(label_svg)}{"".join(node_svg)}</svg>'
    )


__all__ = ["render_fleet_html"]
