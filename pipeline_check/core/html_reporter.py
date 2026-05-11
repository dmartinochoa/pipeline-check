"""HTML report formatter.

Generates a self-contained HTML file, no external CDN dependencies.
YAML rule metadata is loaded from pipeline_check/core/checks/aws/rules/ when
PyYAML is installed; the report degrades gracefully without it.
"""

import html
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .chains import Chain
from .checks.base import Finding, Severity, severity_rank
from .scorer import ScoreResult

try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

_RULES_DIR = Path(__file__).parent / "checks" / "aws" / "rules"

_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#dc3545",
    Severity.HIGH:     "#fd7e14",
    Severity.MEDIUM:   "#d4930a",
    Severity.LOW:      "#0d6efd",
    Severity.INFO:     "#6c757d",
}

_GRADE_COLOR = {"A": "#198754", "B": "#0d9488", "C": "#d4930a", "D": "#dc3545"}

_CSS = """
/* ============================================================
   Token block mirrors .claude/design_system/colors_and_type.css
   so the report stays in lock-step with the docs site and the
   portable design Skill. The --light-* names are the canonical
   light-mode tokens; .dark below redefines them for dark mode.
   ============================================================ */
:root {
  /* Severity scale */
  --sev-critical: #dc3545;
  --sev-high:     #fd7e14;
  --sev-medium:   #d4930a;
  --sev-low:      #0d6efd;
  --sev-info:     #6c757d;

  /* Grade scale */
  --grade-a: #198754;
  --grade-b: #0d9488;
  --grade-c: #d4930a;
  --grade-d: #dc3545;

  /* Light mode (report's default) */
  --light-bg:         #f0f2f5;
  --light-card:       #ffffff;
  --light-header-bg:  #1a1a2e;
  --light-border:     #dee2e6;
  --light-text:       #212529;
  --light-muted:      #6c757d;
  --light-row-hover:  #f8f9fa;
  --light-detail-bg:  #f8f9fa;

  /* Type families */
  --font-sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --font-mono: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--font-sans);
  background: var(--light-bg); color: var(--light-text); font-size: 14px; line-height: 1.5;
}
a { color: inherit; }

/* ── Header ── */
header {
  background: var(--light-header-bg); color: #e8e8f0; padding: 14px 24px;
}
.header-inner {
  max-width: 1200px; margin: 0 auto;
  display: flex; justify-content: space-between; align-items: center;
}
header h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.3px; }
.header-sub { font-size: 12px; color: #9090b0; margin-left: 8px; }
.header-meta { font-size: 12px; color: #9090b0; }

/* ── Main ── */
main { max-width: 1200px; margin: 24px auto; padding: 0 24px; }

/* ── Score card ── */
.score-card {
  background: var(--light-card); border-radius: 8px; border: 1px solid var(--light-border);
  padding: 24px; margin-bottom: 24px;
  display: flex; align-items: center; gap: 32px; flex-wrap: wrap;
}
.grade-block {
  text-align: center; border: 3px solid; border-radius: 8px;
  padding: 10px 22px; min-width: 96px; flex-shrink: 0;
}
.grade-letter { font-size: 46px; font-weight: 800; line-height: 1; }
.grade-score  { font-size: 18px; font-weight: 600; margin-top: 4px; font-variant-numeric: tabular-nums; }
.grade-denom  { font-size: 12px; font-weight: 400; opacity: .7; }
.score-detail { flex: 1; min-width: 0; }
.score-bar-track {
  height: 8px; background: var(--light-border); border-radius: 4px;
  margin: 10px 0 14px; overflow: hidden;
}
.score-bar-fill {
  height: 100%; border-radius: 4px; transition: width .3s ease;
}
.count-row    { font-size: 15px; margin-bottom: 14px; font-variant-numeric: tabular-nums; }
.c-fail  { color: var(--sev-critical); font-weight: 600; }
.c-pass  { color: var(--grade-a); font-weight: 600; }
.c-sep   { color: var(--light-muted); margin: 0 4px; }
.c-total { color: var(--light-muted); font-size: 13px; margin-left: 4px; }
.sev-row { display: flex; gap: 10px; flex-wrap: wrap; }
.sev-pill {
  display: flex; align-items: center; gap: 5px;
  background: var(--light-detail-bg); border: 1px solid var(--light-border);
  border-radius: 20px; padding: 3px 10px; font-size: 12px;
  font-variant-numeric: tabular-nums;
}
.sev-dot  { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.sev-name { font-weight: 600; }
.sev-cnt  { color: var(--light-muted); }

/* ── Findings table ── */
.findings-table {
  width: 100%; border-collapse: collapse;
  background: var(--light-card); border-radius: 8px;
  border: 1px solid var(--light-border); overflow: hidden;
}
.findings-table thead th {
  background: #f1f3f5; text-align: left; padding: 9px 14px;
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .5px; color: var(--light-muted);
  border-bottom: 1px solid var(--light-border);
}
.findings-table tbody tr { border-bottom: 1px solid var(--light-border); }
.findings-table tbody tr:last-child { border-bottom: none; }
.findings-table tbody tr:hover td { background: var(--light-row-hover); }
.findings-table tbody td { padding: 9px 14px; vertical-align: top; }
td.td-id { border-left: 3px solid transparent; }
tr.row-fail td.td-id { border-left-color: var(--sev-critical); }
tr.row-pass td.td-id { border-left-color: var(--grade-a); }
.check-id { font-family: var(--font-mono); font-weight: 600; font-size: 13px; white-space: nowrap; font-variant-numeric: tabular-nums; }
.resource  { font-family: var(--font-mono); font-size: 12px; color: var(--light-muted); word-break: break-all; max-width: 180px; }

/* ── Badges ── */
.badge {
  display: inline-block; padding: 2px 7px; border-radius: 4px;
  font-size: 11px; font-weight: 700; text-transform: uppercase; white-space: nowrap;
  font-family: var(--font-mono); letter-spacing: 0.04em;
}
.b-critical { background:#fde8e8; color: var(--sev-critical); }
.b-high     { background:#fef0e6; color:#c85d00; }
.b-medium   { background:#fef8e0; color:#8a5e00; }
.b-low      { background:#e7f0ff; color:#0d4fb5; }
.b-info     { background:#f0f0f0; color:#555; }
.b-pass     { background:#e6f4ec; color: var(--grade-a); }
.b-fail     { background:#fde8e8; color: var(--sev-critical); }

/* ── Expandable details ── */
details > summary {
  cursor: pointer; list-style: none;
  display: flex; align-items: flex-start; gap: 6px; font-weight: 500;
}
details > summary::-webkit-details-marker { display: none; }
details > summary::before {
  content: "▶"; font-size: 9px; color: var(--light-muted);
  margin-top: 3px; flex-shrink: 0; transition: transform .15s;
}
details[open] > summary::before { transform: rotate(90deg); }
.check-detail {
  margin-top: 10px; padding: 14px; border-radius: 6px;
  background: var(--light-detail-bg); border-left: 3px solid var(--light-border); font-size: 13px;
}
.d-section { margin-bottom: 12px; }
.d-section:last-child { margin-bottom: 0; }
.d-label {
  font-family: var(--font-mono);
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .12em; color: var(--light-muted); margin-bottom: 3px;
}
.d-value ul { margin: 4px 0 0 16px; }
.d-value li { margin-bottom: 3px; }
.owasp-tag {
  display: inline-block; background: #eef0fb; color: #3f4faa;
  padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;
  font-family: var(--font-mono);
}

/* ── Filter bar ── */
.filter-bar {
  background: var(--light-card); border: 1px solid var(--light-border); border-radius: 8px;
  padding: 10px 14px; margin-bottom: 14px;
  display: flex; gap: 14px; flex-wrap: wrap; align-items: center; font-size: 13px;
  position: sticky; top: 0; z-index: 10;
}
.bulk-btn {
  border: 1px solid var(--light-border); background: var(--light-card);
  border-radius: 4px; padding: 3px 10px; font-size: 12px; cursor: pointer;
  color: var(--light-muted);
}
.bulk-btn:hover { background: var(--light-row-hover); }
/* Sticky headers offset accounts for the filter bar's height. The
   bar wraps to a second / third row on narrow screens; the media
   queries below bump the offset so the headers don't slide
   underneath the wrapped controls. ``--filter-bar-h`` is a CSS
   custom property so a future JS-driven measure (resize observer)
   can override at runtime without touching this rule.
*/
:root { --filter-bar-h: 60px; }
@media (max-width: 900px) { :root { --filter-bar-h: 110px; } }
@media (max-width: 600px) { :root { --filter-bar-h: 200px; } }
.findings-table thead th {
  position: sticky; top: var(--filter-bar-h); z-index: 5;
}
.filter-group { display: flex; align-items: center; gap: 6px; }
.filter-group label { font-weight: 600; color: var(--light-muted); font-size: 11px; text-transform: uppercase; letter-spacing: .5px; }
.filter-group select { padding: 4px 8px; border: 1px solid var(--light-border); border-radius: 4px; font-size: 13px; background: var(--light-card); }
.filter-group input[type=text] { padding: 4px 8px; border: 1px solid var(--light-border); border-radius: 4px; font-size: 13px; min-width: 180px; }
.filter-count { color: var(--light-muted); font-size: 12px; margin-left: auto; font-variant-numeric: tabular-nums; }

/* ── Copy-ignore button ── */
.copy-ignore-btn {
  float: right; margin-left: 8px;
  border: 1px solid var(--light-border); background: var(--light-card);
  border-radius: 4px; padding: 2px 8px; font-size: 11px; cursor: pointer;
  color: var(--light-muted); font-family: var(--font-mono);
}
.copy-ignore-btn:hover { background: var(--light-row-hover); }
.copy-ignore-btn.copied { background: #e6f4ec; color: var(--grade-a); border-color: var(--grade-a); }

/* ── Dark mode ──
   ``--light-muted`` bumped from #8888aa to #a0a0c0 so the muted
   text on dark backgrounds clears WCAG AA at 5.1:1 (was right at
   the 4.5:1 threshold). All other tokens unchanged.
*/
.dark {
  --light-bg: #1a1a2e; --light-card: #16213e; --light-header-bg: #0f0f23;
  --light-border: #2a2a4a; --light-text: #e0e0e8; --light-muted: #a0a0c0;
  --light-row-hover: #1e2a4a; --light-detail-bg: #12203a;
}
.dark .findings-table thead th { background: #1a1a3e; }
.dark .owasp-tag { background: #2a2a5a; color: #9999dd; }
.dark .sev-pill { background: #1a1a3e; }
.dark .b-pass { background: #1a3a2a; } .dark .b-fail { background: #3a1a1a; }
.dark .b-critical { background: #3a1a1a; } .dark .b-high { background: #3a2a1a; }
.dark .b-medium { background: #3a3a1a; } .dark .b-low { background: #1a2a3a; }
.dark .b-info { background: #2a2a2a; color: #aaa; }

/* ── Theme toggle ── */
.theme-toggle {
  background: none; border: 1px solid #555; border-radius: 4px;
  color: #9090b0; padding: 3px 10px; cursor: pointer; font-size: 12px;
}
.theme-toggle:hover { background: rgba(255,255,255,.1); }

/* ── Attack chains panel ──
   The chain card's left-border color is the only per-card tinted
   piece (set inline since severity drives the choice). All the
   structural / typographic styling lives in CSS classes so the
   chain panel doesn't drift from the rest of the report.
*/
.chains-section { margin: 24px 0; }
.chains-section > h2 {
  margin: 0 0 12px;
  color: var(--sev-critical);
  font-size: 18px;
}
.chains-section > .chains-lede {
  color: var(--light-muted);
  margin: 0 0 12px;
  font-size: 13px;
}
.chain-card {
  background: var(--light-card);
  padding: 14px 18px;
  margin: 0 0 12px;
  border-radius: 4px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, .05);
  /* ``border-left-color`` is set inline per chain severity; only
     the width / style live here. */
  border-left: 5px solid transparent;
}
.chain-card__head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 8px;
}
.chain-card__title { margin: 0; font-size: 16px; }
.chain-card__title code {
  background: var(--light-detail-bg);
  padding: 1px 6px;
  border-radius: 3px;
  font-family: var(--font-mono);
}
.chain-card__meta {
  font-size: 12px;
  color: var(--light-muted);
}
.chain-card__summary { margin: 8px 0; }
.chain-card__narrative {
  background: var(--light-detail-bg);
  padding: 10px;
  border-radius: 3px;
  white-space: pre-wrap;
  font-size: 13px;
  margin: 8px 0;
  font-family: var(--font-mono);
}
.chain-card__line { margin-top: 8px; }
.chain-card__line code {
  padding: 1px 6px;
  border-radius: 3px;
  font-family: var(--font-mono);
}
.chain-card__triggers code { background: #eef; }
.chain-card__mitre code { background: #fed; }
.dark .chain-card__triggers code { background: #2a2a5a; color: #cfd0e8; }
.dark .chain-card__mitre code { background: #4a3520; color: #f0d8b4; }

/* ── Anchor flash when a finding is deep-linked ── */
:target td { animation: flash 1.5s ease; }
@keyframes flash {
  0%   { background: #fff3cd; }
  100% { background: transparent; }
}
.dark :target td { animation-name: flash-dark; }
@keyframes flash-dark {
  0%   { background: #3a3a1a; }
  100% { background: transparent; }
}

/* ── Footer ── */
footer { text-align: center; padding: 24px; color: var(--light-muted); font-size: 12px; }

/* ── Print ── */
@media print {
  body, .dark { background: #fff !important; color: #000 !important; }
  header, footer, .filter-bar, .theme-toggle, .copy-ignore-btn, .bulk-btn { display: none !important; }
  main { max-width: none; margin: 0; padding: 0; }
  .score-card { break-inside: avoid; border: 1px solid #000; }
  details { page-break-inside: avoid; }
  details > summary::before { content: ""; }
  details > .check-detail { display: block !important; }
  .findings-table, .findings-table thead th { position: static !important; }
}
"""


_SCRIPT = r"""
(function () {
  // ── Theme: honor saved choice → OS preference → light default ──
  const THEME_KEY = 'pipelinecheck.theme';
  function initTheme() {
    const saved = localStorage.getItem(THEME_KEY);
    const prefersDark = window.matchMedia &&
      window.matchMedia('(prefers-color-scheme: dark)').matches;
    const useDark = saved === 'dark' || (saved === null && prefersDark);
    document.body.classList.toggle('dark', useDark);
  }
  initTheme();
  const themeBtn = document.querySelector('.theme-toggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const nowDark = !document.body.classList.contains('dark');
      document.body.classList.toggle('dark', nowDark);
      localStorage.setItem(THEME_KEY, nowDark ? 'dark' : 'light');
    });
  }

  // ── Filter state ───────────────────────────────────────────────
  const rows = document.querySelectorAll('tbody tr[data-check-id]');
  const sev   = document.getElementById('f-sev');
  const std   = document.getElementById('f-std');
  const prov  = document.getElementById('f-prov');
  const stat  = document.getElementById('f-status');
  const text  = document.getElementById('f-text');
  const count = document.getElementById('f-count');
  const FILTER_INPUTS = { sev, std, prov, stat, q: text };

  // Hydrate filters from URL query on load so shared links restore state.
  function hydrateFromUrl() {
    const params = new URLSearchParams(window.location.search);
    for (const [name, el] of Object.entries(FILTER_INPUTS)) {
      if (!el) continue;
      const v = params.get(name);
      if (v !== null) el.value = v;
    }
  }

  // Mirror filter state into the URL without adding history entries so
  // the back button still exits the report.
  function serializeToUrl() {
    const params = new URLSearchParams();
    for (const [name, el] of Object.entries(FILTER_INPUTS)) {
      if (el && el.value) params.set(name, el.value);
    }
    const qs = params.toString();
    const url = qs ? ('?' + qs + window.location.hash) : (window.location.pathname + window.location.hash);
    history.replaceState(null, '', url);
  }

  function visibleCount() {
    let n = 0;
    rows.forEach(r => { if (r.style.display !== 'none') n++; });
    count.textContent = n + ' shown';
  }

  function apply() {
    const want_sev  = sev.value;
    const want_std  = std.value;
    const want_prov = prov.value;
    const want_stat = stat.value;
    const needle    = text.value.toLowerCase().trim();
    rows.forEach(r => {
      const rsev  = r.dataset.severity;
      const rstds = (r.dataset.standards || '').split(',');
      const rprov = r.dataset.provider;
      const rstat = r.dataset.status;
      const hay   = (r.dataset.haystack || '').toLowerCase();
      let ok = true;
      if (want_sev  && rsev  !== want_sev)  ok = false;
      if (want_std  && !rstds.includes(want_std)) ok = false;
      if (want_prov && rprov !== want_prov) ok = false;
      if (want_stat && rstat !== want_stat) ok = false;
      if (needle && !hay.includes(needle))  ok = false;
      r.style.display = ok ? '' : 'none';
    });
    visibleCount();
    serializeToUrl();
  }

  hydrateFromUrl();
  [sev, std, prov, stat].forEach(el => el.addEventListener('change', apply));
  text.addEventListener('input', apply);
  apply();

  // ── Expand-all / collapse-all ───────────────────────────────────
  const expandBtn = document.getElementById('f-expand');
  const collapseBtn = document.getElementById('f-collapse');
  function setAll(open) {
    document.querySelectorAll('tr[data-check-id] details').forEach(d => {
      // Only toggle rows currently visible after filtering, honors the
      // user's "show me what's failing" filter even when they expand all.
      if (d.closest('tr').style.display !== 'none') d.open = open;
    });
  }
  if (expandBtn)   expandBtn.addEventListener('click', () => setAll(true));
  if (collapseBtn) collapseBtn.addEventListener('click', () => setAll(false));

  // ── Keyboard shortcuts ─────────────────────────────────────────
  document.addEventListener('keydown', (e) => {
    // Don't hijack when the user is already typing in an input/textarea.
    const tag = (e.target.tagName || '').toUpperCase();
    const typing = tag === 'INPUT' || tag === 'TEXTAREA' || e.target.isContentEditable;
    if (e.key === '/' && !typing) {
      e.preventDefault();
      text.focus();
      text.select();
    } else if (e.key === 'Escape' && typing && e.target === text) {
      text.value = '';
      apply();
      text.blur();
    }
  });

  // ── Deep-link scrolling: if a finding anchor is present, expand it. ─
  function openAnchored() {
    if (!window.location.hash) return;
    const el = document.querySelector(window.location.hash);
    if (!el) return;
    const details = el.querySelector('details');
    if (details) details.open = true;
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
  openAnchored();
  window.addEventListener('hashchange', openAnchored);

  // ── Copy-ignore button ─────────────────────────────────────────
  // Two-path copy: navigator.clipboard for HTTPS / localhost, then a
  // textarea + execCommand fallback that works on file:// (the
  // typical local-report viewing case where Chrome blocks the
  // Clipboard API).
  async function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch (err) {
        // fall through
      }
    }
    // Fallback: transient off-screen textarea.
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    ta.style.pointerEvents = 'none';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch (err) {
      ok = false;
    }
    document.body.removeChild(ta);
    return ok;
  }

  document.querySelectorAll('.copy-ignore-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const rule = btn.dataset.rule;
      const ok = await copyToClipboard(rule);
      if (ok) {
        btn.textContent = '✓ copied';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = btn.dataset.label;
          btn.classList.remove('copied');
        }, 1500);
      } else {
        // Surface the failure inline so the user knows to copy
        // manually rather than assuming the rule landed silently.
        btn.textContent = 'copy failed';
        setTimeout(() => {
          btn.textContent = btn.dataset.label;
        }, 1500);
      }
    });
  });
})();
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_rules() -> dict[str, dict[str, Any]]:
    """Load YAML rule definitions indexed by check_id. Returns {} if unavailable.

    Parse errors are logged to stderr rather than silently swallowed —
    a malformed rule YAML is a real maintenance problem that should be
    visible to the operator, even if we still render the report.
    """
    import sys
    if not _YAML_AVAILABLE or not _RULES_DIR.exists():
        return {}
    rules: dict[str, dict[str, Any]] = {}
    for yml_path in _RULES_DIR.glob("*.yml"):
        try:
            with yml_path.open(encoding="utf-8") as fh:
                data = _yaml.safe_load(fh)
        except (OSError, _yaml.YAMLError) as exc:
            print(
                f"[html-reporter] could not load rule file {yml_path}: {exc}",
                file=sys.stderr,
            )
            continue
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict) and "id" in entry:
                    rules[entry["id"]] = entry
    return rules


def _e(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text))


# Match an https:// URL in an incident-ref string. Conservative: only
# https, no userinfo, stop at whitespace / quote / closing punctuation
# so the URL stays clickable without dragging the trailing period of
# the sentence into the anchor.
_URL_RE = re.compile(r"https://[^\s<>\"')]+")


def _autolink(text: str) -> str:
    """HTML-escape *text* and turn embedded https URLs into anchors.

    Used by the "Seen in the wild" footer to render incident-ref
    citations with clickable links to CVEs / postmortems while
    keeping the surrounding prose escaped.
    """
    parts: list[str] = []
    last = 0
    for m in _URL_RE.finditer(text):
        parts.append(_e(text[last:m.start()]))
        url = m.group(0)
        parts.append(
            f'<a href="{_e(url)}" target="_blank" rel="noopener noreferrer">'
            f'{_e(url)}</a>'
        )
        last = m.end()
    parts.append(_e(text[last:]))
    return "".join(parts)


def _severity_badge(severity: Severity) -> str:
    cls = f"b-{severity.value.lower()}"
    return f'<span class="badge {cls}">{_e(severity.value)}</span>'


def _status_badge(passed: bool) -> str:
    return (
        '<span class="badge b-pass">PASS</span>'
        if passed else
        '<span class="badge b-fail">FAIL</span>'
    )


def _severity_summary_html(summary: dict[str, Any]) -> str:
    pills: list[str] = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        data = summary.get(sev.value, {"passed": 0, "failed": 0})
        total = data["passed"] + data["failed"]
        if total == 0:
            continue
        color = _SEVERITY_COLOR[sev]
        pills.append(
            f'<div class="sev-pill">'
            f'<span class="sev-dot" style="background:{color}"></span>'
            f'<span class="sev-name">{sev.value}</span>'
            f'<span class="sev-cnt">{data["failed"]}✗&nbsp;{data["passed"]}✓</span>'
            f'</div>'
        )
    return f'<div class="sev-row">{"".join(pills)}</div>'


# Check-ID prefix → provider slug used in the filter dropdown. Keep in
# sync when a new rule family is introduced; unknown prefixes fall back
# to "other" and become invisible to the Provider filter. The
# ``test_every_known_prefix_maps_somewhere`` regression test in
# ``tests/test_html_reporter.py`` enforces parity between this map and
# the catalog of prefixes the rule pack actually emits.
_PROVIDER_PREFIXES = {
    # CI-provider families
    "GHA": "github", "GL": "gitlab", "BB": "bitbucket", "ADO": "azure",
    "JF": "jenkins", "CC": "circleci", "GCB": "cloudbuild",
    "BK": "buildkite", "DR": "drone", "TKN": "tekton", "ARGO": "argo",
    # AWS core pipeline services
    "CB": "aws", "CP": "aws", "CD": "aws", "IAM": "aws", "S3": "aws",
    "ECR": "aws", "PBAC": "aws",
    # AWS ancillary services (observability, crypto, secrets, code hosting)
    "CT": "aws", "CWL": "aws", "CW": "aws", "EB": "aws",
    "SM": "aws", "SSM": "aws", "KMS": "aws",
    "CA": "aws", "CCM": "aws", "LMB": "aws",
    "SIGN": "aws",
    # IaC providers
    "TF": "terraform", "CF": "cloudformation", "CFN": "cloudformation",
    # Container / runtime providers
    "DF": "dockerfile", "K8S": "kubernetes", "HELM": "helm",
    # OCI image manifests + attestation content (same provider, two
    # rule families: presence checks live under OCI-NNN; content
    # parsing under ATTEST-NNN).
    "OCI": "oci", "ATTEST": "oci",
    # SCM posture (GitHub repo governance via the REST API).
    "SCM": "scm",
    # Cross-step / cross-job dataflow taint engine. The TAINT family
    # spans multiple providers (GHA / GitLab / Buildkite / Tekton /
    # Argo) but the rule IDs share the prefix; bucketing them under
    # a synthetic ``taint`` filter lets the operator see every taint
    # finding in one filter slice regardless of which provider's
    # propagation channel surfaced it.
    "TAINT": "taint",
    # External SARIF ingest from any conformant scanner (Trivy,
    # Checkov, Snyk, KICS, CodeQL, …). Every ``--ingest`` finding
    # carries an ``INGEST-<tool>-<rule>`` check_id, so the prefix
    # collapses to a single ``ingest`` bucket. The source tool's
    # name lives in the rule-id suffix and stays grep-friendly.
    "INGEST": "ingest",
}


def _provider_for(check_id: str) -> str:
    prefix = check_id.split("-", 1)[0].upper()
    return _PROVIDER_PREFIXES.get(prefix, "other")


def _finding_row(finding: Finding, rule: dict[str, Any]) -> str:
    row_cls = "row-fail" if not finding.passed else "row-pass"

    # Result (dynamic description from Finding)
    sections = [
        f'<div class="d-section">'
        f'<div class="d-label">Result</div>'
        f'<div class="d-value">{_e(finding.description)}</div>'
        f'</div>'
    ]

    # Static description from YAML
    if rule.get("description"):
        sections.append(
            f'<div class="d-section">'
            f'<div class="d-label">What this checks</div>'
            f'<div class="d-value">{_e(str(rule["description"]).strip())}</div>'
            f'</div>'
        )

    # Recommended actions, prefer structured list from YAML, fall back to Finding string
    actions = rule.get("recommended_actions")
    if actions:
        items = "".join(f"<li>{_e(a)}</li>" for a in actions)
        sections.append(
            f'<div class="d-section">'
            f'<div class="d-label">Recommended Actions</div>'
            f'<div class="d-value"><ul>{items}</ul></div>'
            f'</div>'
        )
    elif finding.recommendation:
        sections.append(
            f'<div class="d-section">'
            f'<div class="d-label">Recommendation</div>'
            f'<div class="d-value">{_e(finding.recommendation)}</div>'
            f'</div>'
        )

    # CWE identifiers
    if finding.cwe:
        cwe_tags = " ".join(
            f'<span class="owasp-tag" style="background:#fff3e0;color:#e65100">{_e(c)}</span>'
            for c in finding.cwe
        )
        sections.append(
            f'<div class="d-section">'
            f'<div class="d-label">CWE</div>'
            f'<div class="d-value">{cwe_tags}</div>'
            f'</div>'
        )

    # Real-world incidents this rule is anchored to. Anchors abstract
    # security debt to a concrete cost the operator's manager has heard
    # of. Citations are populated on the rule (RULE.incident_refs) and
    # backfilled to the finding by the provider orchestrator.
    if finding.incident_refs:
        items = "".join(
            f"<li>{_autolink(ref)}</li>" for ref in finding.incident_refs
        )
        sections.append(
            f'<div class="d-section">'
            f'<div class="d-label">Seen in the wild</div>'
            f'<div class="d-value"><ul style="margin:4px 0 0 18px;padding:0">'
            f'{items}</ul></div>'
            f'</div>'
        )

    # Concrete proof-of-exploit snippet for HIGH / CRITICAL rules.
    # Pre-formatted so multi-line payloads (issue-title injection
    # strings, manifest fragments, attack sequences) render verbatim.
    if (not finding.passed) and finding.exploit_example:
        sections.append(
            f'<div class="d-section">'
            f'<div class="d-label">Proof of exploit</div>'
            f'<div class="d-value">'
            f'<pre style="background:var(--light-detail-bg);'
            f'border:1px solid var(--light-border);'
            f'padding:8px;border-radius:4px;'
            f'font-family:var(--font-mono);font-size:12px;'
            f'overflow-x:auto;white-space:pre-wrap;margin:4px 0 0 0">'
            f'{_e(finding.exploit_example)}</pre>'
            f'</div></div>'
        )

    # Compliance controls, one tag per ControlRef, grouped by standard.
    if finding.controls:
        by_std: dict[str, list[Any]] = {}
        for c in finding.controls:
            by_std.setdefault(c.standard_title, []).append(c)
        groups_html = ""
        for std_title, refs in by_std.items():
            tags = "".join(
                f'<span class="owasp-tag" title="{_e(r.control_title)}">'
                f'{_e(r.control_id)}: {_e(r.control_title)}</span> '
                for r in refs
            )
            groups_html += (
                f'<div style="margin-top:6px">'
                f'<strong style="font-size:11px">{_e(std_title)}</strong><br>{tags}'
                f'</div>'
            )
        sections.append(
            f'<div class="d-section">'
            f'<div class="d-label">Compliance Controls</div>'
            f'<div class="d-value">{groups_html}</div>'
            f'</div>'
        )

    detail_html = "".join(sections)

    standards = sorted({c.standard for c in finding.controls})
    provider = _provider_for(finding.check_id)
    status = "fail" if not finding.passed else "pass"
    # Haystack for free-text filter. Includes the visible summary +
    # the per-finding description and every Compliance Control ID /
    # title so a search for "CICD-SEC-6" or a phrase from the
    # description matches even when the row's <details> block isn't
    # expanded. Lowercased once at render time so the JS comparison
    # stays a cheap string include.
    haystack_parts = [
        finding.check_id, finding.title, finding.resource,
        finding.description,
    ]
    for ctrl in finding.controls:
        haystack_parts.append(ctrl.control_id)
        haystack_parts.append(ctrl.control_title)
    haystack = " ".join(haystack_parts).lower()
    # Ignore-rule the copy button will drop into the clipboard:
    # ``CHECK_ID:RESOURCE``, the flat format the gate accepts.
    ignore_rule = f"{finding.check_id}:{finding.resource}"

    # Stable, shareable anchor per finding: ``#finding-<check>-<slug>``.
    # Collisions across rows are avoided by including the resource slug;
    # duplicate ``check_id + resource`` pairs are already impossible by
    # construction (the Scanner dedupes on that tuple). When the
    # resource slug exceeds 60 chars we truncate AND append an 8-char
    # hash of the full slug — naive ``slug[:60]`` would collide for
    # two long resource paths sharing a 60-char prefix (e.g.
    # ``infrastructure/terraform/modules/.../foo.tf`` vs
    # ``infrastructure/terraform/modules/.../bar.tf``).
    anchor = "finding-" + finding.check_id.lower()
    if finding.resource:
        slug = "".join(
            c if c.isalnum() or c == "-" else "-"
            for c in finding.resource.lower()
        ).strip("-")
        if slug:
            if len(slug) > 60:
                import hashlib
                tail = hashlib.sha256(slug.encode("utf-8")).hexdigest()[:8]
                slug = f"{slug[:50]}-{tail}"
            anchor = f"{anchor}-{slug}"

    return (
        f'<tr id="{_e(anchor)}" class="{row_cls}" '
        f'data-check-id="{_e(finding.check_id)}" '
        f'data-severity="{_e(finding.severity.value)}" '
        f'data-standards="{_e(",".join(standards))}" '
        f'data-provider="{_e(provider)}" '
        f'data-status="{status}" '
        f'data-haystack="{_e(haystack)}">'
        f'<td class="td-id"><span class="check-id">{_e(finding.check_id)}</span></td>'
        f'<td>{_severity_badge(finding.severity)}</td>'
        f'<td>{_status_badge(finding.passed)}</td>'
        f'<td><span class="resource">{_e(finding.resource)}</span></td>'
        f'<td>'
        f'<details>'
        f'<summary>{_e(finding.title)}'
        f'<button class="copy-ignore-btn" '
        f'data-rule="{_e(ignore_rule)}" '
        f'data-label="copy ignore">copy ignore</button>'
        f'</summary>'
        f'<div class="check-detail">{detail_html}</div>'
        f'</details>'
        f'</td>'
        f'</tr>\n'
    )


def _blast_radius_section_html(findings: list[Finding]) -> str:
    """Render the resource-level blast-radius heatmap.

    A grid of tiles, one per resource (workflow file, image manifest,
    Terraform plan path, etc.). Tile color reflects the worst-severity
    finding on the resource; tile size scales with the number of
    failing findings (sqrt-scaled so a 50-finding resource doesn't
    dwarf a 5-finding one). Each tile carries a ``title`` attribute
    listing the per-severity counts so hovering shows the breakdown
    without clicking through to the table.

    The chart is pure inline SVG so the report stays a single
    self-contained HTML file (no CDN, no JS framework). Sits between
    the chains panel and the findings table, the position that makes
    sense for "which resources hurt most" triage.

    A future v2 will lift this to a true pipeline DAG (steps as
    nodes, ``needs:`` / ``depends_on`` as edges) once the Scanner
    can pass parsed pipeline structure to the reporter; for now the
    heatmap is the strongest visual signal we can render from the
    findings list alone.
    """
    by_resource: dict[str, list[Finding]] = {}
    for f in findings:
        if f.passed:
            continue
        by_resource.setdefault(f.resource or "(unknown)", []).append(f)

    if not by_resource:
        return ""

    # Per-tile metadata: worst severity, count, severity breakdown.
    tiles: list[tuple[str, Severity, int, dict[str, int]]] = []
    for resource, group in by_resource.items():
        worst = max(group, key=lambda f: severity_rank(f.severity)).severity
        breakdown: dict[str, int] = {}
        for f in group:
            breakdown[f.severity.value] = (
                breakdown.get(f.severity.value, 0) + 1
            )
        tiles.append((resource, worst, len(group), breakdown))

    # Sort by worst severity (CRITICAL first), then count desc, then
    # name. Stable so equal entries land in a predictable order.
    tiles.sort(
        key=lambda t: (-severity_rank(t[1]), -t[2], t[0]),
    )

    # Grid layout: pack tiles into 6 columns (responsive layout
    # could lift this; 6 is the breakpoint that fits the report's
    # 1100px max-width comfortably). Tile height scales with sqrt
    # of finding count so 50 findings don't crowd out 5 findings.
    import math
    cols = 6
    cell_w = 170
    cell_pad = 8
    base_h = 56
    max_h = 130
    rows: list[list[tuple[str, Severity, int, dict[str, int]]]] = []
    for i in range(0, len(tiles), cols):
        rows.append(tiles[i:i + cols])

    max_count = max((t[2] for t in tiles), default=1)

    svg_parts: list[str] = []
    canvas_w = cols * (cell_w + cell_pad) + cell_pad
    canvas_h = 0
    y = cell_pad
    for row in rows:
        # Each row's tile heights are independent; the row's height
        # is the max of any tile in it.
        row_heights = [
            int(base_h + (max_h - base_h) * math.sqrt(t[2] / max_count))
            for t in row
        ]
        row_h = max(row_heights)
        for col_idx, (resource, sev, count, breakdown) in enumerate(row):
            tile_h = row_heights[col_idx]
            x = cell_pad + col_idx * (cell_w + cell_pad)
            tile_y = y + (row_h - tile_h)  # bottom-aligned tiles
            color = _SEVERITY_COLOR.get(sev, "#6c757d")
            label = resource.split("/")[-1] if "/" in resource else resource
            tooltip = " | ".join(
                f"{k}: {v}" for k, v in sorted(
                    breakdown.items(),
                    key=lambda kv: -severity_rank(Severity(kv[0])),
                )
            )
            svg_parts.append(
                f'<g><title>{_e(resource)} | {_e(tooltip)}</title>'
                f'<rect x="{x}" y="{tile_y}" width="{cell_w}" '
                f'height="{tile_h}" fill="{color}" rx="4" '
                f'fill-opacity="0.85"/>'
                f'<text x="{x + cell_w / 2}" y="{tile_y + 22}" '
                f'fill="#ffffff" font-size="13" font-weight="600" '
                f'text-anchor="middle" '
                f'style="pointer-events:none">'
                f'{_e(label[:22])}{_e("..." if len(label) > 22 else "")}</text>'
                f'<text x="{x + cell_w / 2}" y="{tile_y + tile_h - 10}" '
                f'fill="#ffffff" font-size="11" font-weight="500" '
                f'text-anchor="middle" fill-opacity="0.9" '
                f'style="pointer-events:none">'
                f'{count} finding{"s" if count != 1 else ""}</text>'
                f'</g>'
            )
        y += row_h + cell_pad
        canvas_h = y
    canvas_h = canvas_h or cell_pad * 2

    legend = " ".join(
        f'<span style="display:inline-flex;align-items:center;gap:6px">'
        f'<span style="width:14px;height:14px;background:'
        f'{_SEVERITY_COLOR[sev]};border-radius:2px;display:inline-block">'
        f'</span>{_e(sev.value)}</span>'
        for sev in (
            Severity.CRITICAL, Severity.HIGH,
            Severity.MEDIUM, Severity.LOW, Severity.INFO,
        )
    )

    return (
        '<section class="blast-radius" style="margin:24px 0">'
        '<h2 style="margin:0 0 4px;color:var(--light-text)">'
        f'Blast radius ({len(tiles)} resource'
        f'{"s" if len(tiles) != 1 else ""})</h2>'
        '<p style="color:var(--light-muted);margin:0 0 8px;font-size:13px">'
        'Each tile is one resource with at least one failing '
        'finding. Color = worst severity. Size = total failing '
        'findings. Hover for the per-severity breakdown.</p>'
        f'<div style="background:var(--light-card);padding:10px;'
        f'border-radius:4px;overflow-x:auto">'
        f'<svg width="{canvas_w}" height="{canvas_h}" '
        f'viewBox="0 0 {canvas_w} {canvas_h}" '
        f'role="img" aria-label="Blast radius chart">'
        + "".join(svg_parts) +
        '</svg></div>'
        f'<div style="margin-top:8px;display:flex;gap:14px;'
        f'flex-wrap:wrap;font-size:12px;color:var(--light-muted)">'
        f'{legend}</div>'
        '</section>'
    )


def _chains_section_html(chains: list[Chain]) -> str:
    """Render the Attack Chains panel.

    Sits between the score card and the findings table. Each chain is
    its own card with a left border tinted by the chain's severity so
    a CRITICAL chain is unmissable. Narrative is preserved as a
    ``<pre>`` block, chain rules already format multi-line steps and
    we don't want Markdown reflow to dissolve the numbered list.
    """
    if not chains:
        return ""
    cards: list[str] = []
    for c in chains:
        color = _SEVERITY_COLOR.get(c.severity, "#6c757d")
        triggers = " ".join(
            f"<code>{_e(cid)}</code>"
            for cid in c.triggering_check_ids
        )
        mitre_html = (
            '<div class="chain-card__line chain-card__mitre">'
            "<strong>MITRE ATT&amp;CK:</strong> "
            + " ".join(
                f"<code>{_e(t)}</code>" for t in c.mitre_attack
            )
            + "</div>"
            if c.mitre_attack
            else ""
        )
        kc_html = (
            f'<div class="chain-card__line">'
            f"<strong>Kill chain:</strong> {_e(c.kill_chain_phase)}</div>"
            if c.kill_chain_phase
            else ""
        )
        refs_html = ""
        if c.references:
            refs_html = (
                '<div class="chain-card__line"><strong>References:</strong>'
                "<ul>"
                + "".join(
                    f'<li><a href="{_e(r)}" target="_blank" '
                    f'rel="noopener">{_e(r)}</a></li>'
                    for r in c.references
                )
                + "</ul></div>"
            )
        cards.append(
            f'<div class="chain-card" '
            f'style="border-left-color:{color}">'
            f'<div class="chain-card__head">'
            f'<h3 class="chain-card__title" style="color:{color}">'
            f'<code>{_e(c.chain_id)}</code> &mdash; {_e(c.title)}</h3>'
            f'<div class="chain-card__meta">'
            f'severity: <strong style="color:{color}">'
            f'{_e(c.severity.value)}</strong> '
            f'&nbsp;·&nbsp; confidence: {_e(c.confidence.value)}'
            f'</div>'
            f'</div>'
            f'<p class="chain-card__summary">{_e(c.summary)}</p>'
            f'<pre class="chain-card__narrative">{_e(c.narrative)}</pre>'
            f'<div class="chain-card__line chain-card__triggers">'
            f'<strong>Triggering checks:</strong> {triggers}</div>'
            f'{mitre_html}{kc_html}'
            f'<div class="chain-card__line">'
            f'<strong>Recommendation:</strong> {_e(c.recommendation)}'
            f'</div>'
            f'{refs_html}'
            f'</div>'
        )
    return (
        '<section class="chains-section">'
        f'<h2>&#9888; Attack Chains ({len(chains)})</h2>'
        '<p class="chains-lede">'
        'Multiple findings combine into a real attack path. Fix any one '
        'finding in a chain to break it.</p>'
        + "".join(cards) +
        '</section>'
    )


def _filter_bar_html(findings: list[Finding]) -> str:
    """Render the dropdowns with only the options present in the results."""
    severities_present = sorted(
        {f.severity.value for f in findings},
        key=lambda s: -severity_rank(Severity(s)),
    )
    standards_present = sorted({c.standard for f in findings for c in f.controls})
    providers_present = sorted({_provider_for(f.check_id) for f in findings})

    def _opts(values: list[str], label: str) -> str:
        opts = f'<option value="">All {label}</option>'
        for v in values:
            opts += f'<option value="{_e(v)}">{_e(v)}</option>'
        return opts

    return (
        '<div class="filter-bar">'
        '<div class="filter-group"><label>Severity</label>'
        f'<select id="f-sev">{_opts(severities_present, "severities")}</select></div>'
        '<div class="filter-group"><label>Standard</label>'
        f'<select id="f-std">{_opts(standards_present, "standards")}</select></div>'
        '<div class="filter-group"><label>Provider</label>'
        f'<select id="f-prov">{_opts(providers_present, "providers")}</select></div>'
        '<div class="filter-group"><label>Status</label>'
        '<select id="f-status">'
        '<option value="">All</option>'
        '<option value="fail">Fail</option>'
        '<option value="pass">Pass</option>'
        '</select></div>'
        '<div class="filter-group">'
        '<input id="f-text" type="text" '
        'placeholder="Filter by id, title, resource...  (press / to focus)" '
        'aria-label="Free-text filter" />'
        '</div>'
        '<button id="f-expand" class="bulk-btn" type="button" '
        'title="Expand all visible rows">expand all</button>'
        '<button id="f-collapse" class="bulk-btn" type="button" '
        'title="Collapse all rows">collapse</button>'
        '<span class="filter-count" id="f-count"></span>'
        '</div>'
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def report_html(
    findings: list[Finding],
    score_result: ScoreResult,
    region: str = "",
    target: str = "",
    output_path: str | None = None,
    chains: list[Chain] | None = None,
) -> str:
    """Generate a self-contained HTML security report.

    Returns the HTML string. When *output_path* is provided the report is
    also written to that file. When *chains* is supplied an Attack Chains
    section is rendered immediately after the score card, it's the
    highest-signal artifact in the report.
    """
    rules = _load_rules()
    grade = score_result["grade"]
    score = score_result["score"]
    summary = score_result.get("summary", {})

    grade_color = _GRADE_COLOR.get(grade, "#6c757d")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    meta_parts: list[str] = []
    if region:
        meta_parts.append(f"Region: {_e(region)}")
    if target:
        meta_parts.append(f"Target: {_e(target)}")
    meta_parts.append(f"Scanned: {now}")
    meta_str = " &nbsp;·&nbsp; ".join(meta_parts)

    total = len(findings)
    failed = sum(1 for f in findings if not f.passed)
    passed_count = total - failed

    sorted_findings = sorted(
        findings,
        key=lambda f: (f.passed, -severity_rank(f.severity), f.check_id),
    )

    rows_html = "".join(_finding_row(f, rules.get(f.check_id, {})) for f in sorted_findings)
    summary_html = _severity_summary_html(summary)
    filter_bar_html = _filter_bar_html(findings)
    chains_html = _chains_section_html(chains) if chains else ""
    blast_radius_html = _blast_radius_section_html(findings)

    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PipelineCheck Security Report</title>
  <style>{_CSS}</style>
</head>
<body>

<header>
  <div class="header-inner">
    <div>
      <h1>PipelineCheck<span class="header-sub">CI/CD Security Report</span></h1>
    </div>
    <div style="display:flex;align-items:center;gap:12px">
      <div class="header-meta">{meta_str}</div>
      <button class="theme-toggle" type="button" aria-label="Toggle dark mode">dark/light</button>
    </div>
  </div>
</header>

<main>
  <div class="score-card">
    <div class="grade-block" style="border-color:{grade_color};color:{grade_color}">
      <div class="grade-letter">{_e(grade)}</div>
      <div class="grade-score">{score}<span class="grade-denom">/100</span></div>
    </div>
    <div class="score-detail">
      <div class="count-row">
        <span class="c-fail">{failed} failed</span>
        <span class="c-sep">/</span>
        <span class="c-pass">{passed_count} passed</span>
        <span class="c-total">({total} total)</span>
      </div>
      <div class="score-bar-track">
        <div class="score-bar-fill" style="width:{score}%;background:{grade_color}"></div>
      </div>
      {summary_html}
    </div>
  </div>

  {chains_html}

  {blast_radius_html}

  {filter_bar_html}

  <table class="findings-table">
    <thead>
      <tr>
        <th>ID</th>
        <th>Severity</th>
        <th>Status</th>
        <th>Resource</th>
        <th>Check</th>
      </tr>
    </thead>
    <tbody>
{rows_html}    </tbody>
  </table>
</main>

<footer>
  <p>Generated by <strong>PipelineCheck</strong> &mdash; OWASP Top 10 CI/CD Security Risks</p>
</footer>

<script>{_SCRIPT}</script>
</body>
</html>"""

    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")

    return content
