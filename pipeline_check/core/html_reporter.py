"""HTML report formatter.

Generates a self-contained HTML file — no external CDN dependencies.
YAML rule metadata is loaded from pipeline_check/core/checks/aws/rules/ when
PyYAML is installed; the report degrades gracefully without it.
"""

import html
from datetime import datetime, timezone
from pathlib import Path

from .checks.base import Finding, Severity, severity_rank

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
:root {
  --bg: #f0f2f5;
  --card: #ffffff;
  --header-bg: #1a1a2e;
  --border: #dee2e6;
  --text: #212529;
  --muted: #6c757d;
  --row-hover: #f8f9fa;
  --detail-bg: #f8f9fa;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.5;
}
a { color: inherit; }

/* ── Header ── */
header {
  background: var(--header-bg); color: #e8e8f0; padding: 14px 24px;
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
  background: var(--card); border-radius: 8px; border: 1px solid var(--border);
  padding: 24px; margin-bottom: 24px;
  display: flex; align-items: center; gap: 32px; flex-wrap: wrap;
}
.grade-block {
  text-align: center; border: 3px solid; border-radius: 8px;
  padding: 10px 22px; min-width: 96px; flex-shrink: 0;
}
.grade-letter { font-size: 46px; font-weight: 800; line-height: 1; }
.grade-score  { font-size: 18px; font-weight: 600; margin-top: 4px; }
.grade-denom  { font-size: 12px; font-weight: 400; opacity: .7; }
.score-detail { flex: 1; min-width: 0; }
.score-bar-track {
  height: 8px; background: var(--border); border-radius: 4px;
  margin: 10px 0 14px; overflow: hidden;
}
.score-bar-fill {
  height: 100%; border-radius: 4px; transition: width .3s ease;
}
.count-row    { font-size: 15px; margin-bottom: 14px; }
.c-fail  { color: #dc3545; font-weight: 600; }
.c-pass  { color: #198754; font-weight: 600; }
.c-sep   { color: var(--muted); margin: 0 4px; }
.c-total { color: var(--muted); font-size: 13px; margin-left: 4px; }
.sev-row { display: flex; gap: 10px; flex-wrap: wrap; }
.sev-pill {
  display: flex; align-items: center; gap: 5px;
  background: var(--detail-bg); border: 1px solid var(--border);
  border-radius: 20px; padding: 3px 10px; font-size: 12px;
}
.sev-dot  { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.sev-name { font-weight: 600; }
.sev-cnt  { color: var(--muted); }

/* ── Findings table ── */
.findings-table {
  width: 100%; border-collapse: collapse;
  background: var(--card); border-radius: 8px;
  border: 1px solid var(--border); overflow: hidden;
}
.findings-table thead th {
  background: #f1f3f5; text-align: left; padding: 9px 14px;
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .5px; color: var(--muted);
  border-bottom: 1px solid var(--border);
}
.findings-table tbody tr { border-bottom: 1px solid var(--border); }
.findings-table tbody tr:last-child { border-bottom: none; }
.findings-table tbody tr:hover td { background: var(--row-hover); }
.findings-table tbody td { padding: 9px 14px; vertical-align: top; }
td.td-id { border-left: 3px solid transparent; }
tr.row-fail td.td-id { border-left-color: #dc3545; }
tr.row-pass td.td-id { border-left-color: #198754; }
.check-id { font-family: monospace; font-weight: 600; font-size: 13px; white-space: nowrap; }
.resource  { font-family: monospace; font-size: 12px; color: var(--muted); word-break: break-all; max-width: 180px; }

/* ── Badges ── */
.badge {
  display: inline-block; padding: 2px 7px; border-radius: 4px;
  font-size: 11px; font-weight: 700; text-transform: uppercase; white-space: nowrap;
}
.b-critical { background:#fde8e8; color:#dc3545; }
.b-high     { background:#fef0e6; color:#c85d00; }
.b-medium   { background:#fef8e0; color:#8a5e00; }
.b-low      { background:#e7f0ff; color:#0d4fb5; }
.b-info     { background:#f0f0f0; color:#555; }
.b-pass     { background:#e6f4ec; color:#198754; }
.b-fail     { background:#fde8e8; color:#dc3545; }

/* ── Expandable details ── */
details > summary {
  cursor: pointer; list-style: none;
  display: flex; align-items: flex-start; gap: 6px; font-weight: 500;
}
details > summary::-webkit-details-marker { display: none; }
details > summary::before {
  content: "▶"; font-size: 9px; color: var(--muted);
  margin-top: 3px; flex-shrink: 0; transition: transform .15s;
}
details[open] > summary::before { transform: rotate(90deg); }
.check-detail {
  margin-top: 10px; padding: 14px; border-radius: 6px;
  background: var(--detail-bg); border-left: 3px solid var(--border); font-size: 13px;
}
.d-section { margin-bottom: 12px; }
.d-section:last-child { margin-bottom: 0; }
.d-label {
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .6px; color: var(--muted); margin-bottom: 3px;
}
.d-value ul { margin: 4px 0 0 16px; }
.d-value li { margin-bottom: 3px; }
.owasp-tag {
  display: inline-block; background: #eef0fb; color: #3f4faa;
  padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;
}

/* ── Filter bar ── */
.filter-bar {
  background: var(--card); border: 1px solid var(--border); border-radius: 8px;
  padding: 10px 14px; margin-bottom: 14px;
  display: flex; gap: 14px; flex-wrap: wrap; align-items: center; font-size: 13px;
}
.filter-group { display: flex; align-items: center; gap: 6px; }
.filter-group label { font-weight: 600; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .5px; }
.filter-group select { padding: 4px 8px; border: 1px solid var(--border); border-radius: 4px; font-size: 13px; background: var(--card); }
.filter-group input[type=text] { padding: 4px 8px; border: 1px solid var(--border); border-radius: 4px; font-size: 13px; min-width: 180px; }
.filter-count { color: var(--muted); font-size: 12px; margin-left: auto; }

/* ── Copy-ignore button ── */
.copy-ignore-btn {
  float: right; margin-left: 8px;
  border: 1px solid var(--border); background: var(--card);
  border-radius: 4px; padding: 2px 8px; font-size: 11px; cursor: pointer;
  color: var(--muted); font-family: monospace;
}
.copy-ignore-btn:hover { background: var(--row-hover); }
.copy-ignore-btn.copied { background: #e6f4ec; color: #198754; border-color: #198754; }

/* ── Dark mode ── */
.dark {
  --bg: #1a1a2e; --card: #16213e; --header-bg: #0f0f23;
  --border: #2a2a4a; --text: #e0e0e8; --muted: #8888aa;
  --row-hover: #1e2a4a; --detail-bg: #12203a;
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

/* ── Footer ── */
footer { text-align: center; padding: 24px; color: var(--muted); font-size: 12px; }
"""


_SCRIPT = r"""
(function () {
  const rows = document.querySelectorAll('tbody tr[data-check-id]');
  const sev = document.getElementById('f-sev');
  const std = document.getElementById('f-std');
  const prov = document.getElementById('f-prov');
  const stat = document.getElementById('f-status');
  const text = document.getElementById('f-text');
  const count = document.getElementById('f-count');

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
  }

  [sev, std, prov, stat].forEach(el => el.addEventListener('change', apply));
  text.addEventListener('input', apply);
  visibleCount();

  document.querySelectorAll('.copy-ignore-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const rule = btn.dataset.rule;
      try {
        await navigator.clipboard.writeText(rule);
        btn.textContent = '✓ copied';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = btn.dataset.label;
          btn.classList.remove('copied');
        }, 1500);
      } catch (err) {
        console.warn('clipboard failed', err);
      }
    });
  });
})();
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_rules() -> dict[str, dict]:
    """Load YAML rule definitions indexed by check_id. Returns {} if unavailable.

    Parse errors are logged to stderr rather than silently swallowed —
    a malformed rule YAML is a real maintenance problem that should be
    visible to the operator, even if we still render the report.
    """
    import sys
    if not _YAML_AVAILABLE or not _RULES_DIR.exists():
        return {}
    rules: dict[str, dict] = {}
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


def _severity_badge(severity: Severity) -> str:
    cls = f"b-{severity.value.lower()}"
    return f'<span class="badge {cls}">{_e(severity.value)}</span>'


def _status_badge(passed: bool) -> str:
    return (
        '<span class="badge b-pass">PASS</span>'
        if passed else
        '<span class="badge b-fail">FAIL</span>'
    )


def _severity_summary_html(summary: dict) -> str:
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


_PROVIDER_PREFIXES = {
    "GHA": "github", "GL": "gitlab", "BB": "bitbucket", "ADO": "azure",
    "JF": "jenkins", "CC": "circleci",
    "CB": "aws", "CP": "aws", "CD": "aws", "IAM": "aws", "S3": "aws",
    "ECR": "aws", "PBAC": "aws",
    "TF": "terraform",
}


def _provider_for(check_id: str) -> str:
    prefix = check_id.split("-", 1)[0].upper()
    return _PROVIDER_PREFIXES.get(prefix, "other")


def _finding_row(finding: Finding, rule: dict) -> str:
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

    # Recommended actions — prefer structured list from YAML, fall back to Finding string
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

    # Compliance controls — one tag per ControlRef, grouped by standard.
    if finding.controls:
        by_std: dict[str, list] = {}
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
    # Haystack for free-text filter; include the visible summary text
    # but NOT the detail sections (keeps matches predictable).
    haystack = f"{finding.check_id} {finding.title} {finding.resource}".lower()
    # Ignore-rule the copy button will drop into the clipboard:
    # ``CHECK_ID:RESOURCE`` — the flat format the gate accepts.
    ignore_rule = f"{finding.check_id}:{finding.resource}"

    return (
        f'<tr class="{row_cls}" '
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
        '<input id="f-text" type="text" placeholder="Filter by id, title, resource..." />'
        '</div>'
        '<span class="filter-count" id="f-count"></span>'
        '</div>'
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def report_html(
    findings: list[Finding],
    score_result: dict,
    region: str = "",
    target: str = "",
    output_path: str | None = None,
) -> str:
    """Generate a self-contained HTML security report.

    Returns the HTML string. When *output_path* is provided the report is
    also written to that file.
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
      <button class="theme-toggle" onclick="document.body.classList.toggle('dark')">dark/light</button>
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
