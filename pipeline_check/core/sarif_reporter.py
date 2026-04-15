"""SARIF 2.1.0 reporter.

SARIF (Static Analysis Results Interchange Format) is the OASIS standard
consumed by GitHub Advanced Security, GitLab SAST, Azure DevOps, and
every major SAST aggregator. Emitting SARIF turns pipeline_check findings
into code-scanning alerts inline on pull requests without any custom
integration.

Key shape notes:

- Only **failed** findings become ``results`` — SARIF's convention is
  that a rule with no results is a passing / not-triggered check.
- Every distinct ``check_id`` is declared once under
  ``runs[0].tool.driver.rules`` with its title, description, help, and
  default severity. Results then reference rules by index + id.
- Severity is expressed two ways: the enum ``level`` (error/warning/note)
  for UI coloring, and the floating-point ``security-severity``
  (0–10 CVSS-style) that GitHub uses to filter code-scanning alerts.
- Compliance controls attached by the Scanner are surfaced via
  ``properties.tags`` (so they are searchable in the GitHub UI) and
  ``properties.controls`` (structured form for programmatic consumers).
"""
from __future__ import annotations

import json

from .checks.base import Finding, Severity


_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_TOOL_URI = "https://github.com/dnlmrtn/pipeline-check"


# Severity → (SARIF level, GitHub security-severity score).
#
# ``level`` drives the UI coloring and is one of error / warning / note.
# ``security-severity`` is a 0.0–10.0 numeric that GitHub's code scanning
# alert filters use. Keep these rankings consistent with the CLI's
# --severity-threshold ordering in base.py.
_LEVEL_MAP: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("error", "9.5"),
    Severity.HIGH:     ("error", "7.5"),
    Severity.MEDIUM:   ("warning", "5.5"),
    Severity.LOW:      ("warning", "3.0"),
    Severity.INFO:     ("note", "1.0"),
}


def report_sarif(
    findings: list[Finding],
    score_result: dict,
    tool_version: str = "",
) -> str:
    """Serialise findings to a SARIF 2.1.0 JSON string.

    Parameters
    ----------
    findings:
        The full set of findings from the scanner — both passed and
        failed. Passed findings are used to complete the rule catalogue
        but do not emit results.
    score_result:
        The dict returned by ``score()``. Surfaced as run-level
        ``properties`` so SARIF consumers can filter by overall grade.
    tool_version:
        Version string to embed as ``driver.version``. Pass
        ``pipeline_check.__version__`` from the CLI.
    """
    rules = _build_rules(findings)
    rule_index = {rule["id"]: idx for idx, rule in enumerate(rules)}

    results = [_finding_to_result(f, rule_index) for f in findings if not f.passed]

    payload = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pipeline_check",
                        "version": tool_version or "0.0.0",
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "score": score_result,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2)


# ────────────────────────────────────────────────────────────────────────────
# Internals
# ────────────────────────────────────────────────────────────────────────────


def _build_rules(findings: list[Finding]) -> list[dict]:
    """Build one rule per distinct check_id.

    Severity + help text are taken from the first occurrence. Later
    findings with the same check_id reuse the rule; they may differ in
    their per-resource description, which lives on the result, not the
    rule.
    """
    seen: dict[str, dict] = {}
    for f in findings:
        if f.check_id in seen:
            continue
        level, score = _LEVEL_MAP.get(f.severity, ("warning", "5.0"))
        # Tags: "security" + the standard slugs this check maps to.
        # Control IDs are NOT included here — GitHub code-scanning caps
        # tags per rule at 20, and structured control data is already
        # exposed via ``properties.controls`` for programmatic consumers.
        standard_tags = sorted({c.standard for c in f.controls})
        tags = ["security", *standard_tags][:20]
        seen[f.check_id] = {
            "id": f.check_id,
            "name": _rule_name(f.check_id, f.title),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.title},
            "help": {
                "text": f.recommendation,
                "markdown": f"**Recommendation**\n\n{f.recommendation}",
            },
            "defaultConfiguration": {"level": level},
            "properties": {
                "security-severity": score,
                "tags": tags,
            },
        }
    return list(seen.values())


def _finding_to_result(f: Finding, rule_index: dict[str, int]) -> dict:
    level, _ = _LEVEL_MAP.get(f.severity, ("warning", "5.0"))
    result: dict = {
        "ruleId": f.check_id,
        "ruleIndex": rule_index.get(f.check_id, 0),
        "level": level,
        "message": {"text": f.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(f.resource)},
                },
                "logicalLocations": [
                    {"name": f.resource, "kind": "resource"},
                ],
            }
        ],
        "properties": {
            "severity": f.severity.value,
            "controls": [c.to_dict() for c in f.controls],
        },
    }
    return result


def _rule_name(check_id: str, title: str) -> str:
    """Derive a CamelCase SARIF rule name from the title.

    SARIF requires ``name`` to be a *stable* identifier distinct from
    ``id``. We build it from the title by stripping non-alphanumerics and
    camel-casing — this is stable as long as titles don't change and is
    readable in UIs that show rule names.
    """
    parts = [p for p in _split_title(title) if p]
    if not parts:
        return check_id.replace("-", "")
    return "".join(p[:1].upper() + p[1:].lower() for p in parts)


def _split_title(title: str) -> list[str]:
    # Splits on any non-alphanumeric; empty segments are dropped downstream.
    out: list[str] = []
    cur: list[str] = []
    for ch in title:
        if ch.isalnum():
            cur.append(ch)
        else:
            if cur:
                out.append("".join(cur))
                cur = []
    if cur:
        out.append("".join(cur))
    return out


def _artifact_uri(resource: str) -> str:
    """Best-effort mapping from a finding's resource handle to a SARIF URI.

    For file-based providers (GitHub / GitLab / Bitbucket) the resource
    is already a path. For AWS / Terraform it is a resource name (e.g.
    an ARN or bucket name) — we encode those as ``resource://<name>`` so
    SARIF consumers treat them as opaque identifiers rather than trying
    to open a file on disk.
    """
    if not resource:
        return "unknown"
    # Heuristic: anything that contains a path separator, starts with a
    # drive letter, or ends in .yml/.yaml/.tf/.json is probably a file.
    lowered = resource.lower()
    if (
        "/" in resource or "\\" in resource
        or lowered.endswith((".yml", ".yaml", ".tf", ".json"))
    ):
        return resource.replace("\\", "/")
    return f"resource:///{resource}"
