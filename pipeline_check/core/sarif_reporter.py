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
        rule_props: dict = {
            "security-severity": score,
            "tags": tags,
        }
        if f.cwe:
            rule_props["cwe"] = list(f.cwe)
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
            "properties": rule_props,
        }
    return list(seen.values())


def _finding_to_result(f: Finding, rule_index: dict[str, int]) -> dict:
    level, _ = _LEVEL_MAP.get(f.severity, ("warning", "5.0"))
    physical_location: dict = {
        "artifactLocation": {"uri": _artifact_uri(f.resource)},
    }
    # Best-effort line number: for file-based findings we try to grep
    # the resource content for a signature line per check_id. This
    # makes GitHub PR annotations land on the offending line instead
    # of the file header. When we can't determine a line (AWS/Terraform
    # or unreadable file) we omit the region entirely — GitHub handles
    # a missing region fine, a wrong one looks like a bug.
    start_line = _best_effort_line(f)
    if start_line is not None:
        physical_location["region"] = {"startLine": start_line}

    logical_location: dict = {"name": f.resource, "kind": "resource"}
    # AWS resources: surface an ARN/region property so programmatic
    # SARIF consumers can pivot to the console.
    arn = _aws_arn(f.resource)
    if arn:
        logical_location["fullyQualifiedName"] = arn

    properties: dict = {
        "severity": f.severity.value,
        "controls": [c.to_dict() for c in f.controls],
    }
    if f.cwe:
        properties["cwe"] = list(f.cwe)
    if arn:
        properties["arn"] = arn
        properties["region"] = _region_from_arn(arn) or ""

    result: dict = {
        "ruleId": f.check_id,
        "ruleIndex": rule_index.get(f.check_id, 0),
        "level": level,
        "message": {"text": f.description},
        "locations": [
            {
                "physicalLocation": physical_location,
                "logicalLocations": [logical_location],
            }
        ],
        "properties": properties,
    }
    return result


def _best_effort_line(f: Finding) -> int | None:
    """Try to find a line number in ``f.resource`` the finding refers to.

    Strategy: only run on file-based findings (resource looks like a
    path, file exists, is small enough to read). Match by check_id —
    e.g. GHA-001 looks for a tag-pinned ``uses:`` line, GHA-008 looks
    for a credential-shaped token. When no pattern matches we return
    None so the SARIF consumer falls back to whole-file annotation.
    """
    import os
    import re as _re

    from .checks._patterns import SECRET_VALUE_RE

    path = f.resource
    if not path or not isinstance(path, str):
        return None
    # Avoid pathologically large files and AWS resource names.
    try:
        if not os.path.isfile(path):
            return None
        if os.path.getsize(path) > 256 * 1024:
            return None
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError):
        return None

    check_id = f.check_id.upper()
    # Per-check line signatures. Return the 1-based line number of the
    # first match. Missing patterns mean "don't annotate a specific
    # line" — caller falls back to file-level.
    patterns: dict[str, _re.Pattern[str]] = {
        "GHA-001": _re.compile(r"\buses:\s*\S+@(?!\s*[0-9a-f]{40}\b)\S+"),
        "GHA-002": _re.compile(r"pull_request\.head\.(?:sha|ref)"),
        "GHA-003": _re.compile(r"\$\{\{\s*github\.event\."),
        "GL-001":  _re.compile(r"^\s*image:\s*\S+(?<!@sha256):\w+"),
        "BB-001":  _re.compile(r"^\s*-?\s*pipe:\s*\S+"),
        "ADO-001": _re.compile(r"^\s*-?\s*task:\s*\S+@\d"),
        "ADO-005": _re.compile(r"^\s*image:\s*\S+:\S+"),
    }
    pat = patterns.get(check_id)
    if pat is not None:
        for idx, line in enumerate(lines, start=1):
            if pat.search(line):
                return idx
        return None

    # Generic fallback for secret-scanning checks: first line matching
    # the built-in credential regex.
    if check_id in ("GHA-008", "GL-008", "BB-008", "ADO-008"):
        for idx, line in enumerate(lines, start=1):
            if SECRET_VALUE_RE.search(line):
                return idx
            # SECRET_VALUE_RE is anchored; also check for AKIA inline.
            if "AKIA" in line or "ghp_" in line:
                return idx
    return None


def _aws_arn(resource: str) -> str | None:
    """Return the ARN embedded in an AWS check resource, or None."""
    if isinstance(resource, str) and resource.startswith("arn:"):
        return resource
    return None


def _region_from_arn(arn: str) -> str | None:
    # arn:aws:service:region:account:resource
    try:
        parts = arn.split(":", 5)
        return parts[3] or None
    except (IndexError, AttributeError):
        return None


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
