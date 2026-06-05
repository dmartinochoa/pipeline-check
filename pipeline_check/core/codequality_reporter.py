"""GitLab Code Quality reporter.

GitLab CI renders any artifact declared as ``reports: codequality:`` as
inline MR annotations, the same way GitHub renders a SARIF upload. The
schema is the Code Climate `gl-code-quality-report` JSON format: a flat
JSON array, one object per issue, with ``description``, ``check_name``,
``severity``, ``fingerprint``, and ``location.{path,lines.begin}``.

We emit one entry per ``(failing finding, location)`` pair, so a single
aggregate finding that lists ten offending lines becomes ten MR
annotations. Findings with no structured ``locations`` fall back to
``resource``. Passing findings are skipped, the format has no "passed"
concept.

Severity mapping pipeline_check -> Code Climate:

- CRITICAL -> ``blocker``
- HIGH     -> ``critical``
- MEDIUM   -> ``major``
- LOW      -> ``minor``
- INFO     -> ``info``

The ``fingerprint`` is a SHA-1 over ``(check_id, normalized_path, line)``.
Description text is deliberately excluded so cosmetic prose tweaks across
releases (or per-run mutations like ``--verify-secrets-show-identity``)
don't churn previously-dismissed MR threads.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .checks.base import Finding, Severity, inline_exploit
from .report_view import ReportView

_SEVERITY_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "blocker",
    Severity.HIGH: "critical",
    Severity.MEDIUM: "major",
    Severity.LOW: "minor",
    Severity.INFO: "info",
}

# Sentinel path emitted when a finding has neither a structured location
# nor a usable resource string. GitLab won't match it against the MR diff,
# but the entry still surfaces in the Code Quality report rather than
# being silently dropped at serialization time.
_UNKNOWN_PATH = "unknown"


def _normalize_path(path: str) -> str:
    """Force forward-slash separators so GitLab can match against the MR diff
    when the scanner ran on a Windows runner."""
    return path.replace("\\", "/")


def _fingerprint(check_id: str, path: str, line: int | None) -> str:
    """Stable SHA-1 over the bits that identify a unique finding.

    ``usedforsecurity=False`` lets the call run on FIPS-mode hosts; the
    hash is dedupe identity, not a security primitive.
    """
    line_part = "" if line is None else str(line)
    payload = f"{check_id}|{path}|{line_part}"
    return hashlib.sha1(
        payload.encode("utf-8"), usedforsecurity=False,
    ).hexdigest()


def _issue(
    f: Finding, path: str, line: int | None, inline_explain: bool = False,
) -> dict[str, Any]:
    """Build one Code Climate issue dict for finding + location.

    With *inline_explain*, the finding's ``exploit_example`` is appended
    to ``description``. The fingerprint is over ``(check_id, path,
    line)`` only, so enriching the description never churns a
    previously-dismissed MR thread.
    """
    desc = (f.description or f.title).strip()
    exploit = inline_exploit(f, inline_explain)
    if exploit:
        desc = f"{desc}\n\nProof of exploit:\n{exploit}"
    norm_path = _normalize_path(path) if path else _UNKNOWN_PATH
    location: dict[str, Any] = {"path": norm_path}
    if line is not None:
        location["lines"] = {"begin": line}
    return {
        "description": desc,
        "check_name": f.check_id,
        "fingerprint": _fingerprint(f.check_id, norm_path, line),
        "severity": _SEVERITY_MAP.get(f.severity, "info"),
        "location": location,
    }


def report_codequality(
    findings: list[Finding], inline_explain: bool = False,
) -> str:
    """Render *findings* as a GitLab Code Quality JSON string.

    Only failing findings are emitted; passing findings have no
    representation in the format. The result is a JSON array, ready to
    drop into a GitLab job's ``artifacts.reports.codequality:`` slot.
    When *inline_explain* is set, each issue's ``description`` carries
    the finding's ``exploit_example``.
    """
    issues: list[dict[str, Any]] = []
    for f in ReportView(findings).failed:
        if f.locations:
            for loc in f.locations:
                issues.append(_issue(f, loc.path, loc.start_line, inline_explain))
        else:
            issues.append(_issue(f, f.resource, None, inline_explain))
    return json.dumps(issues, indent=2) + "\n"
