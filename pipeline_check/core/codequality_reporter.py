"""GitLab Code Quality reporter.

GitLab CI renders any artifact declared as ``reports: codequality:`` as
inline MR annotations, the same way GitHub renders a SARIF upload. The
schema is the Code Climate `gl-code-quality-report` JSON format: a flat
JSON array, one object per issue, with ``description``, ``check_name``,
``severity``, ``fingerprint``, and ``location.{path,lines.begin}``.

We emit one entry per ``(failing finding, location)`` pair, so a single
aggregate finding that lists ten offending lines becomes ten MR
annotations. Findings with no structured ``locations`` fall back to
``resource`` and omit ``lines``. Passing findings are skipped, the
format has no "passed" concept.

Severity mapping pipeline_check -> Code Climate:

- CRITICAL -> ``blocker``
- HIGH     -> ``critical``
- MEDIUM   -> ``major``
- LOW      -> ``minor``
- INFO     -> ``info``

The ``fingerprint`` is a SHA-1 over ``(check_id, path, line,
description)`` so identical findings across runs collide and GitLab
can hide already-flagged issues until they reappear.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .checks.base import Finding, Severity

_SEVERITY_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "blocker",
    Severity.HIGH: "critical",
    Severity.MEDIUM: "major",
    Severity.LOW: "minor",
    Severity.INFO: "info",
}


def _fingerprint(check_id: str, path: str, line: int | None, desc: str) -> str:
    """Stable SHA-1 over the bits that identify a unique finding."""
    payload = f"{check_id}|{path}|{line if line is not None else ''}|{desc}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def _issue(
    f: Finding, path: str, line: int | None,
) -> dict[str, Any]:
    """Build one Code Climate issue dict for finding + location."""
    desc = (f.description or f.title).strip()
    location: dict[str, Any] = {"path": path}
    if line is not None:
        location["lines"] = {"begin": line}
    return {
        "description": desc,
        "check_name": f.check_id,
        "fingerprint": _fingerprint(f.check_id, path, line, desc),
        "severity": _SEVERITY_MAP.get(f.severity, "info"),
        "location": location,
    }


def report_codequality(findings: list[Finding]) -> str:
    """Render *findings* as a GitLab Code Quality JSON string.

    Only failing findings are emitted; passing findings have no
    representation in the format. The result is a JSON array, ready to
    drop into a GitLab job's ``artifacts.reports.codequality:`` slot.
    """
    issues: list[dict[str, Any]] = []
    for f in findings:
        if f.passed:
            continue
        if f.locations:
            for loc in f.locations:
                issues.append(_issue(f, loc.path, loc.start_line))
        else:
            issues.append(_issue(f, f.resource or "", None))
    return json.dumps(issues, indent=2, sort_keys=False) + "\n"
