"""Smart-init scan: the engine behind ``pipeline_check init``.

The plain template scaffold lives in :mod:`init_template`. This module
wraps it with a one-shot scan that fills in the gate block from real
findings instead of comments, writes a baseline file that captures
existing failures, and returns a "top N to fix first" summary the CLI
prints to stderr.

Goal: a new user runs ``pipeline_check init`` once, commits the two
generated files, and their first CI run after that is exit-0 — every
legacy finding is baselined and only new regressions block merges.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import init_template
from .checks.base import Finding, Severity, severity_rank
from .reporter import report_json
from .scorer import score as score_findings

if TYPE_CHECKING:
    from .scorer import ScoreResult


#: Default baseline filename written by ``init`` when failures exist.
DEFAULT_BASELINE_PATH = ".pipeline-check-baseline.json"

#: Default config filename written by ``init``.
DEFAULT_CONFIG_PATH = ".pipeline-check.yml"

#: How many "top to fix first" entries the CLI prints. Five fits in a
#: terminal screen without scrolling; the user can run ``--explain`` on
#: any ID to drill in.
TOP_FIX_COUNT = 5


@dataclass(frozen=True, slots=True)
class TopFinding:
    """One row in the ``init`` "top to fix" summary."""

    check_id: str
    severity: Severity
    title: str
    resource: str
    fixable: bool


@dataclass(frozen=True, slots=True)
class InitScanResult:
    """Everything the CLI needs to write artifacts and print a summary."""

    detected_pipeline: str | None
    score: int
    grade: str
    total_findings: int
    failing_findings: int
    recommended_fail_on: Severity
    has_failures: bool
    baseline_path: str
    config_yaml: str
    baseline_json: str
    top: list[TopFinding]


def _has_critical(findings: list[Finding]) -> bool:
    return any(
        not f.passed and f.severity is Severity.CRITICAL for f in findings
    )


def _pick_top(findings: list[Finding], fixers: set[str]) -> list[TopFinding]:
    """Pick up to :data:`TOP_FIX_COUNT` highest-impact failures to surface.

    Sort key: severity desc, then "has autofixer" desc (give the user a
    quick win), then check_id asc for determinism. Deduped on
    ``(check_id, resource)`` so the same finding repeated across N
    workflows doesn't crowd out other rules from the list.
    """
    failing = [f for f in findings if not f.passed]
    seen: set[tuple[str, str]] = set()
    deduped: list[Finding] = []
    for f in failing:
        key = (f.check_id.upper(), f.resource)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)

    def sort_key(f: Finding) -> tuple[int, int, str]:
        # Higher severity first, then "has fixer" first, then alpha.
        has_fix = f.check_id.upper() in fixers
        return (-severity_rank(f.severity), 0 if has_fix else 1, f.check_id)

    deduped.sort(key=sort_key)
    return [
        TopFinding(
            check_id=f.check_id,
            severity=f.severity,
            title=f.title,
            resource=f.resource,
            fixable=f.check_id.upper() in fixers,
        )
        for f in deduped[:TOP_FIX_COUNT]
    ]


def build_init_scan_result(
    findings: list[Finding],
    *,
    detected_pipeline: str | None,
    tool_version: str,
    fixers: set[str],
    baseline_path: str = DEFAULT_BASELINE_PATH,
    score_result: ScoreResult | None = None,
) -> InitScanResult:
    """Translate a finished scan into the artifacts ``init`` will write.

    Pulled out as a pure function so tests can drive it with synthetic
    findings without needing a real provider context. The CLI layer
    handles the I/O: running the scan, writing the files, and printing
    the summary.
    """
    sr = score_result if score_result is not None else score_findings(findings)
    failing = [f for f in findings if not f.passed]
    has_critical = _has_critical(findings)
    fail_on = init_template.recommend_fail_on(sr["grade"], has_critical)
    has_failures = bool(failing)

    config_yaml = init_template.render_smart(
        detected_pipeline,
        fail_on=fail_on,
        baseline_path=baseline_path,
        write_baseline=has_failures,
    )
    baseline_json = report_json(findings, sr, tool_version=tool_version)

    return InitScanResult(
        detected_pipeline=detected_pipeline,
        score=sr["score"],
        grade=sr["grade"],
        total_findings=len(findings),
        failing_findings=len(failing),
        recommended_fail_on=fail_on,
        has_failures=has_failures,
        baseline_path=baseline_path,
        config_yaml=config_yaml,
        baseline_json=baseline_json,
        top=_pick_top(findings, fixers),
    )


def parse_baseline_summary(path: str) -> tuple[int, str] | None:
    """Return ``(failing_count, grade)`` from a baseline JSON file.

    Used by the gate-failure trailer to tell the user "X new findings
    since baseline". Returns ``None`` when the file is missing or
    malformed; callers fall back to a less-specific hint.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    findings = doc.get("findings")
    if not isinstance(findings, list):
        return None
    failing = sum(
        1 for f in findings
        if isinstance(f, dict) and not f.get("passed", True)
    )
    score = doc.get("score") or {}
    grade = score.get("grade") if isinstance(score, dict) else None
    return failing, grade if isinstance(grade, str) else ""
