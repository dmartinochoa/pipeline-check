"""GCB-016. Step ``dir:`` field contains a parent-directory escape (``..``)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-016",
    title="Step dir field contains parent-directory escape (..)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7", "CICD-SEC-4"),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-22",),
    recommendation=(
        "Replace ``..`` traversals in ``dir:`` with absolute paths "
        "rooted under ``/workspace`` (e.g. ``dir: /workspace/sub``) "
        "or split the work across multiple steps that each set "
        "``dir:`` to an exact subdirectory. The Cloud Build worker "
        "starts each step with the workspace mounted at "
        "``/workspace``; a ``..`` escape from there reaches the "
        "builder image's root filesystem and any credentials the "
        "image carries."
    ),
    docs_note=(
        "Cloud Build doesn't sandbox the ``dir:`` value beyond a "
        "join against ``/workspace``. ``dir: ../etc`` resolves to "
        "``/etc`` inside the builder container, which is rarely the "
        "intent. The check fires on any literal ``..`` segment; "
        "single-dot ``./`` and absolute paths are fine."
    ),
)


def _has_escape(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.replace("\\", "/").split("/")
    return ".." in parts


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    steps = doc.get("steps")
    if isinstance(steps, list):
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            d = step.get("dir")
            if _has_escape(d):
                step_id = step.get("id") or f"steps[{idx}]"
                offenders.append(f"{step_id}: dir={d!r}")
    passed = not offenders
    desc = (
        "No step's ``dir`` field contains a parent-directory escape."
        if passed else
        f"{len(offenders)} step(s) traverse out of /workspace via "
        f"``..``: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
