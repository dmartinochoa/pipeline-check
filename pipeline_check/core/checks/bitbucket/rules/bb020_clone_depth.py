"""BB-020 — full clone exposes entire repository history to pipeline."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="BB-020",
    title="Full clone depth exposes complete history",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV",),
    recommendation=(
        "Set `clone: depth: 1` (or a small number) in pipeline or "
        "step options to limit the amount of repository history "
        "available in the build environment. Full clones make it "
        "easier to extract secrets that were committed and later "
        "removed."
    ),
    docs_note=(
        "By default Bitbucket Pipelines clone with `depth: 50`. "
        "Setting `depth: full` exposes the entire commit history, "
        "including any secrets that were committed and later removed. "
        "This check flags explicit `clone: depth: full` settings."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    clone = doc.get("clone")
    full_clone = False
    if isinstance(clone, dict):
        depth = clone.get("depth")
        if depth == "full" or (isinstance(depth, str) and depth.lower() == "full"):
            full_clone = True
    passed = not full_clone
    desc = (
        "Pipeline does not use full clone depth."
        if passed
        else "Pipeline sets `clone: depth: full`, exposing the entire "
        "repository history including previously committed secrets."
    )
    return Finding(
        check_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        resource=path,
        description=desc,
        recommendation=RULE.recommendation,
        passed=passed,
    )
