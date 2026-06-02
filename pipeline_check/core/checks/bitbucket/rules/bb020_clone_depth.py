"""BB-020, full clone exposes entire repository history to pipeline."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps

RULE = Rule(
    id="BB-020",
    title="Full clone depth exposes complete history",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV",),
    cwe=("CWE-250",),
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
        "This check flags explicit `clone: depth: full` settings at the "
        "top level or inside individual steps."
    ),
)


def _is_full_depth(clone: object) -> bool:
    """Return True when a clone block has depth: full (case-insensitive)."""
    if not isinstance(clone, dict):
        return False
    depth = clone.get("depth")
    return isinstance(depth, str) and depth.lower() == "full"


def check(path: str, doc: dict[str, Any]) -> Finding:
    # Check top-level clone block.
    full_clone = _is_full_depth(doc.get("clone"))

    # Also check step-level clone overrides.
    if not full_clone:
        for _loc, step in iter_steps(doc):
            if _is_full_depth(step.get("clone")):
                full_clone = True
                break

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
