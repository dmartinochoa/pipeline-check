"""Scoring and grading logic.

Scoring model
-------------
Each check is weighted by severity:
    CRITICAL = 20 points
    HIGH     = 10 points
    MEDIUM   =  5 points
    LOW      =  2 points
    INFO     =  0 points  (informational, does not affect score)

Base score = (sum of weights for *passing* checks) / (sum of all weights) * 100

On top of that, each CRITICAL failure deducts an additional 5 points to ensure
that a single critical failure cannot be masked by a large number of low-severity
passes.

Final score is clamped to [0, 100] and mapped to a letter grade:
    A  >= 90
    B  >= 75
    C  >= 60
    D  < 60
"""

from typing import TypedDict

from .checks.base import Finding, Severity


class ScoreResult(TypedDict):
    score: int
    grade: str
    summary: dict[str, dict[str, int]]

_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

_CRITICAL_PENALTY = 5  # extra points deducted per CRITICAL failure


def score(findings: list[Finding]) -> ScoreResult:
    """Compute the overall security score and grade.

    Returns a dict with keys:
        score   int   0-100
        grade   str   A | B | C | D
        summary dict  {severity_str: {passed: int, failed: int}}
    """
    summary: dict[str, dict[str, int]] = {
        s.value: {"passed": 0, "failed": 0} for s in Severity
    }

    total_weight = 0
    passing_weight = 0
    critical_failures = 0

    for f in findings:
        bucket = "passed" if f.passed else "failed"
        summary[f.severity.value][bucket] += 1

        w = _WEIGHTS[f.severity]
        total_weight += w
        if f.passed:
            passing_weight += w
        elif f.severity is Severity.CRITICAL:
            critical_failures += 1

    if total_weight == 0:
        # Only INFO findings (weight 0) or no findings at all.
        raw = 100.0
    else:
        raw = (passing_weight / total_weight) * 100.0

    raw -= critical_failures * _CRITICAL_PENALTY
    final = max(0, min(100, round(raw)))

    if final >= 90:
        grade = "A"
    elif final >= 75:
        grade = "B"
    elif final >= 60:
        grade = "C"
    else:
        grade = "D"

    return {
        "score": final,
        "grade": grade,
        "summary": summary,
    }
