"""CI gate — turn a scan result into a pass/fail decision with nuance.

Historically ``pipeline_check`` failed CI only when the overall grade
reached D. That's too coarse for real pipelines: a single new CRITICAL
finding should block a merge even if the score average still rounds to
a B, and teams adopting the tool on a legacy repo need to gate only on
*new* regressions rather than the existing baseline.

This module layers six orthogonal gate conditions on top of a raw
finding list. Any tripped condition fails the gate (logical OR).

Condition          Flag                 Fails the gate when…
-----------------  -------------------  -----------------------------------
Severity threshold --fail-on SEV        any effective finding's severity ≥ SEV
Grade threshold    --min-grade A|B|C|D  overall grade is worse than the bar
Count cap          --max-failures N     more than N effective failing findings
Specific check     --fail-on-check ID   a named check is in the effective set

**Default gate when no condition is set:** ``--fail-on CRITICAL``. This
is a deliberate change from earlier versions, which defaulted to "fail
iff grade == D". The severity-based default is simpler, strictly tighter
on the dimension that matters most (a CRITICAL finding should never
pass silently regardless of overall grade), and matches how tools like
Trivy, Grype, and ``npm audit`` behave. Loosen with ``--fail-on
NEVER``-equivalent approaches (e.g. ``--max-failures 999999``) or
tighten with ``--fail-on HIGH``.

"Effective findings" are the failing findings after two subtractive
filters:

- **Baseline** (``--baseline path.json``) — a previously emitted JSON
  report. Any ``(check_id, resource)`` pair already failing in the
  baseline is excluded from gate evaluation. They are still rendered in
  reports, so teams see them, but they don't block new commits.
- **Ignore file** (``--ignore-file path``) — curated suppressions for
  accepted tech debt. Each line is either ``CHECK_ID`` (suppress
  everywhere) or ``CHECK_ID:RESOURCE`` (suppress for an exact resource
  match). ``#`` starts a comment. A sensible default path of
  ``.pipelinecheckignore`` is picked up automatically when present.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .checks.base import Finding, Severity, severity_rank


# Grade ordering — A is best, D is worst. Kept inline rather than imported
# from the scorer so this module has no upward coupling.
_GRADES = ("A", "B", "C", "D")


@dataclass(frozen=True)
class IgnoreRule:
    """One line of an ignore file."""

    check_id: str           # upper-cased
    resource: str | None    # exact match; None means any resource


@dataclass
class GateConfig:
    """All knobs the CI gate understands. None/empty means 'not applied'."""

    fail_on: Severity | None = None
    min_grade: str | None = None          # "A" / "B" / "C" / "D"
    max_failures: int | None = None
    fail_on_checks: set[str] = field(default_factory=set)
    baseline_path: str | None = None
    ignore_rules: list[IgnoreRule] = field(default_factory=list)

    def any_explicit_gate(self) -> bool:
        """True when at least one gate condition is explicitly configured.

        Callers use this to decide whether to fall back to the legacy
        'grade D → fail' default.
        """
        return bool(
            self.fail_on
            or self.min_grade
            or self.max_failures is not None
            or self.fail_on_checks
        )


@dataclass
class GateResult:
    """Outcome of ``evaluate_gate``."""

    passed: bool
    #: Human-readable reasons the gate failed. Empty on pass.
    reasons: list[str]
    #: Failing findings after baseline + ignore filtering — the set the
    #: gate conditions were evaluated against.
    effective: list[Finding]
    #: Failing findings suppressed by the ignore file.
    suppressed: list[Finding]
    #: Failing findings already present in the baseline.
    baseline_matched: list[Finding]

    @property
    def exit_code(self) -> int:
        return 0 if self.passed else 1


# ────────────────────────────────────────────────────────────────────────────
# Ignore-file and baseline loading
# ────────────────────────────────────────────────────────────────────────────


def load_ignore_file(path: str | Path) -> list[IgnoreRule]:
    """Parse an ignore file into a list of :class:`IgnoreRule`.

    Missing files return an empty list (common case — the flag is set
    pointing at an optional default path). Malformed lines are skipped
    rather than erroring, so a stray blank or comment can't brick CI.
    """
    p = Path(path)
    if not p.exists():
        return []
    rules: list[IgnoreRule] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" in line:
            check_id, resource = line.split(":", 1)
            rules.append(IgnoreRule(check_id=check_id.strip().upper(),
                                    resource=resource.strip()))
        else:
            rules.append(IgnoreRule(check_id=line.strip().upper(),
                                    resource=None))
    return rules


def load_baseline(path: str | Path) -> set[tuple[str, str]]:
    """Load a prior JSON report and return the set of ``(check_id, resource)``
    pairs that failed in it.

    A missing file or a malformed document yields an empty set rather
    than raising — the common case is "first run, no baseline yet" and
    we don't want that to crash CI.
    """
    p = Path(path)
    if not p.exists():
        return set()
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    out: set[tuple[str, str]] = set()
    for f in doc.get("findings", []):
        if not f.get("passed", True):
            out.add((str(f.get("check_id", "")).upper(),
                     str(f.get("resource", ""))))
    return out


# ────────────────────────────────────────────────────────────────────────────
# Gate evaluation
# ────────────────────────────────────────────────────────────────────────────


def _is_ignored(f: Finding, rules: Iterable[IgnoreRule]) -> bool:
    for r in rules:
        if r.check_id != f.check_id.upper():
            continue
        if r.resource is None or r.resource == f.resource:
            return True
    return False


def evaluate_gate(
    findings: list[Finding],
    score_result: dict,
    config: GateConfig,
) -> GateResult:
    """Apply ``config`` to the scan's findings + score and decide pass/fail.

    When ``config.any_explicit_gate()`` is false and no baseline/ignore
    filtering is in play, the legacy default kicks in: fail iff
    ``score_result['grade'] == 'D'``. This preserves prior behavior.
    """
    failing = [f for f in findings if not f.passed]

    # Filter: baseline
    baseline_pairs = (
        load_baseline(config.baseline_path)
        if config.baseline_path else set()
    )
    baseline_matched: list[Finding] = []
    after_baseline: list[Finding] = []
    for f in failing:
        if (f.check_id.upper(), f.resource) in baseline_pairs:
            baseline_matched.append(f)
        else:
            after_baseline.append(f)

    # Filter: ignore rules
    suppressed: list[Finding] = []
    effective: list[Finding] = []
    for f in after_baseline:
        if _is_ignored(f, config.ignore_rules):
            suppressed.append(f)
        else:
            effective.append(f)

    # Evaluate conditions. If no explicit gate was configured, default to
    # --fail-on CRITICAL so a CRITICAL finding never passes silently.
    reasons: list[str] = []
    fail_on = config.fail_on
    fail_on_is_default = False
    if fail_on is None and not config.any_explicit_gate():
        fail_on = Severity.CRITICAL
        fail_on_is_default = True

    if fail_on is not None:
        threshold = severity_rank(fail_on)
        tripping = [f for f in effective if severity_rank(f.severity) >= threshold]
        if tripping:
            by_sev = sorted({f.severity.value for f in tripping})
            suffix = "default gate" if fail_on_is_default else f"--fail-on {fail_on.value}"
            reasons.append(
                f"{len(tripping)} finding(s) at or above "
                f"{fail_on.value} ({', '.join(by_sev)}) — {suffix}"
            )

    if config.min_grade:
        grade = score_result.get("grade", "D")
        if _grade_worse_than(grade, config.min_grade):
            reasons.append(
                f"Grade {grade} is worse than --min-grade {config.min_grade}"
            )

    if config.max_failures is not None and len(effective) > config.max_failures:
        reasons.append(
            f"{len(effective)} failing findings exceed --max-failures "
            f"{config.max_failures}"
        )

    if config.fail_on_checks:
        tripped = sorted(
            {f.check_id for f in effective if f.check_id.upper() in config.fail_on_checks}
        )
        if tripped:
            reasons.append(
                f"Disallowed check(s) failed: {', '.join(tripped)} — "
                f"--fail-on-check"
            )

    return GateResult(
        passed=not reasons,
        reasons=reasons,
        effective=effective,
        suppressed=suppressed,
        baseline_matched=baseline_matched,
    )


def _grade_worse_than(actual: str, bar: str) -> bool:
    """A grade ``actual`` is worse than ``bar`` if it comes later in A→D."""
    try:
        return _GRADES.index(actual) > _GRADES.index(bar)
    except ValueError:
        # Unknown grade — treat as worst.
        return True
