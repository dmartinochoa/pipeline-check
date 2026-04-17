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

import datetime as _dt
import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .checks.base import Finding, Severity, severity_rank

# Grade ordering — A is best, D is worst. Kept inline rather than imported
# from the scorer so this module has no upward coupling.
_GRADES = ("A", "B", "C", "D")


@dataclass(frozen=True)
class IgnoreRule:
    """One line of an ignore file.

    Suppressions can carry an ``expires`` date (YAML format only). Once
    the date is in the past, ``is_expired`` returns True and callers
    skip the rule so suppressions can't rot silently. The flat-text
    format has no expiry field — those rules never expire.
    """

    check_id: str           # upper-cased
    resource: str | None    # exact match; None means any resource
    expires: _dt.date | None = None
    reason: str | None = None

    def is_expired(self, today: _dt.date | None = None) -> bool:
        if self.expires is None:
            return False
        ref = today or _dt.date.today()
        return ref > self.expires


@dataclass
class GateConfig:
    """All knobs the CI gate understands. None/empty means 'not applied'."""

    fail_on: Severity | None = None
    min_grade: str | None = None          # "A" / "B" / "C" / "D"
    max_failures: int | None = None
    fail_on_checks: set[str] = field(default_factory=set)
    baseline_path: str | None = None
    #: When set, resolve the baseline JSON from ``git show <ref>:<path>``
    #: instead of reading a file. Mutually exclusive with baseline_path
    #: at the CLI layer; if both are set here, file wins.
    baseline_from_git: tuple[str, str] | None = None  # (ref, path)
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
    #: Ignore rules whose ``expires`` date has passed. Reported to the
    #: user so stale suppressions surface instead of rotting silently.
    expired_rules: list[IgnoreRule] = field(default_factory=list)
    #: Human-readable labels for every gate condition that was evaluated.
    conditions_evaluated: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return 0 if self.passed else 1


# ────────────────────────────────────────────────────────────────────────────
# Ignore-file and baseline loading
# ────────────────────────────────────────────────────────────────────────────


def load_ignore_file(path: str | Path) -> list[IgnoreRule]:
    """Parse an ignore file into a list of :class:`IgnoreRule`.

    Two formats are supported, picked by extension:

    - ``.yml`` / ``.yaml`` — structured list of entries::

          - check_id: GHA-001
            resource: .github/workflows/release.yml
            expires: 2026-06-30
            reason: waiting on upstream Dependabot config

      ``expires`` (ISO date) is optional; once it passes the rule is
      returned but :py:meth:`IgnoreRule.is_expired` is True and
      ``evaluate_gate`` refuses to apply it. ``reason`` is metadata
      only — kept so reviewers can see the justification without
      crawling git history.

    - Anything else — the flat-text format (one ``CHECK_ID`` or
      ``CHECK_ID:RESOURCE`` per line, ``#`` for comments). No expiry
      field; rules in this format never expire.

    Missing files return an empty list rather than raising — the
    default path is optional.
    """
    p = Path(path)
    if not p.exists():
        return []
    if p.suffix.lower() in {".yml", ".yaml"}:
        return _load_ignore_yaml(p)
    return _load_ignore_flat(p)


def _load_ignore_flat(p: Path) -> list[IgnoreRule]:
    rules: list[IgnoreRule] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" in line:
            check_id, resource = line.split(":", 1)
            resource = resource.strip()
            # An empty resource (``GHA-001:`` or ``GHA-001:   ``) is the
            # user asking for a blanket suppression, equivalent to
            # writing the check id alone. Normalise to None so the rule
            # actually matches something — a literal ``""`` resource
            # would only suppress findings with an exact empty string.
            rules.append(IgnoreRule(
                check_id=check_id.strip().upper(),
                resource=resource or None,
            ))
        else:
            rules.append(IgnoreRule(check_id=line.strip().upper(),
                                    resource=None))
    return rules


class _DupKeyIgnoreLoader(yaml.SafeLoader):
    """SafeLoader for ignore files that rejects duplicate mapping keys.

    A YAML ignore-file entry with a duplicated field (e.g. two
    ``resource:`` keys under one rule) silently keeps only the last
    value under pyyaml's default behaviour. For a suppression file
    that's a trap — half the user's intent is discarded invisibly.
    """

    def construct_mapping(self, node, deep=False):  # type: ignore[override]
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                mark = key_node.start_mark
                raise yaml.constructor.ConstructorError(
                    None, None,
                    f"duplicate key {key!r} at line {mark.line + 1}, "
                    f"column {mark.column + 1}",
                    mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _load_ignore_yaml(p: Path) -> list[IgnoreRule]:
    try:
        doc = yaml.load(p.read_text(encoding="utf-8"), Loader=_DupKeyIgnoreLoader)
    except yaml.YAMLError as exc:
        # Surface the parse error — a typo here silently removes every
        # suppression and the user has no way to tell without diffing
        # findings against a prior run.
        print(
            f"[ignore-file] could not parse {p}: {exc}. No rules loaded.",
            file=sys.stderr,
        )
        return []
    except OSError as exc:
        print(
            f"[ignore-file] could not read {p}: {exc}. No rules loaded.",
            file=sys.stderr,
        )
        return []
    if not isinstance(doc, list):
        print(
            f"[ignore-file] {p} must contain a top-level list of rules; "
            f"got {type(doc).__name__}. No rules loaded.",
            file=sys.stderr,
        )
        return []
    rules: list[IgnoreRule] = []
    for entry in doc:
        if not isinstance(entry, dict):
            continue
        cid = entry.get("check_id") or entry.get("id")
        if not isinstance(cid, str):
            continue
        resource = entry.get("resource")
        if resource is not None and not isinstance(resource, str):
            resource = None
        expires = _coerce_date(entry.get("expires"))
        reason = entry.get("reason")
        if reason is not None and not isinstance(reason, str):
            reason = None
        rules.append(IgnoreRule(
            check_id=cid.strip().upper(),
            resource=resource.strip() if resource else None,
            expires=expires,
            reason=reason,
        ))
    return rules


def _coerce_date(value: object) -> _dt.date | None:
    if isinstance(value, _dt.date):
        return value
    if isinstance(value, str):
        try:
            return _dt.date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


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
    return _baseline_from_doc(doc)


def load_baseline_from_git(ref: str, path: str, cwd: str | Path = ".") -> set[tuple[str, str]]:
    """Load a baseline JSON report directly from ``git show <ref>:<path>``.

    This lets the gate compare against a prior commit's scan output
    without requiring the caller to check it out or restore an
    artifact by hand. Returns an empty set on any failure, mirroring
    ``load_baseline`` for file-based lookups.
    """
    from .diff import git_show
    content = git_show(ref, path, cwd=cwd)
    if content is None:
        return set()
    try:
        doc = json.loads(content)
    except json.JSONDecodeError:
        return set()
    return _baseline_from_doc(doc)


def _baseline_from_doc(doc: object) -> set[tuple[str, str]]:
    """Extract failing ``(check_id, resource)`` pairs from a baseline doc.

    Defensive: the baseline JSON comes from whatever the user hands us
    — an old scan, a hand-edited file, or a completely unrelated JSON.
    Every downstream caller (``load_baseline``, ``load_baseline_from_git``)
    already catches parse errors, so any *shape* error here must return
    an empty set rather than crashing CI.
    """
    out: set[tuple[str, str]] = set()
    if not isinstance(doc, dict):
        return out
    findings = doc.get("findings")
    if not isinstance(findings, list):
        return out
    for f in findings:
        if not isinstance(f, dict):
            continue
        if not f.get("passed", True):
            out.add((str(f.get("check_id", "")).upper(),
                     str(f.get("resource", ""))))
    return out


# ────────────────────────────────────────────────────────────────────────────
# Gate evaluation
# ────────────────────────────────────────────────────────────────────────────


def _is_ignored(f: Finding, rules: Iterable[IgnoreRule], today: _dt.date) -> bool:
    for r in rules:
        if r.is_expired(today):
            continue
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

    # Filter: baseline — file wins over git-ref when both set.
    if config.baseline_path:
        baseline_pairs = load_baseline(config.baseline_path)
    elif config.baseline_from_git:
        ref, path = config.baseline_from_git
        baseline_pairs = load_baseline_from_git(ref, path)
    else:
        baseline_pairs = set()
    baseline_matched: list[Finding] = []
    after_baseline: list[Finding] = []
    for f in failing:
        if (f.check_id.upper(), f.resource) in baseline_pairs:
            baseline_matched.append(f)
        else:
            after_baseline.append(f)

    # Filter: ignore rules. Cache today's date so the expiry check
    # doesn't invoke the clock once per (rule, finding) pair.
    today = _dt.date.today()
    suppressed: list[Finding] = []
    effective: list[Finding] = []
    for f in after_baseline:
        if _is_ignored(f, config.ignore_rules, today):
            suppressed.append(f)
        else:
            effective.append(f)

    # Evaluate conditions. If no explicit gate was configured, default to
    # --fail-on CRITICAL so a CRITICAL finding never passes silently.
    reasons: list[str] = []
    conditions: list[str] = []
    fail_on = config.fail_on
    fail_on_is_default = False
    if fail_on is None and not config.any_explicit_gate():
        fail_on = Severity.CRITICAL
        fail_on_is_default = True

    if fail_on is not None:
        suffix = "default gate" if fail_on_is_default else "--fail-on"
        threshold = severity_rank(fail_on)
        tripping = [f for f in effective if severity_rank(f.severity) >= threshold]
        if tripping:
            by_sev = sorted({f.severity.value for f in tripping})
            reasons.append(
                f"{len(tripping)} finding(s) at or above "
                f"{fail_on.value} ({', '.join(by_sev)}) — {suffix}"
            )
        conditions.append(f"severity < {fail_on.value} — {suffix}")

    if config.min_grade:
        grade = score_result.get("grade", "D")
        conditions.append(f"grade >= {config.min_grade} — --min-grade")
        if _grade_worse_than(grade, config.min_grade):
            reasons.append(
                f"Grade {grade} is worse than --min-grade {config.min_grade}"
            )

    if config.max_failures is not None:
        conditions.append(f"failures <= {config.max_failures} — --max-failures")
        if len(effective) > config.max_failures:
            reasons.append(
                f"{len(effective)} failing findings exceed --max-failures "
                f"{config.max_failures}"
            )

    if config.fail_on_checks:
        ids = ", ".join(sorted(config.fail_on_checks))
        conditions.append(f"disallowed checks: {ids} — --fail-on-check")
        tripped = sorted(
            {f.check_id for f in effective if f.check_id.upper() in config.fail_on_checks}
        )
        if tripped:
            reasons.append(
                f"Disallowed check(s) failed: {', '.join(tripped)} — "
                f"--fail-on-check"
            )

    expired_rules = [r for r in config.ignore_rules if r.is_expired(today)]

    return GateResult(
        passed=not reasons,
        reasons=reasons,
        effective=effective,
        suppressed=suppressed,
        baseline_matched=baseline_matched,
        expired_rules=expired_rules,
        conditions_evaluated=conditions,
    )


def _grade_worse_than(actual: str, bar: str) -> bool:
    """A grade ``actual`` is worse than ``bar`` if it comes later in A→D."""
    try:
        return _GRADES.index(actual) > _GRADES.index(bar)
    except ValueError:
        # Unknown grade — treat as worst.
        return True
