"""CI gate, turn a scan result into a pass/fail decision with nuance.

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

- **Baseline** (``--baseline path.json``), a previously emitted JSON
  report. Any ``(check_id, resource)`` pair already failing in the
  baseline is excluded from gate evaluation. They are still rendered in
  reports, so teams see them, but they don't block new commits.
- **Ignore file** (``--ignore-file path``), curated suppressions for
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

import yaml

from ._yaml_strict import DupKeyLoader as _DupKeyIgnoreLoader
from .chains import Chain
from .checks.base import Finding, Severity, severity_rank
from .inline_ignore import InlineIgnoreIndex
from .scorer import ScoreResult

# Grade ordering. A is best, D is worst. Kept inline rather than imported
# from the scorer so this module has no upward coupling.
_GRADES = ("A", "B", "C", "D")

#: Default forewarning window for soon-to-expire suppressions. An ignore
#: rule with ``expires`` within this many days of today shows up under
#: :attr:`GateResult.expiring_soon` so the operator schedules a revisit
#: before the gate flips. Two-week default chosen so a Friday afternoon
#: scan still gives the team a sprint's notice. Tunable per-run via
#: ``--warn-expiring-suppressions`` (see :func:`parse_expiry_window`).
EXPIRY_WARNING_DAYS = 14

#: Words that disable the expiry forewarning entirely when passed to
#: ``--warn-expiring-suppressions`` (alongside a bare ``0`` / ``0d``).
_EXPIRY_DISABLE_WORDS = frozenset({"off", "none", "never", "no"})


def parse_expiry_window(raw: str) -> int | None:
    """Parse a ``--warn-expiring-suppressions`` value into a day count.

    Accepts a bare integer (``"7"``) or a day-suffixed form (``"7d"``);
    ``"0"`` / ``"0d"`` and the words ``off`` / ``none`` / ``never`` / ``no``
    disable the forewarning and return ``None``. Raises ``ValueError`` on a
    negative or non-numeric value so the CLI can surface a clean error.
    """
    s = raw.strip().lower()
    if s in _EXPIRY_DISABLE_WORDS:
        return None
    if s.endswith("d"):
        s = s[:-1]
    try:
        days = int(s)
    except ValueError:
        raise ValueError(
            f"expiry window must be an integer number of days "
            f"(e.g. '7' or '7d'), or one of "
            f"{sorted(_EXPIRY_DISABLE_WORDS)} to disable; got {raw!r}"
        ) from None
    if days < 0:
        raise ValueError(
            f"expiry window cannot be negative; got {raw!r}"
        )
    return None if days == 0 else days


@dataclass(frozen=True, slots=True)
class IgnoreRule:
    """One line of an ignore file.

    Suppressions can carry an ``expires`` date (YAML format only). Once
    the date is in the past, ``is_expired`` returns True and callers
    skip the rule so suppressions can't rot silently. The flat-text
    format has no expiry field. Those rules never expire.
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

    def days_until_expiry(self, today: _dt.date | None = None) -> int | None:
        """Days remaining before this suppression expires.

        Returns None for rules without an ``expires`` date. Negative
        values mean the rule is already expired (caller should usually
        prefer :py:meth:`is_expired` for that check). Used by the CLI
        to forewarn users when a suppression is approaching its
        expiry date so they revisit it before the gate flips.
        """
        if self.expires is None:
            return None
        ref = today or _dt.date.today()
        return (self.expires - ref).days


@dataclass(slots=True)
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
    #: Inline ignore index built from ``# pipeline-check: ignore[...]``
    #: comments in the scanned source files. ``None`` means inline
    #: ignores are disabled (``--no-inline-ignore``).
    inline_ignores: InlineIgnoreIndex | None = None
    #: Specific attack-chain IDs that should fail the gate when matched.
    #: Use ``{"AC-001", "AC-007"}`` to gate only on chains the team has
    #: explicitly opted in to.
    fail_on_chains: set[str] = field(default_factory=set)
    #: When True, fail the gate if *any* attack chain matched. Useful as
    #: a blanket "no correlated attack paths" guard for high-trust repos.
    fail_on_any_chain: bool = False
    #: When True, fail the gate if any file the scan tried to read could
    #: not be parsed (the ``parse_error_count`` passed to
    #: :func:`evaluate_gate`). Additive: it does NOT disable the default
    #: ``--fail-on CRITICAL`` floor, so it layers a "the scan must have
    #: read everything" requirement on top. Set by ``--fail-on-parse-error``.
    fail_on_parse_error: bool = False
    #: Forewarning window (days) for soon-to-expire ignore rules. An
    #: ignore rule expiring within this many days is reported under
    #: :attr:`GateResult.expiring_soon`. ``None`` disables the forewarning
    #: (already-expired rules are still reported via ``expired_rules``).
    #: Defaults to :data:`EXPIRY_WARNING_DAYS`; set by
    #: ``--warn-expiring-suppressions``.
    expiry_warning_days: int | None = EXPIRY_WARNING_DAYS

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
            or self.fail_on_chains
            or self.fail_on_any_chain
        )


@dataclass(slots=True)
class GateResult:
    """Outcome of ``evaluate_gate``."""

    passed: bool
    #: Human-readable reasons the gate failed. Empty on pass.
    reasons: list[str]
    #: Failing findings after baseline + ignore filtering, the set the
    #: gate conditions were evaluated against.
    effective: list[Finding]
    #: Failing findings suppressed by the ignore file.
    suppressed: list[Finding]
    #: Failing findings already present in the baseline.
    baseline_matched: list[Finding]
    #: Ignore rules whose ``expires`` date has passed. Reported to the
    #: user so stale suppressions surface instead of rotting silently.
    expired_rules: list[IgnoreRule] = field(default_factory=list)
    #: Ignore rules whose ``expires`` date falls within
    #: :data:`EXPIRY_WARNING_DAYS` of today (14 days by default).
    #: Reported as a forewarning so the operator schedules a revisit
    #: before the suppression starts failing the gate. Distinct from
    #: ``expired_rules``: these still suppress, but soon won't.
    expiring_soon: list[IgnoreRule] = field(default_factory=list)
    #: Human-readable labels for every gate condition that was evaluated.
    conditions_evaluated: list[str] = field(default_factory=list)
    #: Attack chains that tripped a chain gate condition. Empty when
    #: chain gates aren't configured or no chain matched.
    tripped_chains: list[Chain] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return 0 if self.passed else 1


# ────────────────────────────────────────────────────────────────────────────
# Ignore-file and baseline loading
# ────────────────────────────────────────────────────────────────────────────


def load_ignore_file(path: str | Path) -> list[IgnoreRule]:
    """Parse an ignore file into a list of :class:`IgnoreRule`.

    Two formats are supported, picked by extension:

    - ``.yml`` / ``.yaml``, structured list of entries::

          - check_id: GHA-001
            resource: .github/workflows/release.yml
            expires: 2026-06-30
            reason: waiting on upstream Dependabot config

      ``expires`` (ISO date) is optional; once it passes the rule is
      returned but :py:meth:`IgnoreRule.is_expired` is True and
      ``evaluate_gate`` refuses to apply it. ``reason`` is metadata
      only, kept so reviewers can see the justification without
      crawling git history.

    - Anything else, the flat-text format (one ``CHECK_ID`` or
      ``CHECK_ID:RESOURCE`` per line, ``#`` for comments). No expiry
      field; rules in this format never expire.

    Missing files return an empty list rather than raising, the
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
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(
            f"[ignore-file] could not read {p}: {exc}. No rules loaded.",
            file=sys.stderr,
        )
        return []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" in line:
            check_id, resource = line.split(":", 1)
            resource = resource.strip()
            # An empty resource (``GHA-001:`` or ``GHA-001:   ``) is the
            # user asking for a blanket suppression, equivalent to
            # writing the check id alone. Normalize to None so the rule
            # actually matches something, a literal ``""`` resource
            # would only suppress findings with an exact empty string.
            rules.append(IgnoreRule(
                check_id=check_id.strip().upper(),
                resource=resource or None,
            ))
        else:
            rules.append(IgnoreRule(check_id=line.strip().upper(),
                                    resource=None))
    return rules


def _load_ignore_yaml(p: Path) -> list[IgnoreRule]:
    try:
        doc = yaml.load(p.read_text(encoding="utf-8"), Loader=_DupKeyIgnoreLoader)
    except yaml.YAMLError as exc:
        # Surface the parse error, a typo here silently removes every
        # suppression and the user has no way to tell without diffing
        # findings against a prior run.
        print(
            f"[ignore-file] could not parse {p}: {exc}. No rules loaded.",
            file=sys.stderr,
        )
        return []
    except (OSError, UnicodeDecodeError) as exc:
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
    than raising, the common case is "first run, no baseline yet" and
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
   , an old scan, a hand-edited file, or a completely unrelated JSON.
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


def _norm_resource(s: str) -> str:
    # Compare ignore-file resource paths in POSIX form. The ignore
    # file is often authored on Windows (``.github\workflows\foo.yml``)
    # but the runner emits forward slashes; literal string equality
    # silently fails to apply the suppression. Normalize both sides.
    return s.replace("\\", "/")


def _is_ignored(
    f: Finding,
    rules: Iterable[IgnoreRule],
    today: _dt.date,
    inline_ignores: InlineIgnoreIndex | None = None,
) -> bool:
    norm_resource = _norm_resource(f.resource)
    for r in rules:
        if r.is_expired(today):
            continue
        if r.check_id != f.check_id.upper():
            continue
        if r.resource is None or _norm_resource(r.resource) == norm_resource:
            return True
    if inline_ignores and inline_ignores.matches(
        f.check_id, f.resource, f.locations,
    ):
        return True
    return False


def evaluate_gate(
    findings: list[Finding],
    score_result: ScoreResult,
    config: GateConfig,
    chains: list[Chain] | None = None,
    parse_error_count: int = 0,
) -> GateResult:
    """Apply ``config`` to the scan's findings + score and decide pass/fail.

    When ``config.any_explicit_gate()`` is false and no baseline/ignore
    filtering is in play, the legacy default kicks in: fail iff
    ``score_result['grade'] == 'D'``. This preserves prior behavior.

    *chains* are optional, when provided and ``config.fail_on_chains``
    or ``config.fail_on_any_chain`` is set, matching chains add reasons
    to the gate result. Chains never apply baseline/ignore filtering;
    the rationale is that a correlated attack path is intrinsically a
    new finding even when the constituent legs were baselined.

    *parse_error_count* is the number of files the scan could not parse
    (from ``cli._scan_status``). When ``config.fail_on_parse_error`` is
    set and the count is non-zero, the gate fails: a security gate should
    be able to refuse a scan that silently skipped part of its input.
    """
    failing = [f for f in findings if not f.passed]

    # Filter: baseline, file wins over git-ref when both set.
    if config.baseline_path:
        baseline_pairs = load_baseline(config.baseline_path)
    elif config.baseline_from_git:
        ref, path = config.baseline_from_git
        baseline_pairs = load_baseline_from_git(ref, path)
    else:
        baseline_pairs = set()
    # Normalize resource path separators so a baseline written on one OS
    # (``.github\workflows\x.yml``) still suppresses the same finding on
    # another (``.github/workflows/x.yml``).
    baseline_pairs = {(cid, _norm_resource(res)) for cid, res in baseline_pairs}
    baseline_matched: list[Finding] = []
    after_baseline: list[Finding] = []
    for f in failing:
        if (f.check_id.upper(), _norm_resource(f.resource)) in baseline_pairs:
            baseline_matched.append(f)
        else:
            after_baseline.append(f)

    # Filter: ignore rules. Cache today's date so the expiry check
    # doesn't invoke the clock once per (rule, finding) pair.
    today = _dt.date.today()
    suppressed: list[Finding] = []
    effective: list[Finding] = []
    for f in after_baseline:
        if _is_ignored(f, config.ignore_rules, today, config.inline_ignores):
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
                f"{fail_on.value} ({', '.join(by_sev)}), {suffix}"
            )
        conditions.append(f"severity < {fail_on.value}, {suffix}")

    if config.min_grade:
        grade = score_result.get("grade", "D")
        conditions.append(f"grade >= {config.min_grade}, --min-grade")
        if _grade_worse_than(grade, config.min_grade):
            reasons.append(
                f"Grade {grade} is worse than --min-grade {config.min_grade}"
            )

    if config.max_failures is not None:
        conditions.append(f"failures <= {config.max_failures}, --max-failures")
        if len(effective) > config.max_failures:
            reasons.append(
                f"{len(effective)} failing findings exceed --max-failures "
                f"{config.max_failures}"
            )

    if config.fail_on_checks:
        ids = ", ".join(sorted(config.fail_on_checks))
        conditions.append(f"disallowed checks: {ids}, --fail-on-check")
        tripped = sorted(
            {f.check_id for f in effective if f.check_id.upper() in config.fail_on_checks}
        )
        if tripped:
            reasons.append(
                f"Disallowed check(s) failed: {', '.join(tripped)}, "
                f"--fail-on-check"
            )

    tripped_chains: list[Chain] = []
    if chains:
        if config.fail_on_any_chain:
            conditions.append("no attack chains, --fail-on-any-chain")
            if chains:
                tripped_chains.extend(chains)
                ids = ", ".join(sorted({c.chain_id for c in chains}))
                reasons.append(
                    f"{len(chains)} attack chain(s) detected: {ids}, "
                    f"--fail-on-any-chain"
                )
        elif config.fail_on_chains:
            wanted = {c.upper() for c in config.fail_on_chains}
            conditions.append(
                f"disallowed chains: {', '.join(sorted(wanted))}, --fail-on-chain"
            )
            matched = [c for c in chains if c.chain_id.upper() in wanted]
            if matched:
                tripped_chains.extend(matched)
                ids = ", ".join(sorted({c.chain_id for c in matched}))
                reasons.append(
                    f"Disallowed attack chain(s) detected: {ids}, "
                    f"--fail-on-chain"
                )

    if config.fail_on_parse_error:
        conditions.append("no unparseable files, --fail-on-parse-error")
        if parse_error_count > 0:
            reasons.append(
                f"{parse_error_count} file(s) could not be parsed, "
                f"--fail-on-parse-error"
            )

    expired_rules = [r for r in config.ignore_rules if r.is_expired(today)]
    expiring_soon: list[IgnoreRule] = []
    window = config.expiry_warning_days
    if window is not None:
        for r in config.ignore_rules:
            if r.expires is None or r.is_expired(today):
                continue
            days = r.days_until_expiry(today)
            if days is not None and days <= window:
                expiring_soon.append(r)

    return GateResult(
        passed=not reasons,
        reasons=reasons,
        effective=effective,
        suppressed=suppressed,
        baseline_matched=baseline_matched,
        expired_rules=expired_rules,
        expiring_soon=expiring_soon,
        conditions_evaluated=conditions,
        tripped_chains=tripped_chains,
    )


def _grade_worse_than(actual: str, bar: str) -> bool:
    """A grade ``actual`` is worse than ``bar`` if it comes later in A→D."""
    try:
        return _GRADES.index(actual) > _GRADES.index(bar)
    except ValueError:
        # Unknown grade, treat as worst.
        return True
