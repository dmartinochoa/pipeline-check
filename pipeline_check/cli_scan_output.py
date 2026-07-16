"""Scan-status computation and scan / gate summary rendering.

The structured completeness summary (``_scan_status`` and its terminal
``reason`` line) and the stderr scan / gate summaries the ``scan``
command prints after a run. Extracted from ``cli.py`` to keep that
module focused on argument wiring; these are pure-ish helpers (they read
the scan metadata / gate result and either return a value or ``echo`` to
stderr) and are re-imported into ``cli`` so the call sites are unchanged.
Lower-level imports (``core.scanner`` / ``core.autofix`` /
``core.checks.base``) stay function-local to avoid an import cycle.
"""
from __future__ import annotations

from typing import Any

import click


def _scan_status(meta: Any, findings: list[Any]) -> dict[str, Any]:
    """Structured completeness summary of a scan.

    A scan is incomplete when a file it tried to read could not be
    parsed (malformed YAML / JSON, read error) or when a cloud module
    failed API access (the ``*-000`` degraded probes). The score then
    reflects only what was actually scanned. This summary is emitted in
    the JSON and SARIF outputs so CI consumers can detect an incomplete
    scan, and it backs :func:`_scan_incomplete_reason` (the terminal
    status line). ``reason`` is present only when the scan is incomplete.

    ``warnings`` carries the raw scan-metadata warning strings (parse
    failures, a provider's ``post_filter`` crash, a rule-set filter
    notice) when any fired, so a programmatic consumer sees the same
    detail the stderr summary prints rather than only the parse / degraded
    counts. Absent when the scan produced no warnings.
    """
    parse_fail = 0
    for w in getattr(meta, "warnings", None) or []:
        wl = str(w).lower()
        if "parse error" in wl or "read error" in wl:
            parse_fail += 1
    degraded = sum(
        1 for f in findings
        if getattr(f, "check_id", "").endswith("-000")
        and not getattr(f, "passed", True)
    )
    status: dict[str, Any] = {
        "complete": parse_fail == 0 and degraded == 0,
        "files_scanned": int(getattr(meta, "files_scanned", 0) or 0),
        "files_unparsed": parse_fail,
        "degraded_modules": degraded,
    }
    warnings = [str(w) for w in (getattr(meta, "warnings", None) or [])]
    if warnings:
        status["warnings"] = warnings
    parts: list[str] = []
    if parse_fail:
        parts.append(f"{parse_fail} file(s) could not be parsed")
    if degraded:
        parts.append(f"{degraded} module(s) failed API access")
    if parts:
        status["reason"] = (
            f"{'; '.join(parts)}. The grade reflects only what was scanned."
        )
    return status


def _scan_incomplete_reason(meta: Any, findings: list[Any]) -> str | None:
    """The human-readable reason a scan is incomplete, or ``None`` when
    it fully ran. Drives the terminal report's status line."""
    return _scan_status(meta, findings).get("reason")


def _emit_scan_summary(meta: Any) -> None:
    """Render the scan summary line and any parse warnings to stderr."""
    from .core.scanner import ScanMetadata
    if not isinstance(meta, ScanMetadata):
        return
    for w in meta.warnings:
        click.echo(f"[warn] {w}", err=True)
    if meta.files_scanned == 0 and meta.files_skipped == 0:
        click.echo("[warn] no pipeline files found to scan", err=True)
        return
    skip_part = f" ({meta.files_skipped} skipped)" if meta.files_skipped else ""
    click.echo(
        f"[scan] {meta.provider}: scanned {meta.files_scanned} file(s){skip_part}"
        f" in {meta.elapsed_seconds:.1f}s",
        err=True,
    )


def _build_gate_trailer(
    gate: Any,
    *,
    baseline_path: str | None,
    baseline_from_git: str | None,
) -> str | None:
    """Construct the one-line "what next" hint for a failing gate.

    Picks the most actionable suggestion based on the failing set:
    autofix when at least one finding has a registered fixer,
    otherwise a baseline-write when none was provided, otherwise
    point the user at ``explain`` for the highest-severity failure.
    """
    effective = list(gate.effective)
    if not effective:
        return None
    from .core.autofix import SAFE, available_fixers, fixer_safety
    fixers = set(available_fixers())
    fixable = [f for f in effective if f.check_id.upper() in fixers]
    n_total = len(effective)
    if fixable:
        n_safe = sum(1 for f in fixable if fixer_safety(f.check_id.upper()) == SAFE)
        if n_safe:
            # Bare ``--fix`` is safe-only; advertise what it will actually
            # write, and point the unsafe remainder at the unsafe tier.
            message = (
                f"{n_safe} of {n_total} failing findings "
                f"are autofixable; run `pipeline_check --fix --apply` to apply them"
            )
            n_unsafe = len(fixable) - n_safe
            if n_unsafe:
                message += f" (+{n_unsafe} more via `--fix unsafe --apply`)"
        else:
            # Every available fixer is unsafe-tier, so bare ``--fix`` would
            # write nothing; point at the unsafe tier explicitly so the
            # suggested command actually changes the tree.
            message = (
                f"{len(fixable)} of {n_total} failing findings are autofixable "
                f"(unsafe tier); run `pipeline_check --fix unsafe --apply` to "
                f"apply them"
            )
    elif not baseline_path and not baseline_from_git:
        message = (
            "no baseline configured; run `pipeline_check "
            "--write-baseline baseline.json` then pair with "
            "`--baseline baseline.json` to gate only on new findings"
        )
    else:
        from .core.checks.base import severity_rank
        top = sorted(
            effective,
            key=lambda f: (-severity_rank(f.severity), f.check_id),
        )[0]
        message = (
            f"start with the highest-severity rule: "
            f"`pipeline_check explain {top.check_id}`"
        )
    return f"[gate] next: {message}"


def _emit_gate_summary(
    gate: Any,
    *,
    grade: str | None = None,
    baseline_path: str | None = None,
    baseline_from_git: str | None = None,
) -> None:
    """Render the gate outcome to stderr so JSON/SARIF on stdout stays clean.

    When the gate fails, also emit a single-line "what next" trailer:
    how many of the failing findings have autofixers, and the
    one-command path to close the loop (fix-and-apply, baseline-write,
    or explain-the-rule). The trailer is intentionally short so a CI
    log scan picks it up without scrolling.

    A strong *grade* (A or B) sitting on top of a failing gate is the
    most confusing outcome a first-time user hits, since the grade reads
    as "all good" while the build still exits non-zero. When that
    happens, a one-line note clarifies that the grade is a posture score
    and the gate is a separate blocking policy.
    """
    n_effective = len(gate.effective)
    n_chains_tripped = len(getattr(gate, "tripped_chains", []) or [])
    if gate.passed:
        msg_lines = [f"[gate] PASS ({n_effective} effective finding(s) evaluated)"]
        for cond in getattr(gate, "conditions_evaluated", []):
            msg_lines.append(f"        - {cond}")
    else:
        msg_lines = ["[gate] FAIL"]
        for reason in gate.reasons:
            msg_lines.append(f"        - {reason}")
        if grade in ("A", "B"):
            msg_lines.append(
                f"[gate] note: Grade {grade} is overall posture (checks "
                "weighted by severity), not this gate. A strong grade can "
                "still fail the gate on a single blocking finding."
            )
        trailer = _build_gate_trailer(
            gate,
            baseline_path=baseline_path,
            baseline_from_git=baseline_from_git,
        )
        if trailer:
            msg_lines.append(trailer)
    if n_chains_tripped:
        ids = ", ".join(sorted({c.chain_id for c in gate.tripped_chains}))
        msg_lines.append(f"[gate] {n_chains_tripped} attack chain(s) tripped: {ids}")
    if gate.baseline_matched:
        msg_lines.append(
            f"[gate] {len(gate.baseline_matched)} finding(s) suppressed by baseline"
        )
    if gate.vex_suppressed:
        msg_lines.append(
            f"[gate] {len(gate.vex_suppressed)} advisory finding(s) "
            f"suppressed by OpenVEX (--vex)"
        )
    if gate.suppressed:
        msg_lines.append(
            f"[gate] {len(gate.suppressed)} finding(s) suppressed by ignore file"
        )
    if gate.expired_rules:
        for r in gate.expired_rules:
            scope = f":{r.resource}" if r.resource else ""
            msg_lines.append(
                f"[gate] ignore rule expired on {r.expires}: "
                f"{r.check_id}{scope} (no longer suppressing)"
            )
    if gate.expiring_soon:
        # Forewarn before expiry so the team schedules a revisit
        # rather than discovering the lapsed suppression in CI.
        for r in gate.expiring_soon:
            scope = f":{r.resource}" if r.resource else ""
            days = r.days_until_expiry()
            day_word = "day" if days == 1 else "days"
            when = "today" if days == 0 else f"in {days} {day_word}"
            msg_lines.append(
                f"[gate] ignore rule expires {when} on {r.expires}: "
                f"{r.check_id}{scope} (still suppressing, but plan to revisit)"
            )
    for line in msg_lines:
        click.echo(line, err=True)
