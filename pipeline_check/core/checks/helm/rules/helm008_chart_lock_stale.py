"""HELM-008 — ``Chart.lock`` generated more than 90 days ago.

A stale ``Chart.lock`` means ``helm dependency update`` hasn't been
run in a while. The dependencies are still pinned (good) but no one
has refreshed against the upstream registry's published versions —
known CVEs, deprecation notices, and security advisories from the
last quarter haven't been considered. The right cadence is "run
``helm dependency update`` at least every release", which for most
production charts means at least every couple of months.

The 90-day threshold is the same one used by other supply-chain
posture rules (CIS 1.14 IAM access-key rotation, CIS supply-chain
3.x dependency-refresh expectation). It's deliberately generous;
charts that update on a faster cadence pass trivially.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-008",
    title="Chart.lock generated more than 90 days ago",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-1104",),
    recommendation=(
        "Run ``helm dependency update`` against every dependency-"
        "carrying chart at least once per release cycle, and commit "
        "the regenerated ``Chart.lock``. The lock pins versions and "
        "digests; the *update cadence* is what brings in CVE fixes "
        "and deprecation notices from the last quarter. CI can run "
        "the same command against ``main`` weekly to surface "
        "drift as a PR rather than letting the lock sit stale "
        "until the next release."
    ),
    docs_note=(
        "Reads ``Chart.lock``'s top-level ``generated:`` timestamp "
        "(an ISO-8601 string Helm writes when the lock was last "
        "regenerated) and compares against ``now``. Fires when the "
        "delta is more than 90 days. Charts without ``Chart.lock`` "
        "are skipped — HELM-002 covers the missing-lock case "
        "directly. Charts whose ``generated:`` field is malformed "
        "or absent silently pass on this rule (HELM-002 covers the "
        "absent-lock case from a different angle)."
    ),
    known_fp=(
        "A chart that pins exact versions and never needs new "
        "dependencies (e.g. a chart packaging a single internal "
        "library that itself updates rarely) may legitimately have "
        "a stale Chart.lock. Suppress with ``--ignore-file`` when "
        "this matches your situation.",
    ),
)


_STALE_THRESHOLD = timedelta(days=90)


def _parse_generated(value: object) -> datetime | None:
    """Return *value* as a tz-aware datetime, or ``None`` if unparsable.

    Helm writes ISO-8601 timestamps like
    ``2024-01-02T15:04:05.000Z`` or
    ``2024-01-02T15:04:05+00:00``. We accept both common forms by
    normalizing the trailing ``Z`` to ``+00:00`` before parsing.
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    # ``Z`` -> ``+00:00`` so fromisoformat accepts it (3.10 doesn't
    # parse ``Z`` natively; 3.11+ does, but we support 3.10 too).
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # Naive datetime — assume UTC. Helm always writes a tz, but
        # be defensive against hand-edited locks.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def check(ctx: HelmContext, *, _now: datetime | None = None) -> Finding:
    """Check is parameterised on ``_now`` so tests inject a frozen clock."""
    now = _now or datetime.now(timezone.utc)
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        if chart.chart_lock is None:
            continue
        generated = _parse_generated(chart.chart_lock.get("generated"))
        if generated is None:
            continue
        age = now - generated
        if age > _STALE_THRESHOLD:
            offenders.append(
                f"{chart.name}: generated {generated.date().isoformat()} "
                f"({age.days} days ago)"
            )
            locations.append(Location(
                path=chart.chart_lock_path or chart.chart_yaml_path,
            ))
    passed = not offenders
    desc = (
        "Every dependency-carrying chart has a Chart.lock generated "
        "within the last 90 days."
        if passed else
        f"{len(offenders)} chart(s) have a Chart.lock older than 90 "
        f"days: {', '.join(offenders[:3])}"
        f"{'…' if len(offenders) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="helm/charts",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
