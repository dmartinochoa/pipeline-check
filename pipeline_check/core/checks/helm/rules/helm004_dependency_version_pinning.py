"""HELM-004 — Chart dependency version is a range, not an exact pin.

``dependencies[].version`` accepts the full SemVer range syntax —
``^1.0.0``, ``~2.3``, ``>=4.5 <5``, ``*`` — same as
``Chart.yaml`` resolves a Go-style constraint at ``helm dependency
update`` time. The lock file (HELM-002) records whatever version
that resolution picked, so a later ``helm dependency update`` can
silently move every consumer of the chart to a different version
without the chart's own metadata changing. Exact pins (``17.0.0``,
``v1.2.3``) eliminate the drift.

Note: this rule is about ``Chart.yaml``'s declared constraint, not
the ``Chart.lock``. The lock catches whatever resolution found, but
the constraint is what the *next* update will re-resolve against.
A loose constraint plus a lock is still a chart that will float
on the next dep-update — the lock's role is reproducibility, not
constraint tightening.
"""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import HelmContext

RULE = Rule(
    id="HELM-004",
    title="Chart dependency version is a range, not an exact pin",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Replace each ``dependencies[].version`` constraint with the "
        "exact resolved version from ``Chart.lock``. ``17.0.0`` "
        "instead of ``^17.0.0``, ``v1.2.3`` instead of ``~1.2``. "
        "Range syntax (``^``, ``~``, ``>=``, ``*``, ``x``) lets "
        "``helm dependency update`` move every consumer of the "
        "chart to a newer dep on the next refresh, even when the "
        "lock file looked stable."
    ),
    docs_note=(
        "An exact pin is a string that contains only digits, dots, "
        "and at most a single leading ``v`` / trailing pre-release "
        "or build identifier (``1.2.3``, ``v1.2.3``, ``1.2.3-rc1``, "
        "``1.2.3+build.5``). Anything carrying ``^`` / ``~`` / "
        "``>`` / ``<`` / ``*`` / ``x`` / ``X`` / ``||`` / a space "
        "(``>=4 <5``) is treated as a range. The bias is toward "
        "false positives — a chart maintainer can suppress per-rule "
        "via ``--ignore-file`` if they specifically want range "
        "semantics, but the default for production charts is a pin."
    ),
)


# Exact pin shape: optional leading ``v``, then digit-dot-digit
# segments, optional pre-release / build metadata. Anything with a
# range/wildcard token fails this match.
_EXACT_PIN_RE = re.compile(
    r"^v?\d+(?:\.\d+){0,2}"
    r"(?:-[0-9A-Za-z.-]+)?"
    r"(?:\+[0-9A-Za-z.-]+)?$"
)


def check(ctx: HelmContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for chart in ctx.charts:
        if chart.api_version != "v2":
            continue
        for dep in chart.dependencies:
            ver = dep.get("version")
            name = dep.get("name") if isinstance(dep.get("name"), str) else "?"
            if not isinstance(ver, str):
                continue
            if not _is_exact_pin(ver):
                offenders.append(f"{chart.name}/{name} version={ver}")
                locations.append(Location(path=chart.chart_yaml_path))
    passed = not offenders
    desc = (
        "Every chart dependency version is an exact pin."
        if passed else
        f"{len(offenders)} chart dependency version(s) are not "
        f"exact-pinned: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="helm/charts",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )


def _is_exact_pin(version: str) -> bool:
    s = version.strip()
    if not s:
        # An empty version is its own problem (helm rejects it at
        # render time) but is outside this rule's scope.
        return True
    return bool(_EXACT_PIN_RE.match(s))
