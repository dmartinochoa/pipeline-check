"""NUGET-008, direct dependency published within the cooldown window."""
from __future__ import annotations

import datetime as _dt

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NuGetContext, NuGetProject

RULE = Rule(
    id="NUGET-008",
    title="NuGet package published within the cooldown window",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-494"),
    recommendation=(
        "Pin to a version published before the cooldown window, or "
        "wait until the cooldown has elapsed. Most publisher-account "
        "compromises are detected within hours-to-days of publication."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote`` to populate "
        "publish timestamps from ``api.nuget.org``. Passes silently "
        "when the flag is off."
    ),
    exploit_example=(
        "# Vulnerable: consuming a version published 2 hours ago.\n"
        "# Most account-takeover publishes are detected and yanked\n"
        "# within hours-to-days; the next dotnet restore pulls the\n"
        "# compromised package before the takedown.\n"
        "<!-- app.csproj -->\n"
        '<PackageReference Include="PopularLib" Version="5.3.1" />\n'
        "<!-- 5.3.1 was published 2 hours ago -->\n"
        "\n"
        "# Safe: pin to a version published before the cooldown\n"
        "# window, or wait until the cooldown elapses.\n"
        '<PackageReference Include="PopularLib" Version="5.3.0" />'
    ),
)


def _now() -> _dt.datetime:
    """Indirection so tests can freeze wall-clock time via monkeypatch."""
    return _dt.datetime.now(_dt.UTC)


def _within_cooldown(
    publish_time: _dt.datetime,
    now: _dt.datetime,
    cooldown_days: int,
) -> bool:
    """True iff *publish_time* is younger than *cooldown_days* ago.

    Both inputs normalized to UTC tz-aware; a tz-naive *now* (test
    fixture default) is treated as UTC.
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=_dt.UTC)
    if publish_time.tzinfo is None:
        publish_time = publish_time.replace(tzinfo=_dt.UTC)
    return (now - publish_time) < _dt.timedelta(days=cooldown_days)


def check(
    project: NuGetProject, ctx: NuGetContext | None = None,
) -> Finding:
    publish_times: dict[str, dict[str, _dt.datetime]] = (
        ctx.publish_times if ctx is not None else {}
    )
    cooldown_days = 7
    if not publish_times:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=project.path,
            description=(
                "No publish-time metadata available (re-run with "
                "``--resolve-remote`` to enable cooldown analysis)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    now = _now()
    offenders: list[str] = []
    locations: list[Location] = []
    for ref in project.package_refs:
        if ref.version is None:
            continue
        # Only exact versions are eligible for the cooldown gate.
        # NuGet ranges (``[1.0,2.0)``, ``*``) are out of scope.
        if any(c in ref.version for c in ("[", "]", "(", ")", "*", ",")):
            continue
        per_version = publish_times.get(ref.name.lower())
        if not per_version:
            continue
        published = per_version.get(ref.version)
        if published is None:
            continue
        if not _within_cooldown(published, now, cooldown_days):
            continue
        published_aware = (
            published if published.tzinfo is not None
            else published.replace(tzinfo=_dt.UTC)
        )
        age = (now - published_aware).days
        offenders.append(
            f"{ref.name}@{ref.version} "
            f"(published {age}d ago, cooldown {cooldown_days}d)"
        )
        locations.append(Location(
            path=project.path,
            start_line=ref.line_no, end_line=ref.line_no,
        ))

    passed = not offenders
    desc = (
        f"Every PackageReference was published more than "
        f"{cooldown_days} day(s) ago."
        if passed else
        f"{len(offenders)} PackageReference(s) were published within "
        f"the {cooldown_days}-day cooldown window: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A publisher-account "
        f"compromise typically gets caught and yanked within "
        f"hours-to-days; holding back converts the window into a "
        f"vulnerability-disclosure window."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=project.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
