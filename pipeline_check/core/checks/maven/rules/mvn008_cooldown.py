"""MVN-008, direct dependency was published within the cooldown window."""
from __future__ import annotations

import datetime as _dt

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import (
    MavenContext,
    PomFile,
    iter_real_dependencies,
    resolve_version,
)

RULE = Rule(
    id="MVN-008",
    title="Direct dependency was published within the cooldown window",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-494"),
    recommendation=(
        "Either skip the just-published version (pin to the last "
        "release older than the cooldown window) or wait until the "
        "cooldown has elapsed before bumping the POM. Publisher- "
        "account compromises on Maven Central are rarer than on "
        "npm / PyPI, but the takedown window is the same shape: "
        "Sonatype yanks malicious artifacts within hours-to-days "
        "once an advisory lands; holding back N days converts a "
        "publisher-compromise window into a vulnerability- "
        "disclosure window where either the maintainer rotates the "
        "malicious release off Central or the security community "
        "files a CVE that MVN-006 can match against."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote`` to populate "
        "the per-coordinate publish timestamps from the Maven "
        "Central search API "
        "(``https://search.maven.org/solrsearch/select``). Walks "
        "every non-managed ``<dependency>`` with an explicit "
        "``<version>``; flags ones whose ingest timestamp on "
        "Central falls inside the cooldown window (default 7 days). "
        "``<dependencyManagement>`` entries are skipped (those are "
        "version-management declarations, not real consumption). "
        "``${prop}`` substitution against the POM's ``<properties>`` "
        "block is resolved before the lookup so ``${log4j.version}`` "
        "is checked against its resolved value. ``-SNAPSHOT`` and "
        "Maven version-range literals (``[1.0,2.0)``, ``LATEST``, "
        "``RELEASE``) are out of scope — the cooldown applies to a "
        "specific released coordinate. When ``--resolve-remote`` is "
        "off or Central can't be reached, the rule passes silently "
        "so the absence of the network path doesn't trip CI."
    ),
    known_fp=(
        "Internally-published artifacts hosted on a private "
        "Sonatype Nexus / JFrog Artifactory instance won't appear "
        "in Central's search API and are silently skipped. The "
        "cooldown gate is a Central-only signal; vendor- or org- "
        "internal release trains are out of scope and shouldn't "
        "be suppressed (they simply don't fire).",
        "Same-day patch upgrades from a maintainer the team "
        "directly trusts (e.g. an internal fork republished to "
        "Central under a corporate group ID) are flagged. "
        "Suppress per-resource via ``--ignore-file`` — the "
        "cooldown is a default-safe gate, not a hard rule.",
    ),
    incident_refs=(
        "Log4Shell, CVE-2021-44228 (December 2021): public "
        "disclosure on 2021-12-09 triggered Apache's emergency "
        "2.15.0 release the same day; mass exploitation began "
        "within hours. Consumers who held even a 1-day cooldown "
        "on the affected versions would have caught the upstream "
        "advisory before bumping. "
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "Sonatype Lift abuse / typosquat campaigns "
        "(2022-2024): periodic surfacing of typosquat coordinates "
        "(``org.apaache.*``) pushed to Central, typically yanked "
        "within 48 hours of report. A cooldown of any meaningful "
        "length would skip them.",
    ),
    exploit_example=(
        "<!-- Vulnerable: bumping the version to a freshly-\n"
        "     published release within hours of its appearance on\n"
        "     Maven Central is exactly the window in which a\n"
        "     publisher-compromise (stolen Sonatype token, hijacked\n"
        "     maintainer account) or an advisory-not-yet-filed\n"
        "     malicious release lives. Sonatype yanks malicious\n"
        "     coordinates within hours-to-days once flagged;\n"
        "     bumping straight to ``17.0.99`` on its release day\n"
        "     skips that window entirely. -->\n"
        "<dependency>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>shiny-lib</artifactId>\n"
        "  <version>17.0.99</version>\n"
        "  <!-- ``17.0.99`` was published 2 hours ago -->\n"
        "</dependency>\n"
        "\n"
        "<!-- Safe: pin to the most recent release older than the\n"
        "     cooldown window. ``pipeline_check --pipeline maven\n"
        "     --resolve-remote`` queries Maven Central's search API\n"
        "     for per-coordinate publish timestamps and surfaces\n"
        "     anything inside the 7-day window. Hold the bump until\n"
        "     the cooldown elapses, or skip the freshly-pushed\n"
        "     version entirely. -->\n"
        "<dependency>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>shiny-lib</artifactId>\n"
        "  <version>17.0.98</version>\n"
        "  <!-- ``17.0.98`` was published 3 weeks ago -->\n"
        "</dependency>"
    ),
)


# ``-SNAPSHOT`` is a mutable Maven tag (MVN-002's territory) and
# shouldn't be measured against an immutable cooldown; range
# literals likewise are out of scope. The cooldown rule only acts
# on a single concrete release version.
_RANGE_CHARS = ("[", "]", "(", ")", ",")
_RANGE_LITERALS = ("LATEST", "RELEASE")


def _now() -> _dt.datetime:
    """Indirection so tests can freeze wall-clock time via monkeypatch."""
    return _dt.datetime.now(_dt.UTC)


def _is_concrete_release(version: str) -> bool:
    v = version.strip()
    if not v:
        return False
    if v.endswith("-SNAPSHOT") or v.endswith(".SNAPSHOT"):
        return False
    if v in _RANGE_LITERALS:
        return False
    if any(c in v for c in _RANGE_CHARS):
        return False
    # Plain ``+`` is the Gradle "latest-anywhere" wildcard; the
    # Maven equivalent ``LATEST`` is already rejected above, and a
    # bare ``+`` shouldn't reach a registry lookup either.
    if v == "+" or v.endswith(".+"):
        return False
    return True


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
    pom: PomFile, ctx: MavenContext | None = None,
) -> Finding:
    publish_times: dict[str, dict[str, _dt.datetime]] = (
        ctx.publish_times if ctx is not None else {}
    )
    cooldown_days = 7
    if pom.is_settings:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="settings.xml has no project dependencies.",
            recommendation=RULE.recommendation, passed=True,
        )
    if not publish_times:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "No publish-time metadata available (re-run with "
                "``--resolve-remote`` to enable cooldown analysis)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    now = _now()
    offenders: list[str] = []
    locations: list[Location] = []
    for dep in iter_real_dependencies(pom):
        if dep.version is None:
            continue
        resolved = resolve_version(dep.version, pom.properties)
        if not _is_concrete_release(resolved):
            continue
        if resolved.startswith("${"):
            # Property reference couldn't be resolved; skip rather
            # than guess.
            continue
        key = f"{dep.group_id}:{dep.artifact_id}"
        per_version = publish_times.get(key)
        if not per_version:
            continue
        published = per_version.get(resolved)
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
            f"{key}:{resolved} "
            f"(published {age}d ago, cooldown {cooldown_days}d)"
        )
        locations.append(Location(
            path=pom.path,
            start_line=dep.line_no, end_line=dep.line_no,
        ))

    passed = not offenders
    desc = (
        f"Every non-managed dependency was published more than "
        f"{cooldown_days} day(s) ago."
        if passed else
        f"{len(offenders)} dependency / dependencies were published "
        f"within the {cooldown_days}-day cooldown window: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Maven Central yanks "
        f"malicious coordinates within hours-to-days; holding back "
        f"converts the window into a vulnerability-disclosure window."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
