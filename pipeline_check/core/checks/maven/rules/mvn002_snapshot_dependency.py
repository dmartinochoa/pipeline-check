"""MVN-002, pom.xml depends on a mutable SNAPSHOT version."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile, iter_real_dependencies, resolve_version

RULE = Rule(
    id="MVN-002",
    title="pom.xml depends on a mutable SNAPSHOT version",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Replace ``-SNAPSHOT`` versions with a released, immutable "
        "version (``1.2.3``, not ``1.2.3-SNAPSHOT``). Maven treats "
        "SNAPSHOT artifacts as mutable: the repository can re-deploy "
        "the same coordinate, and ``mvn install`` will pull whatever "
        "is current at resolution time. Snapshot dependencies belong "
        "to the development inner loop; gate them out of release "
        "builds and CI build pipelines."
    ),
    docs_note=(
        "Fires on any non-managed ``<version>`` ending in "
        "``-SNAPSHOT`` (case-insensitive). Property references are "
        "resolved against the POM's ``<properties>`` first, so a "
        "property whose value ends in ``-SNAPSHOT`` still trips the "
        "rule. ``<dependencyManagement>`` entries are exempt; "
        "centralized version literals are MVN-004's surface."
    ),
    known_fp=(
        "Multi-module reactor builds where every sibling references "
        "``${project.version}-SNAPSHOT`` during local development. "
        "Suppress in your local profile or scope the scan to the "
        "release POM; gating release builds on SNAPSHOT-free deps "
        "is exactly what this rule is for.",
    ),
)


def _is_snapshot(version: str) -> bool:
    return version.strip().upper().endswith("-SNAPSHOT")


def check(pom: PomFile) -> Finding:
    if pom.is_settings:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="settings.xml has no project dependencies.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for dep in iter_real_dependencies(pom):
        if dep.version is None:
            continue
        resolved = resolve_version(dep.version, pom.properties)
        if not _is_snapshot(resolved):
            continue
        offenders.append(dep.coordinate)
        locations.append(Location(
            path=pom.path, start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    desc = (
        "No dependency in pom.xml uses a SNAPSHOT version."
        if passed else
        f"{len(offenders)} dependency / dependencies on SNAPSHOT "
        f"versions: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. SNAPSHOT artifacts are "
        f"mutable; the same coordinate can resolve to different bytes "
        f"between builds."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
