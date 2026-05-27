"""MVN-009, Maven artifact has a known OSV advisory."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import (
    MavenContext,
    PomFile,
    iter_real_dependencies,
    resolve_version,
)

RULE = Rule(
    id="MVN-009",
    title="Maven artifact has a known OSV advisory",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-506"),
    recommendation=(
        "Upgrade to a patched version or remove the affected artifact. "
        "Consult the advisory URL for remediation guidance."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote`` to query the "
        "OSV advisory database (``api.osv.dev``). Passes silently "
        "when the flag is off. Complements MVN-006 (curated offline "
        "registry) with the full OSV/GHSA long-tail."
    ),
)

# Version shapes that are out of scope for the advisory lookup:
# ``-SNAPSHOT`` is a mutable Maven tag, range literals are not
# concrete coordinates, and ``LATEST`` / ``RELEASE`` are meta-
# versions Maven resolves at build time.
_RANGE_CHARS = ("[", "]", "(", ")", ",")
_RANGE_LITERALS = ("LATEST", "RELEASE")


def _is_concrete_release(version: str) -> bool:
    v = version.strip()
    if not v:
        return False
    if v.endswith(("-SNAPSHOT", ".SNAPSHOT")):
        return False
    if v in _RANGE_LITERALS:
        return False
    if any(c in v for c in _RANGE_CHARS):
        return False
    if v == "+" or v.endswith(".+"):
        return False
    return True


def check(
    pom: PomFile, ctx: MavenContext | None = None,
) -> Finding:
    if pom.is_settings:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="settings.xml has no project dependencies.",
            recommendation=RULE.recommendation, passed=True,
        )
    if ctx is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "No OSV advisory data available (re-run with "
                "``--resolve-remote`` to enable advisory lookups)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    osv: dict[tuple[str, str], list[Any]] = getattr(
        ctx, "osv_advisories", {},
    )
    if not osv:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "No OSV advisory data available (re-run with "
                "``--resolve-remote`` to enable advisory lookups)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

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
        advisories = osv.get((key, resolved))
        if not advisories:
            continue
        ids = [a.id if hasattr(a, "id") else str(a) for a in advisories]
        offenders.append(
            f"{key}:{resolved} ({', '.join(ids)})"
        )
        locations.append(Location(
            path=pom.path,
            start_line=dep.line_no, end_line=dep.line_no,
        ))

    passed = not offenders
    if passed:
        desc = (
            "No dependency matches a known OSV advisory."
        )
    else:
        ref_summary = ", ".join(offenders[:5])
        if len(offenders) > 5:
            ref_summary += f" (+{len(offenders) - 5} more)"
        desc = (
            f"{len(offenders)} dependency / dependencies have known "
            f"OSV advisories: {ref_summary}. Consult the advisory "
            f"URLs for remediation guidance."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
