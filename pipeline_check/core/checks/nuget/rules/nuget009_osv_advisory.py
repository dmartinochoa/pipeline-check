"""NUGET-009, NuGet package has a known OSV advisory."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NuGetContext, NuGetProject

RULE = Rule(
    id="NUGET-009",
    title="NuGet package has a known OSV advisory",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-506"),
    recommendation=(
        "Upgrade to a patched version or remove the affected package. "
        "Consult the advisory URL for remediation guidance."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote`` to query the "
        "OSV advisory database. Passes silently when the flag is off."
    ),
)


def check(
    project: NuGetProject, ctx: NuGetContext | None = None,
) -> Finding:
    if ctx is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=project.path,
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
            resource=project.path,
            description=(
                "No OSV advisory data available (re-run with "
                "``--resolve-remote`` to enable advisory lookups)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    advisory_ids: set[str] = set()
    locations: list[Location] = []
    for ref in project.package_refs:
        if ref.version is None:
            continue
        advisories = osv.get((ref.name.lower(), ref.version))
        if not advisories:
            continue
        ids = [
            a.get("id", "unknown") if isinstance(a, dict) else str(a)
            for a in advisories
        ]
        advisory_ids.update(ids)
        offenders.append(
            f"{ref.name}@{ref.version} ({', '.join(ids)})"
        )
        locations.append(Location(
            path=project.path,
            start_line=ref.line_no, end_line=ref.line_no,
        ))

    passed = not offenders
    if passed:
        desc = (
            "No PackageReference matches a known OSV advisory."
        )
    else:
        ref_summary = ", ".join(offenders[:5])
        if len(offenders) > 5:
            ref_summary += f" (+{len(offenders) - 5} more)"
        desc = (
            f"{len(offenders)} PackageReference(s) have known OSV "
            f"advisories: {ref_summary}. Consult the advisory URLs "
            f"for remediation guidance."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=project.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
