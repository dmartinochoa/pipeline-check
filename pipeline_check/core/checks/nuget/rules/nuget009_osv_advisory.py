"""NUGET-009, NuGet package has a known OSV advisory."""
from __future__ import annotations

from typing import Any

from ....sbom import make_nuget_purl
from ..._primitives.osv_fetcher import advisory_aliases, advisory_id
from ...base import Finding, Location, Severity, VulnRef
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
    exploit_example=(
        "# Vulnerable: pinning a version with a known advisory.\n"
        "# GHSA-xxxx flags a deserialization RCE in\n"
        "# Newtonsoft.Json < 13.0.1; dotnet restore pulls\n"
        "# the vulnerable version into every CI build.\n"
        "<!-- app.csproj -->\n"
        '<PackageReference Include="Newtonsoft.Json" Version="12.0.3" />\n'
        "\n"
        "# Safe: upgrade to the patched version.\n"
        '<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />'
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
    locations: list[Location] = []
    vulns: list[VulnRef] = []
    for ref in project.package_refs:
        if ref.version is None:
            continue
        advisories = osv.get((ref.name.lower(), ref.version))
        if not advisories:
            continue
        ids = [advisory_id(a) for a in advisories]
        offenders.append(
            f"{ref.name}@{ref.version} ({', '.join(ids)})"
        )
        purl = make_nuget_purl(ref.name, ref.version)
        for a in advisories:
            vulns.append(VulnRef(
                vuln_id=advisory_id(a),
                purl=purl,
                aliases=advisory_aliases(a),
            ))
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
        locations=locations, vulnerabilities=tuple(vulns),
    )
