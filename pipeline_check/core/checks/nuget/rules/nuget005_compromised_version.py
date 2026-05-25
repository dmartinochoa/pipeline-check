"""NUGET-005, PackageReference pins a known-compromised NuGet package version."""
from __future__ import annotations

from ...base import Finding, Severity, severity_rank
from ...rule import Rule
from .._compromised_packages import lookup
from ..base import NuGetProject

RULE = Rule(
    id="NUGET-005",
    title="Known-compromised NuGet package version",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-506"),
    recommendation=(
        "Rotate every secret reachable to any process that ran "
        "``dotnet restore`` against this project while the "
        "compromised version was installed. Bump the affected "
        "PackageReference to a post-incident clean version announced "
        "in the citing advisory, regenerate the lock file, and audit "
        "CI build logs for the exfiltration shape the advisory "
        "documents. Pair with NUGET-006 (lock file for reproducible "
        "restores) so a re-publish at the same version literal is "
        "caught by the content hash mismatch."
    ),
    docs_note=(
        "Fires when a PackageReference pins to a version in the "
        "curated compromised-package registry."
    ),
)


def check(project: NuGetProject) -> Finding:
    matches: list[str] = []
    advisories: set[str] = set()
    matched_severities: set[Severity] = set()
    for ref in project.package_refs:
        if ref.version is None:
            continue
        hit = lookup(ref.name, ref.version)
        if hit is None:
            continue
        matches.append(f"{ref.name}@{ref.version}")
        advisories.add(hit.advisory)
        matched_severities.add(hit.severity)
    passed = not matches
    if passed:
        desc = (
            "No PackageReference matches a known-compromised package "
            "version in the curated registry."
        )
        severity = RULE.severity
    else:
        unique = sorted(set(matches))
        ref_summary = ", ".join(unique[:3])
        if len(unique) > 3:
            ref_summary += f" (+{len(unique) - 3} more)"
        adv_summary = "; ".join(sorted(advisories))
        desc = (
            f"{len(matches)} PackageReference(s) match a known-"
            f"compromised package version: {ref_summary}. Rotate any "
            f"secret reachable to ``dotnet restore`` runs against "
            f"this project, then update to a post-incident clean "
            f"version. Advisory: {adv_summary}"
        )
        severity = max(matched_severities, key=severity_rank)
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=severity,
        resource=project.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
