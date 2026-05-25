"""NUGET-002, PackageReference uses a wildcard prerelease version."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetProject

RULE = Rule(
    id="NUGET-002",
    title="Wildcard prerelease NuGet version",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Replace wildcard prerelease specifiers (``*-*``, "
        "``1.0.0-*``) with an exact version pin including the "
        "prerelease tag (``1.0.0-beta.1``). The ``-*`` suffix tells "
        "NuGet to resolve the latest prerelease matching the prefix, "
        "so any newly published prerelease (including a malicious "
        "one) is pulled on the next restore. Prerelease packages are "
        "often less reviewed than stable releases, increasing the "
        "attack surface."
    ),
    docs_note=(
        "Fires when Version ends with ``-*`` or equals ``*-*``."
    ),
)


def _is_wildcard_prerelease(version: str) -> bool:
    v = version.strip()
    return v == "*-*" or v.endswith("-*")


def check(project: NuGetProject) -> Finding:
    offenders: list[str] = []
    for ref in project.package_refs:
        if ref.version is None:
            continue
        if _is_wildcard_prerelease(ref.version):
            offenders.append(f"{ref.name}: {ref.version}")
    passed = not offenders
    desc = (
        "No PackageReference uses a wildcard prerelease specifier."
        if passed else
        f"{len(offenders)} PackageReference(s) use a wildcard "
        f"prerelease version: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Any newly published "
        f"prerelease matching the prefix is pulled on the next "
        f"restore."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=project.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
