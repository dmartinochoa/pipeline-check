"""NUGET-003, PackageReference missing explicit version."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetProject

RULE = Rule(
    id="NUGET-003",
    title="PackageReference missing explicit version",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Add an explicit ``Version`` attribute to every "
        "``<PackageReference>`` element (``<PackageReference "
        "Include=\"Newtonsoft.Json\" Version=\"13.0.3\" />``). "
        "Without one, NuGet resolves the latest available version at "
        "restore time, so a compromised release reaches the build "
        "unobserved. If your solution uses Central Package "
        "Management (``Directory.Packages.props``), this rule is "
        "skipped because versions are governed centrally."
    ),
    docs_note=(
        "Fires when a ``<PackageReference>`` omits the Version "
        "attribute and the project is not centrally managed."
    ),
)


def check(project: NuGetProject) -> Finding:
    if project.is_central_managed:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=project.path,
            description=(
                "Project uses Central Package Management "
                "(Directory.Packages.props); versions are governed "
                "centrally."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for ref in project.package_refs:
        if ref.version is None:
            offenders.append(ref.name)
    passed = not offenders
    desc = (
        "Every PackageReference declares an explicit version."
        if passed else
        f"{len(offenders)} PackageReference(s) omit an explicit "
        f"version: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. NuGet resolves "
        f"these to the latest available version at restore time."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=project.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
