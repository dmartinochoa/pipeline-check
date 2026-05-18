"""MVN-004, pom.xml dependency omits an explicit <version>."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile, iter_real_dependencies

RULE = Rule(
    id="MVN-004",
    title="pom.xml dependency omits an explicit <version>",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Every ``<dependency>`` must carry a ``<version>``, either "
        "inline or via a ``<dependencyManagement>`` block in this "
        "POM or a parent. Implicit-version dependencies inherit "
        "whatever Maven resolves at build time (often the highest "
        "available release), so a maintainer push to a higher "
        "version reaches the build unobserved. If the version is "
        "genuinely managed by a parent POM, declare it in this "
        "POM's ``<dependencyManagement>`` so the resolved version "
        "is at least pinned at the project level."
    ),
    docs_note=(
        "Fires on any non-managed ``<dependency>`` whose "
        "``<version>`` element is absent or empty. Managed entries "
        "in ``<dependencyManagement>`` are the *source* of the "
        "version; they are checked separately by MVN-001 / MVN-002 "
        "for floating ranges and SNAPSHOTs but not by this rule."
    ),
    known_fp=(
        "Spring Boot starters and other BOM-managed dependencies "
        "intentionally omit ``<version>`` so the imported BOM "
        "decides. The rule still fires because the BOM is not "
        "visible at static-analysis time; suppress with a rationale "
        "naming the BOM POM, or import the BOM explicitly into "
        "this project's ``<dependencyManagement>``.",
    ),
)


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
        if dep.version is not None and dep.version.strip():
            continue
        offenders.append(f"{dep.group_id}:{dep.artifact_id}")
        locations.append(Location(
            path=pom.path, start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    desc = (
        "Every dependency in pom.xml declares an explicit version."
        if passed else
        f"{len(offenders)} dependency / dependencies omit "
        f"``<version>``: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Maven resolves these "
        f"at build time from whatever parent / BOM is in scope."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
