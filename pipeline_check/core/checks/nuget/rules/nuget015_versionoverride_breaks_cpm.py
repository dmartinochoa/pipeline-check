"""NUGET-015. PackageReference VersionOverride defeats Central Package Management."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetContext, NuGetProject

RULE = Rule(
    id="NUGET-015",
    title="PackageReference VersionOverride defeats Central Package Management",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Remove the ``VersionOverride`` attribute and pin the "
        "central version instead — update "
        "``Directory.Packages.props`` if the override was meant "
        "to bump every consumer, or scope the override to a "
        "child ``Directory.Packages.props`` if only a subtree "
        "of the workspace needs the bump. The point of Central "
        "Package Management is to keep one version per package "
        "across the workspace; per-project ``VersionOverride`` "
        "punches through that contract and lets individual "
        "``.csproj`` files drift away from the central pin "
        "silently.\n\n"
        "Two stable remediation patterns:\n\n"
        "* If the override exists because one project needs a "
        "newer version, accept the bump everywhere: update "
        "``Directory.Packages.props`` to the new version and "
        "delete the override.\n"
        "* If only a subtree of the workspace can take the new "
        "version, scope it with a nested "
        "``Directory.Packages.props`` in the subtree's "
        "directory; CPM honors the closest parent."
    ),
    docs_note=(
        "Re-parses each ``.csproj`` and walks "
        "``<PackageReference>`` entries for the ``VersionOverride`` "
        "attribute. Fires when the project participates in Central "
        "Package Management (i.e. "
        "``NuGetProject.is_central_managed`` is true) AND any "
        "``VersionOverride`` is set.\n\n"
        "Skips projects that don't participate in CPM — those "
        "use ``Version`` directly on every ``PackageReference``, "
        "and the ``VersionOverride`` attribute is a no-op there. "
        "The audit anchor is specifically the case where CPM is "
        "in force and a project punches a hole through it."
    ),
    known_fp=(
        "Some workspaces use ``VersionOverride`` to selectively "
        "test a newer version of a single package in one "
        "project before promoting it to "
        "``Directory.Packages.props``. The rule still fires; "
        "suppress per project / per package with a one-line "
        "rationale naming the test and the planned promotion "
        "milestone.",
    ),
    incident_refs=(
        "Pattern in long-lived .NET monorepos that adopt CPM "
        "during a posture cleanup but never police "
        "``VersionOverride`` usage afterward: individual "
        "projects accumulate stale overrides for packages "
        "whose central version has since moved on, creating "
        "a hidden multi-version graph that defeats the "
        "single-version-per-package invariant CPM is meant to "
        "guarantee.",
    ),
    exploit_example=(
        "<!-- Directory.Packages.props (central): -->\n"
        "<Project>\n"
        "  <PropertyGroup>\n"
        "    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>\n"
        "  </PropertyGroup>\n"
        "  <ItemGroup>\n"
        "    <PackageVersion Include=\"Newtonsoft.Json\" Version=\"13.0.3\" />\n"
        "  </ItemGroup>\n"
        "</Project>\n"
        "\n"
        "<!-- Vulnerable: per-project VersionOverride defeats\n"
        "     the central pin. -->\n"
        "<!-- src/myapp/myapp.csproj: -->\n"
        "<Project>\n"
        "  <ItemGroup>\n"
        "    <PackageReference Include=\"Newtonsoft.Json\"\n"
        "                      VersionOverride=\"13.0.1\" />\n"
        "  </ItemGroup>\n"
        "</Project>\n"
        "\n"
        "<!-- Risk: the central pin moves to 13.0.4 to pick up a\n"
        "     security advisory fix; this project stays at\n"
        "     13.0.1, unaffected by the central bump.\n"
        "     ``dotnet list package`` shows the override but the\n"
        "     output is noisy across a large workspace and the\n"
        "     drift goes unnoticed. -->\n"
        "\n"
        "<!-- Safe: remove the override; accept the central pin. -->\n"
        "<Project>\n"
        "  <ItemGroup>\n"
        "    <PackageReference Include=\"Newtonsoft.Json\" />\n"
        "  </ItemGroup>\n"
        "</Project>"
    ),
)


_MSBUILD_NS = re.compile(r"^\{[^}]+\}")


def _strip_ns(tag: str) -> str:
    return _MSBUILD_NS.sub("", tag)


def _collect_overrides(csproj_path: str) -> list[tuple[str, str]]:
    """Return ``(package_name, override_version)`` pairs from a
    ``.csproj`` (or other MSBuild-shaped project)."""
    try:
        tree = ET.parse(csproj_path)
    except (ET.ParseError, OSError):
        return []
    out: list[tuple[str, str]] = []
    for elem in tree.iter():
        if _strip_ns(elem.tag) != "PackageReference":
            continue
        name = elem.get("Include") or elem.get("Update")
        override = elem.get("VersionOverride")
        if isinstance(name, str) and isinstance(override, str):
            out.append((name, override))
    return out


def check(project: NuGetProject, ctx: NuGetContext) -> Finding:
    if not project.is_central_managed:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=project.path,
            description=(
                "Project does not participate in Central Package "
                "Management; VersionOverride is a no-op."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    # Resolve relative paths against the scan root; the loader
    # stores ``project.path`` as a path relative to the scan input.
    csproj_path = Path(project.path)
    if not csproj_path.is_absolute() and ctx.scan_root is not None:
        csproj_path = ctx.scan_root / csproj_path
    overrides = _collect_overrides(str(csproj_path))
    if not overrides:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=project.path,
            description=(
                "Project participates in CPM and declares no "
                "VersionOverride attributes."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    rendered = ", ".join(
        f"{name} -> {version}" for name, version in overrides[:5]
    )
    suffix = "…" if len(overrides) > 5 else ""
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=project.path,
        description=(
            f"{len(overrides)} PackageReference VersionOverride "
            f"attribute(s) in a CPM-managed project: "
            f"{rendered}{suffix}. Each one punches a hole "
            f"through the central pin."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
