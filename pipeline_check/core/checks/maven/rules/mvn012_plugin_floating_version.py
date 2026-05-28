"""MVN-012. pom.xml build plugin uses a floating version."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile

RULE = Rule(
    id="MVN-012",
    title="pom.xml build plugin uses a floating version",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Pin every ``<build><plugins><plugin>`` (and "
        "``<pluginManagement>``) entry to an exact version. "
        "Maven plugins run code during the build lifecycle "
        "(compile, package, install, deploy phases), so a "
        "compromised patch release of a popular plugin executes "
        "in the build environment before any runtime sandbox is "
        "in place — and inherits whatever privileges the build "
        "process has (CI runner write access, deploy keys, AWS "
        "credentials).\n\n"
        "Even more critical than dependency pinning (MVN-001): "
        "dependencies usually only run code in production via "
        "the application that uses them; plugins run code at "
        "build time on every developer's machine and every CI "
        "runner. The xz-utils style patch-release smuggle "
        "pattern is directly applicable to any plugin without "
        "an exact pin.\n\n"
        "Example:\n\n"
        "    <plugin>\n"
        "      <groupId>org.apache.maven.plugins</groupId>\n"
        "      <artifactId>maven-shade-plugin</artifactId>\n"
        "      <version>3.5.1</version>\n"
        "    </plugin>"
    ),
    docs_note=(
        "Re-parses ``pom.xml`` and walks every "
        "``<build><plugins><plugin>``, "
        "``<build><pluginManagement><plugins><plugin>``, and "
        "``<profile><build><plugins><plugin>`` entry. Fires when "
        "the ``<version>`` element is missing, uses a Maven "
        "range (``[1.0,2.0)`` / ``[1.0,)``), is a legacy "
        "floating literal (``LATEST`` / ``RELEASE``), or uses a "
        "property whose resolved value is itself floating "
        "(``${plugin.version}`` resolved via ``<properties>``).\n\n"
        "Distinct from MVN-001 (regular ``<dependencies>`` "
        "floating versions): the consumer-side impact of a "
        "compromised plugin is significantly broader because "
        "plugins execute at build time, not just at app "
        "runtime."
    ),
    known_fp=(
        "Multi-module reactor builds sometimes use "
        "``${project.version}`` (the reactor's own version) on a "
        "plugin that's distributed alongside the reactor — this "
        "is a legitimate exact-pin even though the literal looks "
        "property-shaped. The rule resolves property references "
        "against ``<properties>`` before evaluating so this case "
        "passes when the property is concrete. A property that "
        "isn't defined in the same POM stays unresolved and the "
        "rule conservatively skips it.",
    ),
    incident_refs=(
        "Maven Central plugin compromises have a multiplier "
        "effect: every downstream build using a floating range "
        "picks up the malicious patch automatically. Notable "
        "historical examples include the ``codecov`` "
        "patch-version compromise (April 2021) and pattern "
        "reports against widely-used build plugins where the "
        "maintainer account is briefly compromised.",
    ),
    exploit_example=(
        "<!-- Vulnerable: plugin version not pinned. -->\n"
        "<plugin>\n"
        "  <groupId>org.apache.maven.plugins</groupId>\n"
        "  <artifactId>maven-shade-plugin</artifactId>\n"
        "  <version>[3.0,4.0)</version>\n"
        "</plugin>\n"
        "\n"
        "<!-- Attack: a poisoned 3.5.99 is published. Next mvn\n"
        "     install resolves the range and pulls the bad\n"
        "     plugin. The plugin's mojo runs in the package\n"
        "     phase, executes arbitrary Java in the build\n"
        "     environment, and inherits CI runner privileges. -->\n"
        "\n"
        "<!-- Safe: exact pin. -->\n"
        "<plugin>\n"
        "  <groupId>org.apache.maven.plugins</groupId>\n"
        "  <artifactId>maven-shade-plugin</artifactId>\n"
        "  <version>3.5.1</version>\n"
        "</plugin>"
    ),
)


_MAVEN_NS_RE = re.compile(r"^\{[^}]+\}")
_RANGE_PREFIX_RE = re.compile(r"^\s*[\[\(]")
_FLOATING_LITERALS: frozenset[str] = frozenset({"LATEST", "RELEASE"})
_PROPERTY_RE = re.compile(r"^\$\{([^}]+)\}$")


def _strip_ns(tag: str) -> str:
    return _MAVEN_NS_RE.sub("", tag)


def _findtext_local(elem: ET.Element, name: str) -> str:
    for child in elem:
        if _strip_ns(child.tag) == name:
            return (child.text or "").strip()
    return ""


def _find_child_local(
    elem: ET.Element, name: str,
) -> ET.Element | None:
    for child in elem:
        if _strip_ns(child.tag) == name:
            return child
    return None


def _findall_local(
    elem: ET.Element, name: str,
) -> list[ET.Element]:
    return [c for c in elem if _strip_ns(c.tag) == name]


def _resolve_version(
    version: str, properties: dict[str, str],
) -> str:
    """Resolve up to one level of ``${name}`` substitution."""
    m = _PROPERTY_RE.match(version)
    if not m:
        return version
    key = m.group(1)
    resolved = properties.get(key)
    if isinstance(resolved, str) and resolved:
        return resolved
    return version


def _is_floating(version: str) -> bool:
    if not version:
        return True  # absent version => Maven picks latest
    v = version.strip()
    if not v:
        return True
    if v.upper() in _FLOATING_LITERALS:
        return True
    if _RANGE_PREFIX_RE.match(v):
        return True
    if _PROPERTY_RE.match(v):
        # Unresolved property — can't decide, treat as not floating
        # (conservative) so the rule's signal stays low-FP.
        return False
    return False


def _walk_plugins(
    root: ET.Element, properties: dict[str, str],
) -> list[tuple[str, str, str]]:
    """Return (group:artifact, version, container-label) for every
    declared plugin in build / pluginManagement / profiles."""
    out: list[tuple[str, str, str]] = []

    def walk_build(build: ET.Element, container: str) -> None:
        # <build><plugins><plugin>
        plugins_node = _find_child_local(build, "plugins")
        if plugins_node is not None:
            for plug in _findall_local(plugins_node, "plugin"):
                group_id = _findtext_local(plug, "groupId") or "(default)"
                artifact_id = _findtext_local(plug, "artifactId")
                version_raw = _findtext_local(plug, "version")
                resolved = _resolve_version(version_raw, properties)
                out.append((
                    f"{group_id}:{artifact_id}", resolved, container,
                ))
        # <build><pluginManagement><plugins><plugin>
        pm = _find_child_local(build, "pluginManagement")
        if pm is not None:
            inner = _find_child_local(pm, "plugins")
            if inner is not None:
                for plug in _findall_local(inner, "plugin"):
                    group_id = _findtext_local(plug, "groupId") or "(default)"
                    artifact_id = _findtext_local(plug, "artifactId")
                    version_raw = _findtext_local(plug, "version")
                    resolved = _resolve_version(version_raw, properties)
                    out.append((
                        f"{group_id}:{artifact_id}", resolved,
                        f"{container}/pluginManagement",
                    ))

    build = _find_child_local(root, "build")
    if build is not None:
        walk_build(build, "build")
    profiles = _find_child_local(root, "profiles")
    if profiles is not None:
        for profile in _findall_local(profiles, "profile"):
            profile_id = _findtext_local(profile, "id") or "anon"
            inner_build = _find_child_local(profile, "build")
            if inner_build is not None:
                walk_build(inner_build, f"profile:{profile_id}/build")
    return out


def check(pom: PomFile) -> Finding:
    if pom.is_settings:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="settings.xml has no project plugins.",
            recommendation=RULE.recommendation, passed=True,
        )
    try:
        root = ET.fromstring(pom.text)
    except ET.ParseError:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="pom.xml parse error; can't audit plugins.",
            recommendation=RULE.recommendation, passed=True,
        )
    plugins = _walk_plugins(root, pom.properties)
    if not plugins:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="pom.xml declares no build plugins.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for coord, version, container in plugins:
        if not _is_floating(version):
            continue
        label = (
            f"{coord} (no version)" if not version
            else f"{coord} {version}"
        )
        offenders.append(f"{container}/{label}")
        artifact = coord.split(":", 1)[-1]
        line_no = 1
        marker = f"<artifactId>{artifact}</artifactId>"
        if marker in pom.text:
            line_no = pom.text[:pom.text.index(marker)].count("\n") + 1
        locations.append(Location(
            path=pom.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "Every declared build plugin pins to an exact version."
        if passed else
        f"{len(offenders)} plugin / plugins are not exact-pinned: "
        f"{'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Each one runs "
        f"during the build lifecycle; a compromised patch "
        f"release executes in the build environment."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
