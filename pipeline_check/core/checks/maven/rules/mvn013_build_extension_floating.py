"""MVN-013. pom.xml build extension uses a floating version."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile

RULE = Rule(
    id="MVN-013",
    title="pom.xml build extension uses a floating version",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Pin every ``<build><extensions><extension>`` entry to "
        "an exact version. Build extensions load during Maven's "
        "early-init phase — *before* any plugin runs — and can "
        "register custom lifecycle phases, deployment "
        "protocols, or POM resolvers. A compromised extension "
        "patch release executes in the build environment with "
        "the same privileges any other build code would have, "
        "and runs on every developer's machine and every CI "
        "runner.\n\n"
        "Example:\n\n"
        "    <build>\n"
        "      <extensions>\n"
        "        <extension>\n"
        "          <groupId>org.apache.maven.wagon</groupId>\n"
        "          <artifactId>wagon-ssh</artifactId>\n"
        "          <version>3.5.3</version>\n"
        "        </extension>\n"
        "      </extensions>\n"
        "    </build>\n\n"
        "Extensions are less commonly used than plugins but "
        "carry the same patch-release-smuggle risk; the limited "
        "surface (most projects use 0 or 1 extensions) makes "
        "pinning them a trivial maintenance cost."
    ),
    docs_note=(
        "Re-parses ``pom.xml`` and walks every "
        "``<build><extensions><extension>`` (and the equivalent "
        "inside ``<profile><build>``). Fires on the same "
        "floating shapes MVN-012 catches for plugins: missing "
        "``<version>``, Maven range (``[1.0,2.0)`` / "
        "``[1.0,)``), legacy floating literals (``LATEST`` / "
        "``RELEASE``).\n\n"
        "Distinct from MVN-012 (plugins) because extensions "
        "load earlier in the Maven lifecycle and have different "
        "remediation guidance (extensions are usually wagons / "
        "lifecycle providers, not build-step actors)."
    ),
    known_fp=(
        "Library projects that consume their own snapshot "
        "versions in a multi-module reactor may legitimately "
        "use ``${project.version}`` on an extension. The rule "
        "resolves property references against ``<properties>`` "
        "before evaluating, so the case passes when the "
        "property is concrete.",
    ),
    incident_refs=(
        "Maven Central extension compromises follow the same "
        "patch-release-smuggle pattern as plugins. Because "
        "extensions load before plugins, a malicious extension "
        "can also tamper with the plugin loading process, "
        "amplifying the blast radius beyond what the extension "
        "itself does.",
    ),
    exploit_example=(
        "<!-- Vulnerable: extension version is a range. -->\n"
        "<build>\n"
        "  <extensions>\n"
        "    <extension>\n"
        "      <groupId>org.apache.maven.wagon</groupId>\n"
        "      <artifactId>wagon-ssh</artifactId>\n"
        "      <version>[3.0,)</version>\n"
        "    </extension>\n"
        "  </extensions>\n"
        "</build>\n"
        "\n"
        "<!-- Safe: exact pin. -->\n"
        "<build>\n"
        "  <extensions>\n"
        "    <extension>\n"
        "      <groupId>org.apache.maven.wagon</groupId>\n"
        "      <artifactId>wagon-ssh</artifactId>\n"
        "      <version>3.5.3</version>\n"
        "    </extension>\n"
        "  </extensions>\n"
        "</build>"
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


def _resolve_version(version: str, properties: dict[str, str]) -> str:
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
        return True
    v = version.strip()
    if not v:
        return True
    if v.upper() in _FLOATING_LITERALS:
        return True
    if _RANGE_PREFIX_RE.match(v):
        return True
    if _PROPERTY_RE.match(v):
        return False
    return False


def _walk_extensions(
    root: ET.Element, properties: dict[str, str],
) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []

    def walk_build(build: ET.Element, container: str) -> None:
        exts_node = _find_child_local(build, "extensions")
        if exts_node is None:
            return
        for ext in _findall_local(exts_node, "extension"):
            group_id = _findtext_local(ext, "groupId") or "(default)"
            artifact_id = _findtext_local(ext, "artifactId")
            version_raw = _findtext_local(ext, "version")
            resolved = _resolve_version(version_raw, properties)
            out.append((
                f"{group_id}:{artifact_id}", resolved, container,
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
            description="settings.xml has no project extensions.",
            recommendation=RULE.recommendation, passed=True,
        )
    try:
        root = ET.fromstring(pom.text)
    except ET.ParseError:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "pom.xml parse error; can't audit extensions."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    extensions = _walk_extensions(root, pom.properties)
    if not extensions:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="pom.xml declares no build extensions.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for coord, version, container in extensions:
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
        "Every declared build extension pins to an exact version."
        if passed else
        f"{len(offenders)} build extension(s) are not exact-"
        f"pinned: {'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Extensions load "
        f"during Maven's early-init phase, before plugins."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
