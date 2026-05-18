"""MVN-001, pom.xml dependency uses a floating Maven version range."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile, iter_real_dependencies, resolve_version

RULE = Rule(
    id="MVN-001",
    title="pom.xml dependency uses a floating version range",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Replace Maven version ranges (``[1.0,2.0)``, ``[1.0,)``, "
        "``LATEST``, ``RELEASE``) with an exact version pin "
        "(``<version>1.2.3</version>``). The range form lets Maven "
        "pick any later release that fits, so a compromised patch "
        "version reaches the build without a code change. Pair the "
        "exact-pin manifest with a verified-by-checksum or "
        "verified-by-signature repository policy (MVN-005) so a "
        "tampered jar at the same version literal still fails."
    ),
    docs_note=(
        "Fires on any ``<version>`` value that matches the Maven "
        "range grammar: bracket-or-paren-delimited intervals "
        "(``[1.0,2.0)``, ``(,3.0]``), open ranges (``[1.0,)``), "
        "or the legacy floating tokens ``LATEST`` / ``RELEASE``. "
        "Property references (``${spring.version}``) are resolved "
        "against the POM's ``<properties>`` block before the check "
        "runs, so a property pointing at a range still fires.\n\n"
        "Managed entries in ``<dependencyManagement>`` are NOT "
        "evaluated by this rule (that's MVN-004's surface) because "
        "the version-management section's purpose is to centralize "
        "version literals, not consume them at install time."
    ),
    known_fp=(
        "Multi-module reactor builds sometimes legitimately use "
        "``${project.version}`` (the reactor's own version) which "
        "resolves to a plain string from the parent POM. The rule "
        "honors property substitution so this passes; if it does "
        "fire on a deliberate range (e.g. a build-time tool pulled "
        "via a range you control), suppress with a one-line "
        "rationale.",
    ),
    incident_refs=(
        "Codecov Bash Uploader compromise (April 2021): downstream "
        "builds pulling Codecov via mutable references shipped the "
        "tampered uploader for two months. The Maven-side analog is "
        "any range-pinned ``codecov`` / scanner / agent jar; same "
        "exposure window. https://about.codecov.io/security-update/",
    ),
    exploit_example=(
        "<!-- Vulnerable: range admits a future patch version. -->\n"
        "<dependency>\n"
        "  <groupId>org.example</groupId>\n"
        "  <artifactId>util</artifactId>\n"
        "  <version>[1.0,2.0)</version>\n"
        "</dependency>\n"
        "\n"
        "<!-- Attack: the maintainer's account is hijacked and a\n"
        "     malicious 1.7.99 is published. Next ``mvn install``\n"
        "     resolves the range and pulls the poisoned jar without\n"
        "     any pom.xml change. -->\n"
        "\n"
        "<!-- Safe: exact pin. A swap at the same coordinate breaks\n"
        "     the checksum/signature gate (MVN-005). -->\n"
        "<dependency>\n"
        "  <groupId>org.example</groupId>\n"
        "  <artifactId>util</artifactId>\n"
        "  <version>1.7.0</version>\n"
        "</dependency>\n"
    ),
)


# Maven range grammar: bracket / paren delimited interval (``[1,2)``,
# ``(1,3]``, ``[1.0,)``, ``(,2.0]``) or the legacy floating literals.
_RANGE_PREFIX_RE = re.compile(r"^\s*[\[\(]")
_FLOATING_LITERALS: frozenset[str] = frozenset({"LATEST", "RELEASE"})


def _is_floating(version: str) -> bool:
    v = version.strip()
    if not v:
        return False
    if v.upper() in _FLOATING_LITERALS:
        return True
    return bool(_RANGE_PREFIX_RE.match(v))


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
        if dep.version is None:
            continue
        resolved = resolve_version(dep.version, pom.properties)
        if not _is_floating(resolved):
            continue
        offenders.append(f"{dep.coordinate} (resolves to {resolved!r})")
        locations.append(Location(
            path=pom.path, start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    desc = (
        "Every dependency in pom.xml is pinned to an exact version."
        if passed else
        f"{len(offenders)} dependency / dependencies use a floating "
        f"version range: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The next install can "
        f"pick a later release, including a compromised one."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
