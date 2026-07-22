"""MVN-016. build.gradle re-enables HTTP via allowInsecureProtocol = true."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile

RULE = Rule(
    id="MVN-016",
    title="build.gradle re-enables HTTP via allowInsecureProtocol = true",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-319",),
    recommendation=(
        "Remove ``allowInsecureProtocol = true`` and serve the "
        "repository over HTTPS. Gradle 7+ refuses to resolve "
        "dependencies from an ``http://`` repository unless the "
        "build explicitly opts back in with this flag, precisely "
        "because a plain-HTTP repo is a MITM surface: anyone on the "
        "network path between the build and the repo can substitute "
        "the artifacts Gradle downloads (and Gradle resolves "
        "build-script plugins the same way, so the swap can be "
        "build-time RCE). Point the ``maven { url ... }`` at an "
        "HTTPS endpoint; if the repo can't terminate TLS, front it "
        "with a TLS-terminating reverse proxy rather than disabling "
        "the protection."
    ),
    docs_note=(
        "Fires when a Gradle build script (``build.gradle`` / "
        "``build.gradle.kts``) contains "
        "``allowInsecureProtocol = true`` (the Groovy form) or "
        "``isAllowInsecureProtocol = true`` (the Kotlin DSL "
        "property), the explicit opt-out Gradle 7+ requires to "
        "allow an ``http://`` repository.\n\n"
        "Complements MVN-003 (an ``http://`` repository URL). "
        "MVN-003 matches the literal URL; this rule catches the "
        "enabling flag, which fires even when the URL itself is a "
        "property the regex extractor can't resolve to a literal "
        "``http://`` string."
    ),
    known_fp=(
        "A build that only ever resolves from a trusted internal "
        "mirror on an isolated network segment may set the flag "
        "deliberately. Suppress per line with a rationale naming "
        "the network boundary; the HTTPS / TLS-proxy path is "
        "strictly safer.",
    ),
    incident_refs=(
        "Gradle made ``http://`` repositories opt-in (requiring "
        "``allowInsecureProtocol``) in Gradle 7 specifically "
        "because unencrypted artifact resolution is a "
        "man-in-the-middle surface; re-enabling it reopens that "
        "surface for both dependencies and build-script plugins.",
    ),
    exploit_example=(
        "// Vulnerable: HTTP repo re-enabled in build.gradle.\n"
        "repositories {\n"
        "    maven {\n"
        "        url 'http://repo.internal/maven'\n"
        "        allowInsecureProtocol = true\n"
        "    }\n"
        "}\n"
        "\n"
        "// Attack: a MITM on the path to repo.internal serves a\n"
        "// backdoored dependency (or a poisoned build-script\n"
        "// plugin, resolved the same way). The build downloads and\n"
        "// runs it; nothing authenticates the bytes.\n"
        "\n"
        "// Safe: HTTPS endpoint, flag removed.\n"
        "repositories {\n"
        "    maven { url 'https://repo.internal/maven' }\n"
        "}"
    ),
)


# Matches both the Groovy ``allowInsecureProtocol = true`` and the
# Kotlin DSL ``isAllowInsecureProtocol = true`` (the latter contains
# the former as a case-insensitive substring). The ``=`` is optional
# so the ``allowInsecureProtocol(true)`` setter form matches, and the
# Gradle lazy-property ``allowInsecureProtocol.set(true)`` form is
# covered by the ``.set(`` alternative.
_FLAG_RE = re.compile(
    r"allowInsecureProtocol\s*(?:\.set\s*\(|[=(])?\s*true",
    re.IGNORECASE,
)
#: Single- / double-quoted string literals, blanked out of a line
#: prefix before the ``//`` line-comment check so an embedded URL
#: (``"http://…"``) isn't mistaken for a comment.
_QUOTED_STRING_RE = re.compile(r"'[^']*'|\"[^\"]*\"")
_GRADLE_SUFFIXES: tuple[str, ...] = ("build.gradle", "build.gradle.kts")


def check(pom: PomFile) -> Finding:
    if not pom.path.endswith(_GRADLE_SUFFIXES):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="Not a Gradle build script; flag does not apply.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[int] = []
    locations: list[Location] = []
    for m in _FLAG_RE.finditer(pom.text):
        line_start = pom.text.rfind("\n", 0, m.start()) + 1
        prefix = pom.text[line_start:m.start()]
        # Skip a flag inside a ``//`` line comment, but first blank out
        # quoted string literals so a repo URL like ``url "http://…"``
        # earlier on the same line isn't misread as a comment (that
        # would be a false negative on the exact unsafe pattern).
        if "//" in _QUOTED_STRING_RE.sub("", prefix):
            continue
        line_no = pom.text[:m.start()].count("\n") + 1
        offenders.append(line_no)
        locations.append(Location(
            path=pom.path, start_line=line_no, end_line=line_no,
        ))
    passed = not offenders
    desc = (
        "Build script does not re-enable insecure HTTP repositories."
        if passed else
        f"allowInsecureProtocol = true set at "
        f"line(s) {', '.join(str(n) for n in offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. This opts back in to "
        f"plain-HTTP artifact resolution, a MITM surface for both "
        f"dependencies and build-script plugins."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
