"""MVN-005, Maven repository accepts artifacts without strict checksum gating."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile

RULE = Rule(
    id="MVN-005",
    title="Maven repository accepts artifacts without strict checksum gating",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-353",),
    recommendation=(
        "On every ``<repository>``, set ``<checksumPolicy>fail"
        "</checksumPolicy>`` under both ``<releases>`` and "
        "``<snapshots>``. Maven's default policy is ``warn``: a "
        "checksum mismatch logs a line and the build continues with "
        "the tampered artifact. ``fail`` halts on any mismatch, "
        "which is the only setting that actually gates the build on "
        "checksum integrity. For Maven 3.9.x and newer, prefer the "
        "global ``-C`` / ``-c`` invocation flag in CI plus per-repo "
        "``fail`` so a missing checksumPolicy doesn't downgrade to "
        "warn at runtime."
    ),
    docs_note=(
        "Fires when any ``<repository>`` / ``<pluginRepository>`` "
        "declares ``<checksumPolicy>warn</checksumPolicy>`` or "
        "``<checksumPolicy>ignore</checksumPolicy>`` (explicitly "
        "weakened from the default), or when the policy is absent "
        "AND the URL is not Maven Central (Central enforces "
        "checksums server-side, so the policy is moot for that "
        "single repo). Internal mirrors and third-party repositories "
        "are the canonical place this rule fires."
    ),
    known_fp=(
        "Internal artifact repositories with server-side checksum "
        "verification (a Nexus / Artifactory deployment configured "
        "to reject mismatched uploads) functionally meet the "
        "control even with ``warn`` at the client. The rule cannot "
        "see the server-side policy; suppress with a rationale "
        "naming the platform / version that enforces it.",
    ),
)


_MAVEN_CENTRAL_URLS: frozenset[str] = frozenset({
    "https://repo.maven.apache.org/maven2",
    "https://repo.maven.apache.org/maven2/",
    "https://repo1.maven.org/maven2",
    "https://repo1.maven.org/maven2/",
})


def _is_central(url: str) -> bool:
    # Lowercase before comparing so a mixed-case form like
    # ``https://Repo1.Maven.Org/maven2`` is still recognized as Central
    # (URL host comparison is case-insensitive).
    u = url.strip().lower().rstrip("/")
    return f"{u}/" in _MAVEN_CENTRAL_URLS or u in {
        "https://repo.maven.apache.org/maven2",
        "https://repo1.maven.org/maven2",
    }


def _is_gradle_pom(pom: PomFile) -> bool:
    return pom.path.endswith((".gradle", ".gradle.kts"))


def check(pom: PomFile) -> Finding:
    # ``<checksumPolicy>`` is a Maven-XML concept with no build.gradle
    # equivalent: a Gradle-parsed ``maven { url ... }`` repo always has
    # ``checksum_policy=None``, so flagging it would fire on every Gradle
    # HTTPS repo with a recommendation that can't be applied. Gradle's
    # integrity mechanism is ``verification-metadata.xml`` (out of scope
    # for this rule), so skip Gradle-origin files entirely.
    if _is_gradle_pom(pom):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "Gradle build file; <checksumPolicy> is a Maven-XML "
                "concept that does not apply. Gradle integrity is "
                "enforced via verification-metadata.xml."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for repo in pom.repositories:
        if _is_central(repo.url):
            continue
        # Explicit weakening is always a finding.
        if repo.checksum_policy in {"warn", "ignore"}:
            offenders.append(
                f"{repo.section}/{repo.id} ({repo.url}): checksumPolicy"
                f"={repo.checksum_policy}"
            )
            locations.append(Location(
                path=pom.path, start_line=repo.line_no, end_line=repo.line_no,
            ))
            continue
        # Absent policy on a non-Central repo: Maven's runtime default
        # is ``warn``, so silence here is the same as ``warn``.
        if repo.checksum_policy is None:
            offenders.append(
                f"{repo.section}/{repo.id} ({repo.url}): no "
                f"checksumPolicy declared (defaults to warn)"
            )
            locations.append(Location(
                path=pom.path, start_line=repo.line_no, end_line=repo.line_no,
            ))
    passed = not offenders
    desc = (
        "Every non-Central repository declares <checksumPolicy>fail."
        if passed else
        f"{len(offenders)} repository / repositories accept artifacts "
        f"without strict checksum gating: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The build continues on "
        f"a tampered jar with only a warning in the log."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
