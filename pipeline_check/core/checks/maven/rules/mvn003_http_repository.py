"""MVN-003, pom.xml declares a plaintext-HTTP Maven repository."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import PomFile

RULE = Rule(
    id="MVN-003",
    title="pom.xml declares a plaintext-HTTP Maven repository",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-8", "CICD-SEC-3"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-319",),
    recommendation=(
        "Change every ``<repository><url>`` to ``https://`` and "
        "delete any ``<repository>`` whose host doesn't expose TLS. "
        "Plaintext-HTTP repositories let a network attacker swap "
        "downloaded jars in flight (the canonical Maven supply-chain "
        "MITM attack); ``https://`` plus the repository's published "
        "checksums (MVN-005) is the minimum baseline."
    ),
    docs_note=(
        "Fires on any ``<repository>``, ``<pluginRepository>``, "
        "or ``<distributionManagement>`` URL using the ``http://`` "
        "scheme. ``file://`` and ``https://`` are exempt. The rule "
        "evaluates both project POMs and per-user / per-CI "
        "``settings.xml`` mirror entries via the orchestrator."
    ),
    known_fp=(
        "Internal Maven repositories on a fully-isolated build "
        "network sometimes legitimately serve over HTTP. If you can "
        "actually attest that the network path is end-to-end "
        "untamperable (a single-tenant air-gapped subnet), suppress "
        "with a rationale naming that boundary.",
    ),
    incident_refs=(
        "Maven Central enforced HTTPS-only for the central "
        "repository in January 2020; the legacy ``http://repo1."
        "maven.org`` endpoint was retired specifically because of "
        "MITM-tampering attacks against downstream consumers. "
        "https://blog.sonatype.com/central-repository-moving-to-https",
    ),
    exploit_example=(
        "<!-- Vulnerable: Maven fetches every dependency tarball\n"
        "     and pom from this repository over plaintext HTTP. Any\n"
        "     on-path attacker (compromised proxy, malicious VPN\n"
        "     exit, internal mirror BGP hijack) substitutes a\n"
        "     backdoored jar in flight. Maven's checksum verification\n"
        "     only checks against checksums served by the SAME host,\n"
        "     so the attacker swaps both the artifact and the\n"
        "     adjacent .sha1 file. -->\n"
        "<project>\n"
        "  <repositories>\n"
        "    <repository>\n"
        "      <id>internal-mirror</id>\n"
        "      <url>http://nexus.internal.example.com/repository/maven-public/</url>\n"
        "    </repository>\n"
        "  </repositories>\n"
        "</project>\n"
        "\n"
        "<!-- Safe: HTTPS gives TLS for both jar and checksum fetch.\n"
        "     For internal Nexus / Artifactory hosts on a private CA,\n"
        "     install the CA in the build agent's truststore;\n"
        "     never fall back to plaintext HTTP. -->\n"
        "<project>\n"
        "  <repositories>\n"
        "    <repository>\n"
        "      <id>internal-mirror</id>\n"
        "      <url>https://nexus.internal.example.com/repository/maven-public/</url>\n"
        "    </repository>\n"
        "  </repositories>\n"
        "</project>"
    ),
)


def _is_plaintext(url: str) -> bool:
    return url.lower().startswith("http://")


def check(pom: PomFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for repo in pom.repositories:
        if _is_plaintext(repo.url):
            offenders.append(f"{repo.section}/{repo.id}: {repo.url}")
            locations.append(Location(
                path=pom.path, start_line=repo.line_no, end_line=repo.line_no,
            ))
    for mirror in pom.mirrors:
        if _is_plaintext(mirror.url):
            offenders.append(f"mirror/{mirror.id}: {mirror.url}")
            locations.append(Location(
                path=pom.path, start_line=mirror.line_no, end_line=mirror.line_no,
            ))
    passed = not offenders
    desc = (
        "Every declared repository serves over HTTPS."
        if passed else
        f"{len(offenders)} repository / repositories use plaintext "
        f"HTTP: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A network attacker can "
        f"swap downloaded artifacts in flight."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
