"""MVN-006, pom.xml pins a known-compromised Maven Central artifact."""
from __future__ import annotations

from ...base import Finding, Location, Severity, severity_rank
from ...rule import Rule
from .._compromised_packages import lookup
from ..base import PomFile, iter_real_dependencies, resolve_version

RULE = Rule(
    id="MVN-006",
    title="pom.xml pins a known-compromised Maven Central artifact version",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-1395"),
    recommendation=(
        "Bump the affected dependency to a post-incident clean "
        "version announced in the citing advisory. For Log4Shell and "
        "Spring4Shell class CVEs, rotate any secret reachable to "
        "production processes during the exposure window (most "
        "Maven-side advisories enable unauthenticated RCE on the "
        "deployed app, so any in-process credential should be "
        "considered exposed). Pair with MVN-005 (strict checksum "
        "policy) so future bytes published at the same coordinate "
        "are rejected, and with a vuln-scanning step (Snyk, "
        "Dependency-Check) for breadth beyond the curated registry."
    ),
    docs_note=(
        "Walks every non-managed dependency against the curated "
        "compromised-package registry in "
        "``pipeline_check.core.checks.maven._compromised_packages``. "
        "Group/artifact matching is case-insensitive; version "
        "matching is exact (with optional regex fallback for "
        "advisories that span a range). Property references are "
        "resolved against the POM's ``<properties>`` block so "
        "``${log4j.version}`` is checked against its resolved "
        "value. ``<dependencyManagement>`` entries are skipped to "
        "avoid double-counting when the same coordinate is both "
        "managed and consumed."
    ),
    known_fp=(
        "The registry covers only public, advisory-confirmed "
        "compromises and a small set of canonical CVE-mapped "
        "vulnerable versions (Log4Shell, Spring4Shell, Text4Shell). "
        "For broader CVE coverage, run a dependency-vulnerability "
        "scanner (OWASP Dependency-Check, Snyk, Trivy) alongside "
        "pipeline-check; MVN-006 is the curated supply-chain anchor.",
    ),
    incident_refs=(
        "Log4Shell, CVE-2021-44228 (December 2021): the canonical "
        "Maven-side ecosystem-wide RCE. Mass exploitation began "
        "within hours of public disclosure. "
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "Spring4Shell, CVE-2022-22965 (March 2022): RCE via the "
        "spring-beans data-binding path on JDK 9+ WAR deployments. "
        "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
    ),
    exploit_example=(
        "<!-- Vulnerable: pinned to a Log4Shell-affected version. -->\n"
        "<dependency>\n"
        "  <groupId>org.apache.logging.log4j</groupId>\n"
        "  <artifactId>log4j-core</artifactId>\n"
        "  <version>2.14.1</version>\n"
        "</dependency>\n"
        "\n"
        "<!-- Attack: any log line that interpolates an attacker-\n"
        "     controlled string (User-Agent, search field) triggers\n"
        "     a JNDI lookup, which fetches and executes attacker-\n"
        "     served bytecode. One curl is enough to RCE. -->\n"
        "\n"
        "<!-- Safe: post-incident clean version. 2.17.1 disables\n"
        "     the JNDI lookup substitution entirely. -->\n"
        "<dependency>\n"
        "  <groupId>org.apache.logging.log4j</groupId>\n"
        "  <artifactId>log4j-core</artifactId>\n"
        "  <version>2.17.1</version>\n"
        "</dependency>\n"
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
    matches: list[str] = []
    locations: list[Location] = []
    advisories: set[str] = set()
    matched_severities: set[Severity] = set()
    for dep in iter_real_dependencies(pom):
        if dep.version is None:
            continue
        resolved = resolve_version(dep.version, pom.properties)
        hit = lookup(dep.group_id, dep.artifact_id, resolved)
        if hit is None:
            continue
        matches.append(f"{dep.group_id}:{dep.artifact_id}:{resolved}")
        advisories.add(hit.advisory)
        matched_severities.add(hit.severity)
        locations.append(Location(
            path=pom.path, start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not matches
    if passed:
        desc = (
            "No dependency matches a known-compromised Maven Central "
            "artifact version in the curated registry."
        )
        severity = RULE.severity
    else:
        unique = sorted(set(matches))
        ref_summary = ", ".join(unique[:3])
        if len(unique) > 3:
            ref_summary += f" (+{len(unique) - 3} more)"
        adv_summary = "; ".join(sorted(advisories))
        desc = (
            f"{len(matches)} dependency / dependencies match a known-"
            f"compromised Maven Central version: {ref_summary}. "
            f"Update to a post-incident clean version published in "
            f"the citing advisory. Advisory: {adv_summary}"
        )
        severity = max(matched_severities, key=severity_rank)
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
