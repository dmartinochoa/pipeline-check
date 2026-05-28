"""GEM-003. Gemfile ``source`` declared over plain HTTP."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import GemFile

RULE = Rule(
    id="GEM-003",
    title="Gemfile source declared over plain HTTP",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-319",),
    recommendation=(
        "Switch the source URL to ``https://``. Bundler 1.7+ "
        "issues a deprecation warning for plain-HTTP sources and "
        "later versions reject them outright; pinning to a "
        "non-HTTPS rubygems / internal mirror is a MITM attack "
        "surface that Bundler's defaults already try to close. "
        "The mirror you point at must serve TLS; if it doesn't, "
        "the deployment is broken in more places than this rule."
    ),
    docs_note=(
        "Fires on any ``source \"http://...\"`` declaration "
        "(top-level or scoped ``source ... do … end`` block). "
        "Companion to NPM-004 / PYPI-004 / MVN-004 / NUGET-004 / "
        "GOMOD-004 / COMPOSER-003 — same risk model."
    ),
    known_fp=(
        "Air-gapped internal mirrors that can't terminate TLS "
        "may legitimately serve plain HTTP within a trusted "
        "network segment. Suppress per repo with a one-line "
        "rationale naming the network boundary; better still, "
        "front the mirror with a TLS-terminating reverse proxy.",
    ),
    incident_refs=(
        "Classic dependency-confusion / MITM surface: an HTTP "
        "gem mirror serving an attacker-injected payload to a "
        "CI runner whose network path is shared with a "
        "compromised peer.",
    ),
    exploit_example=(
        "# Vulnerable: HTTP source.\n"
        "source \"http://internal/gems\"\n"
        "gem \"rails\", \"7.0.4\"\n"
        "\n"
        "# Risk: any MITM on the path between CI and the mirror\n"
        "# can substitute the gem index / .gem payloads.\n"
        "\n"
        "# Safe: TLS-terminated mirror.\n"
        "source \"https://internal/gems\"\n"
        "gem \"rails\", \"7.0.4\""
    ),
)


def check(pom: GemFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for src in pom.sources:
        if src.url.lower().startswith("http://"):
            offenders.append(src.url)
            locations.append(Location(
                path=pom.path,
                start_line=src.line_no, end_line=src.line_no,
            ))
    passed = not offenders
    if passed:
        desc = "All Gemfile sources declare an HTTPS URL."
    else:
        rendered = ", ".join(offenders[:3])
        suffix = "…" if len(offenders) > 3 else ""
        desc = (
            f"{len(offenders)} source declared over plain HTTP: "
            f"{rendered}{suffix}. Switch to HTTPS."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
