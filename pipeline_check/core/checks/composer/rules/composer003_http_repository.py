"""COMPOSER-003. ``repositories`` entry uses an HTTP (non-TLS) URL."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-003",
    title="composer.json repository declared over plain HTTP",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-319",),
    recommendation=(
        "Switch the repository URL to ``https://``. Composer "
        "since 1.8 ships with ``config.secure-http: true`` by "
        "default, which rejects any HTTP source; downgrading "
        "that flag (or running an older Composer) re-enables "
        "the MITM attack surface. The mirror you point at must "
        "serve TLS; if it doesn't, the deployment is broken in "
        "more places than this rule. Once on HTTPS, also pin "
        "the upstream certificate or registry signing key if "
        "the project supports it."
    ),
    docs_note=(
        "Fires on any ``repositories`` entry whose ``url`` "
        "starts with ``http://``. Covers Composer, VCS, "
        "Artifact, and Path repository types alike. ``path://`` "
        "and ``file://`` entries are skipped (local-only). "
        "Companion to NPM-004 / PYPI-004 / MVN-004 / NUGET-004 "
        "/ GOMOD-004 — same risk model."
    ),
    known_fp=(
        "Air-gapped internal mirrors that cannot terminate TLS "
        "may legitimately serve plain HTTP within a trusted "
        "network segment. Suppress per repo with a one-line "
        "rationale naming the network boundary; better still, "
        "front the mirror with a TLS-terminating reverse proxy.",
    ),
    incident_refs=(
        "Classic dependency-confusion / MITM surface: an HTTP "
        "registry mirror serving an attacker-injected payload "
        "to a CI runner whose network path is shared with a "
        "compromised peer.",
    ),
    exploit_example=(
        "// Vulnerable: HTTP composer repository.\n"
        "{\n"
        "  \"repositories\": [\n"
        "    {\n"
        "      \"type\": \"composer\",\n"
        "      \"url\": \"http://internal.example/composer\"\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "\n"
        "// Risk: any MITM on the path between CI and the\n"
        "// mirror can substitute packages.json / dist URLs.\n"
        "\n"
        "// Safe: TLS-terminated mirror.\n"
        "{\n"
        "  \"repositories\": [\n"
        "    {\n"
        "      \"type\": \"composer\",\n"
        "      \"url\": \"https://internal.example/composer\"\n"
        "    }\n"
        "  ]\n"
        "}"
    ),
)


def check(pom: ComposerFile) -> Finding:
    offenders: list[tuple[str, str]] = []
    locations: list[Location] = []
    for repo in pom.repositories:
        url = repo.url.strip().lower()
        if not url:
            continue
        if url.startswith("http://"):
            offenders.append((repo.type, repo.url))
            locations.append(Location(
                path=pom.path,
                start_line=repo.line_no, end_line=repo.line_no,
            ))
    passed = not offenders
    if passed:
        desc = (
            "All repository entries declare an HTTPS URL or a "
            "local-only source."
        )
    else:
        rendered = ", ".join(
            f"{rtype}:{url}" for rtype, url in offenders[:3]
        )
        suffix = "…" if len(offenders) > 3 else ""
        desc = (
            f"{len(offenders)} repository entry / entries declared "
            f"over plain HTTP: {rendered}{suffix}. Switch to "
            f"HTTPS."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
