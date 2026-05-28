"""COMPOSER-010. config.secure-http: false (HTTPS enforcement disabled)."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-010",
    title="composer.json config.secure-http: false disables HTTPS enforcement",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-319", "CWE-295"),
    recommendation=(
        "Remove the ``config.secure-http: false`` entry from "
        "``composer.json`` (or set it back to ``true``). "
        "Composer's default has been ``secure-http: true`` "
        "since 1.8; the explicit ``false`` is a deliberate "
        "downgrade that lets the project pull packages from "
        "plain-HTTP sources without complaint. That defeats "
        "the same defense that COMPOSER-003 protects on the "
        "individual ``repositories`` URL — a plain-HTTP "
        "mirror, a typosquatted public source, anything the "
        "package resolver finds is now eligible for fetch.\n\n"
        "If the deployment legitimately needs to talk to an "
        "internal mirror that can't terminate TLS, front the "
        "mirror with a TLS-terminating reverse proxy. The "
        "``secure-http: false`` escape hatch is a project-wide "
        "weakening that almost always outlives the local "
        "constraint that motivated it."
    ),
    docs_note=(
        "Fires when ``config.secure-http`` is explicitly set "
        "to the boolean ``false`` in ``composer.json``. The "
        "default value (``true``) is the safe posture, so the "
        "rule only trips on an explicit downgrade. Companion "
        "to COMPOSER-003 (per-repository HTTP URL): "
        "COMPOSER-003 catches one offending URL; "
        "COMPOSER-010 catches the project-wide flag that lets "
        "*any* URL be plain HTTP without complaint."
    ),
    known_fp=(
        "Air-gapped internal mirrors that absolutely can't "
        "terminate TLS may legitimately need this flag. "
        "Suppress with a one-line rationale naming the network "
        "boundary; revisit when the network team brings up a "
        "TLS proxy.",
    ),
    incident_refs=(
        "Composer 1.8.0 release notes mark ``secure-http`` as "
        "``true`` by default because plain-HTTP package "
        "fetches were the most reliable MITM surface in the "
        "ecosystem. Explicit ``false`` re-opens that surface "
        "for every install run.",
    ),
    exploit_example=(
        "// Vulnerable: explicit downgrade.\n"
        "{\n"
        "  \"config\": {\n"
        "    \"secure-http\": false\n"
        "  },\n"
        "  \"repositories\": [\n"
        "    {\"type\": \"composer\", "
        "\"url\": \"http://legacy.internal/composer\"}\n"
        "  ]\n"
        "}\n"
        "\n"
        "// Risk: every package fetch is eligible to go over\n"
        "// plain HTTP without a warning. MITM on the CI\n"
        "// runner's network path can substitute payloads.\n"
        "\n"
        "// Safe: drop the flag, use HTTPS mirrors only.\n"
        "{\n"
        "  \"config\": {},\n"
        "  \"repositories\": [\n"
        "    {\"type\": \"composer\", "
        "\"url\": \"https://internal/composer\"}\n"
        "  ]\n"
        "}"
    ),
)


def check(pom: ComposerFile) -> Finding:
    raw = pom.config.get("secure-http")
    if raw is not False:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "config.secure-http is unset or true (Composer's "
                "default HTTPS-enforcement posture)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    locations: list[Location] = []
    idx = pom.text.find('"secure-http"')
    if idx >= 0:
        line = pom.text[:idx].count("\n") + 1
        locations.append(Location(
            path=pom.path, start_line=line, end_line=line,
        ))
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            "config.secure-http is explicitly set to ``false`` — "
            "the project-wide HTTPS-enforcement gate that "
            "Composer ships on by default is disabled. Remove "
            "the entry or restore ``true``."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
