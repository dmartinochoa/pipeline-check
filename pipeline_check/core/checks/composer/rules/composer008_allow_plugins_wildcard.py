"""COMPOSER-008. ``config.allow-plugins`` permits all plugins."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-008",
    title="composer.json allow-plugins permits any plugin to execute",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-94"),
    recommendation=(
        "Replace ``\"allow-plugins\": true`` with an explicit "
        "per-plugin map: ``\"allow-plugins\": "
        "{\"vendor/known-plugin\": true, ...}``. Composer "
        "plugins run arbitrary PHP at install time — including "
        "from transitive deps — so the allowlist is one of "
        "Composer's primary security boundaries. The wildcard "
        "(``true``) defeats the gate entirely. Composer 2.2+ "
        "ships the default value as ``{}`` and prompts before "
        "running any plugin in interactive mode; CI is "
        "non-interactive, so the prompt is silently bypassed "
        "and every plugin in the graph runs."
    ),
    docs_note=(
        "Fires when ``config.allow-plugins`` is set to the "
        "boolean ``true``. The legitimate shapes are: omit the "
        "key (Composer defaults to ``false`` / empty map and "
        "prompts), set it to ``false`` (block all), or set it "
        "to a map of plugin names with boolean values. Setting "
        "any individual entry to ``true`` is a per-plugin "
        "allowlist, which the rule allows; only the wildcard "
        "boolean trips the rule."
    ),
    known_fp=(
        "Some bootstrap / scaffolding tools (Symfony Flex, "
        "Laravel Installer) need plugin execution to run "
        "scaffolds. Allowlist them by name instead: "
        "``{\"symfony/flex\": true}``. The rule fires only on "
        "the wildcard form so a per-plugin allowlist of any "
        "size passes.",
    ),
    incident_refs=(
        "Composer 2.2 introduced ``allow-plugins`` after a "
        "spate of supply-chain incidents where a transitive "
        "dep shipped a plugin that exfiltrated the env at "
        "``composer install`` time. The gate works only when "
        "the operator explicitly allowlists; setting the "
        "wildcard restores the pre-2.2 attack surface.",
    ),
    exploit_example=(
        "// Vulnerable: wildcard allow.\n"
        "{\n"
        "  \"config\": {\n"
        "    \"allow-plugins\": true\n"
        "  }\n"
        "}\n"
        "\n"
        "// Risk: any plugin in the transitive graph runs at\n"
        "// ``composer install`` time. A maintainer-account\n"
        "// compromise that ships a plugin payload is silently\n"
        "// executed.\n"
        "\n"
        "// Safe: per-plugin allowlist.\n"
        "{\n"
        "  \"config\": {\n"
        "    \"allow-plugins\": {\n"
        "      \"symfony/flex\": true,\n"
        "      \"composer/installers\": true\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


def check(pom: ComposerFile) -> Finding:
    raw = pom.config.get("allow-plugins")
    if raw is not True:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "allow-plugins is unset, false, or a per-plugin "
                "allowlist."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    locations: list[Location] = []
    idx = pom.text.find('"allow-plugins"')
    if idx >= 0:
        line = pom.text[:idx].count("\n") + 1
        locations.append(Location(
            path=pom.path, start_line=line, end_line=line,
        ))
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            "config.allow-plugins is set to ``true`` — every "
            "plugin in the transitive graph is permitted to run "
            "at install time. Replace with an explicit per-plugin "
            "allowlist."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
