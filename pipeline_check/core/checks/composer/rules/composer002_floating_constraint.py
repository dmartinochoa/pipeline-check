"""COMPOSER-002. ``require`` entry uses a floating version constraint."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ComposerFile, is_floating_constraint

RULE = Rule(
    id="COMPOSER-002",
    title="composer.json require uses a floating version constraint",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Replace the floating constraint with an exact pin "
        "(``\"vendor/package\": \"1.2.3\"``). A committed "
        "composer.lock pins resolved versions at install time "
        "and is the primary defense; tightening the manifest "
        "constraint is the secondary defense (makes the "
        "tolerated upgrade window in ``composer update`` "
        "explicit). Floating ranges (``^1.2``, ``~1.2``, "
        "``1.2.*``, ``*``, ``dev-master``) let ``composer "
        "update`` pull in any release matching the range, "
        "including a poisoned patch release published moments "
        "before the build."
    ),
    docs_note=(
        "Fires when any ``require`` or ``require-dev`` entry's "
        "value is anything other than an exact triple "
        "(``X.Y.Z``) or 40-char commit hash. Caret-prefix "
        "(``^1.2``), tilde (``~1.2``), wildcard (``1.2.*`` / "
        "``*``), comparison ranges (``>=1.2,<2``), and "
        "dev-branch aliases (``dev-master``, ``X.Y.x-dev``) all "
        "trip the rule. The right operator response is either "
        "an exact pin or a committed composer.lock (COMPOSER-001)."
    ),
    known_fp=(
        "Some Symfony / Doctrine / Laravel packages publish "
        "patches frequently and a strict exact-pin posture is "
        "operationally painful. Suppress per dep with a one-line "
        "rationale (``# composer:ignore COMPOSER-002 - "
        "follows-symfony-minor-track``) once the team has "
        "committed composer.lock.",
    ),
    incident_refs=(
        "Repeated supply-chain pattern: ``\"vendor/package\": "
        "\"^1.0\"`` in a CI image without composer.lock pulls "
        "the latest 1.x release on every build. Affected hours "
        "from upstream-publish to CI-pull is whatever your "
        "build cadence is.",
    ),
    exploit_example=(
        "# Vulnerable: floating constraint, no lockfile.\n"
        "{\n"
        "  \"require\": {\n"
        "    \"guzzlehttp/guzzle\": \"^7.8\"\n"
        "  }\n"
        "}\n"
        "\n"
        "# Risk: ``composer install`` (without lockfile) resolves\n"
        "# to whatever 7.8.x release Packagist serves at run\n"
        "# time. A maintainer-account compromise that publishes\n"
        "# 7.8.9 with a credential exfil payload lands on the\n"
        "# next CI build.\n"
        "\n"
        "# Safe: exact pin + composer.lock.\n"
        "{\n"
        "  \"require\": {\n"
        "    \"guzzlehttp/guzzle\": \"7.8.1\"\n"
        "  }\n"
        "}"
    ),
)


def check(pom: ComposerFile) -> Finding:
    offenders: list[tuple[str, str]] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        if is_floating_constraint(dep.constraint):
            offenders.append((dep.name, dep.constraint))
            locations.append(Location(
                path=pom.path,
                start_line=dep.line_no, end_line=dep.line_no,
            ))
    passed = not offenders
    if passed:
        desc = (
            "All require / require-dev entries use exact-pin "
            "constraints."
        )
    else:
        rendered = ", ".join(
            f"{name} ({spec})" for name, spec in offenders[:5]
        )
        suffix = "…" if len(offenders) > 5 else ""
        desc = (
            f"{len(offenders)} dependency / dependencies use a "
            f"floating constraint: {rendered}{suffix}. Replace "
            f"with an exact pin and commit composer.lock."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
