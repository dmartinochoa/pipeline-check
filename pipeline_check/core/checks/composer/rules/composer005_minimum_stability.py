"""COMPOSER-005. ``minimum-stability`` allows unstable releases."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-005",
    title="composer.json minimum-stability accepts unstable releases",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Set ``\"minimum-stability\": \"stable\"`` in "
        "composer.json (or leave the key unset; Composer's "
        "default *is* ``stable``). When a specific dependency "
        "genuinely needs a pre-release, pin it with the per-dep "
        "stability flag instead: "
        "``\"vendor/pkg\": \"1.0.0-RC1@RC\"``. That way the "
        "manifest declares one explicit exception rather than "
        "lowering the floor for the whole graph."
    ),
    docs_note=(
        "Fires when ``minimum-stability`` is set to ``dev``, "
        "``alpha``, ``beta``, or ``RC``. The default value is "
        "``stable``, so the rule only trips on an explicit "
        "lowering. Composer evaluates this floor across the "
        "entire transitive graph: setting it to ``dev`` allows "
        "any dependency's dev-branch alias to satisfy a "
        "constraint, dramatically widening the attack surface "
        "(branch heads on packagist can be force-pushed)."
    ),
    known_fp=(
        "Some teams legitimately run on pre-release Symfony / "
        "Doctrine versions during the release-candidate "
        "window. Suppress with a one-line rationale naming the "
        "RC track and a TODO to revert when the GA ships.",
    ),
    incident_refs=(
        "Maintainer compromise risk multiplies on dev branch "
        "aliases — a force-push to ``master`` propagates to "
        "every consumer on ``dev-master`` the moment Composer "
        "re-resolves. The combined floor (this rule) plus "
        "dev-branch aliases (COMPOSER-002) is the high-blast "
        "case.",
    ),
    exploit_example=(
        "// Vulnerable: lowered floor.\n"
        "{\n"
        "  \"minimum-stability\": \"dev\",\n"
        "  \"require\": {\n"
        "    \"some/pkg\": \"^1.0\"\n"
        "  }\n"
        "}\n"
        "\n"
        "// Risk: ``some/pkg`` dev-branch alias is now\n"
        "// eligible to satisfy any transitive ^1.0 constraint.\n"
        "// One maintainer-account compromise on any dep up\n"
        "// the graph propagates instantly.\n"
        "\n"
        "// Safe: default floor, per-dep escape.\n"
        "{\n"
        "  \"require\": {\n"
        "    \"some/pkg\": \"1.0.0-RC1@RC\"\n"
        "  }\n"
        "}"
    ),
)


_UNSTABLE: frozenset[str] = frozenset({"dev", "alpha", "beta", "rc"})


def check(pom: ComposerFile) -> Finding:
    raw = pom.minimum_stability.strip().lower()
    if raw not in _UNSTABLE:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                f"minimum-stability is ``{pom.minimum_stability}`` "
                f"(stable floor)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    locations: list[Location] = []
    needle = '"minimum-stability"'
    idx = pom.text.find(needle)
    if idx >= 0:
        line = pom.text[:idx].count("\n") + 1
        locations.append(Location(
            path=pom.path, start_line=line, end_line=line,
        ))
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            f"minimum-stability is ``{pom.minimum_stability}`` — "
            f"unstable releases (dev / alpha / beta / RC) are "
            f"eligible to satisfy any constraint in the "
            f"transitive graph. Restore ``stable`` and pin "
            f"pre-releases per dep."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
