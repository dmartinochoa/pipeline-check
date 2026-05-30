"""COMPOSER-011. ``repositories`` re-points a package to external VCS."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-011",
    title="composer.json repository re-points a package to an external VCS source",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Drop the custom ``repositories`` entry, or pin the "
        "package to a trusted source you control. Composer "
        "resolves custom repositories ahead of Packagist, so a "
        "``vcs`` / ``git`` / ``package`` / ``composer`` entry can "
        "quietly override a well-known coordinate with an "
        "attacker-controlled fork. This is the Composer shape of "
        "dependency confusion: the coordinate still reads like the "
        "real package, but resolution now points at the custom "
        "source first.\n\n"
        "If the project genuinely needs an internal package "
        "source, keep it but confirm the URL is owned by your "
        "team and that the names it serves are namespaced so they "
        "can't shadow public packages."
    ),
    docs_note=(
        "Fires on any ``repositories`` entry of type ``vcs``, "
        "``git``, ``package``, or ``composer``. These types "
        "re-point package resolution to an arbitrary source, and "
        "because custom repos win over Packagist, a malicious "
        "entry is a dependency-confusion vector. ``path`` and "
        "``artifact`` types are local-only and don't trip the "
        "rule. Companion to COMPOSER-012 (Packagist disabled / "
        "custom repo canonical)."
    ),
    known_fp=(
        "Private organizations legitimately host internal "
        "packages on a custom Composer / VCS repository. Suppress "
        "with a one-line rationale confirming the URL is owned by "
        "your team; pair it with namespaced package names so the "
        "custom source can't shadow a public coordinate.",
    ),
    incident_refs=(
        "Composer resolves custom ``repositories`` before "
        "Packagist, the same priority order that makes "
        "dependency-confusion attacks work across npm / PyPI / "
        "NuGet. A custom ``vcs`` entry that names a public "
        "coordinate serves the attacker's fork on the next "
        "install.",
    ),
    exploit_example=(
        "// Vulnerable: custom vcs repo shadows a public package.\n"
        "{\n"
        "  \"repositories\": [\n"
        "    {\n"
        "      \"type\": \"vcs\",\n"
        "      \"url\": \"https://github.com/attacker/widgets\"\n"
        "    }\n"
        "  ],\n"
        "  \"require\": {\"acme/widgets\": \"*\"}\n"
        "}\n"
        "\n"
        "// Risk: Composer prefers the custom repo over Packagist\n"
        "// and pulls the backdoored fork, running its install\n"
        "// scripts in the build.\n"
        "\n"
        "// Safe: resolve acme/widgets from Packagist only.\n"
        "{\n"
        "  \"require\": {\"acme/widgets\": \"1.2.3\"}\n"
        "}"
    ),
)


_EXTERNAL_TYPES: frozenset[str] = frozenset(
    {"vcs", "git", "package", "composer"},
)


def check(pom: ComposerFile) -> Finding:
    offenders: list[tuple[str, str]] = []
    locations: list[Location] = []
    for repo in pom.repositories:
        if repo.type.lower() not in _EXTERNAL_TYPES:
            continue
        where = repo.url or repo.type
        offenders.append((repo.type, where))
        locations.append(Location(
            path=pom.path,
            start_line=repo.line_no, end_line=repo.line_no,
        ))
    passed = not offenders
    if passed:
        desc = (
            "No custom vcs / git / package / composer repository "
            "entries (resolution stays on Packagist)."
        )
    else:
        rendered = ", ".join(
            f"{rtype}:{where}" for rtype, where in offenders[:3]
        )
        suffix = "…" if len(offenders) > 3 else ""
        desc = (
            f"{len(offenders)} custom repository entry / entries "
            f"re-point resolution ahead of Packagist: "
            f"{rendered}{suffix}. Confirm each source is "
            f"trusted or drop it."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
