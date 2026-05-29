"""NPM-014, direct dependency relies on a single npm publisher."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import NpmContext, NpmManifest, iter_manifest_dependencies

RULE = Rule(
    id="NPM-014",
    title="Direct dependency relies on a single npm publisher",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Treat a single-publisher dependency as a single point of "
        "compromise: if that one npm account is phished or its token "
        "leaks, every consumer pulls malicious code on the next install "
        "(the axios / chalk / lodash class of risk). For dependencies "
        "you pull in directly, prefer packages whose publish access is "
        "shared across maintainers or an org team, pin to a reviewed "
        "version, and pair with NPM-008 (cooldown) so a compromised "
        "release has a window to be caught before it reaches your "
        "lockfile."
    ),
    docs_note=(
        "Network-dependent: needs ``--resolve-remote`` to read each "
        "direct dependency's publisher list from ``registry.npmjs.org`` "
        "(the same packument fetch NPM-008 uses, so it adds no extra "
        "requests). Flags a package whose top-level ``maintainers`` "
        "array (the npm accounts with publish access, not the repo's "
        "contributor list) has exactly one entry. Scoped to direct "
        "dependencies in ``dependencies`` / ``devDependencies`` / "
        "``optionalDependencies`` / ``peerDependencies``; transitive "
        "packages are out of scope. LOW severity by design: a single "
        "publisher is extremely common across the registry and is a "
        "posture signal, not an active vulnerability, so it stays below "
        "the default ``--fail-on`` gate while still surfacing in a "
        "report. When ``--resolve-remote`` is off or the registry can't "
        "be reached, the rule passes silently."
    ),
    known_fp=(
        "A single-publisher package maintained by a trusted org behind "
        "2FA and provenance is far lower risk than the bare count "
        "implies; the rule can't see the account's hardening from the "
        "manifest. Suppress per-resource for dependencies the team has "
        "vetted.",
    ),
    incident_refs=(
        "axios maintainer-account takeover (March 30, 2026): a single "
        "publisher account compromise let an attacker push a malicious "
        "release to roughly 99M weekly downloads before detection.",
        "@ctrl/tinycolor account takeover (May 2024): single-publisher "
        "package; malicious versions stayed live for ~36 hours before "
        "coordinated removal.",
    ),
    exploit_example=(
        "// Risk: ``shiny-lib`` has one npm account with publish\n"
        "// access. Phish or steal that one token and every consumer\n"
        "// installs attacker code on the next ``npm install`` — no\n"
        "// other maintainer is positioned to notice or revert it.\n"
        "// package.json\n"
        "{\n"
        "  \"dependencies\": {\n"
        "    \"shiny-lib\": \"^4.2.0\"\n"
        "  }\n"
        "}\n"
        "\n"
        "// Surface it: ``pipeline_check --pipeline npm\n"
        "// --resolve-remote`` reads the package's publisher list from\n"
        "// the registry and flags the single-publisher direct deps so\n"
        "// you can weigh the takeover blast radius per dependency and\n"
        "// pair the riskiest with a cooldown (NPM-008).\n"
    ),
)


def check(manifest: NpmManifest, ctx: NpmContext | None = None) -> Finding:
    maintainer_counts: dict[str, int] = (
        ctx.maintainer_counts if ctx is not None else {}
    )
    if not maintainer_counts:
        # No metadata — silent pass. ``--resolve-remote`` is the opt-in
        # network path (documented in docs_note); the absence of it must
        # not fail CI for users on the default offline scan.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "No publisher metadata available (re-run with "
                "``--resolve-remote`` to enable single-publisher "
                "analysis)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    locations: list[Location] = []
    seen: set[str] = set()
    for section, name, _spec in iter_manifest_dependencies(manifest):
        if name in seen:
            continue  # same dep in two sections — report once
        seen.add(name)
        count = maintainer_counts.get(name)
        if count is None or count != 1:
            continue  # registry didn't resolve it, or it has >1 publisher
        offenders.append(f"{section}.{name}")
        idx = manifest.text.find(f'"{name}"')
        line_no = manifest.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=manifest.path, start_line=line_no, end_line=line_no,
        ))

    passed = not offenders
    desc = (
        "No direct dependency relies on a single npm publisher."
        if passed else
        f"{len(offenders)} direct dependency / dependencies are "
        f"published by a single npm account: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A compromise of that one "
        f"account ships malicious code to every consumer on the next "
        f"install."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
