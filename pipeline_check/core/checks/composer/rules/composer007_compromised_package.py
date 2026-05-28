"""COMPOSER-007. composer.json requires a known-compromised package version."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from .._compromised_packages import lookup
from ..base import ComposerFile

RULE = Rule(
    id="COMPOSER-007",
    title="composer.json requires a known-compromised package version",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Bump the offending dep to a patched version (named in "
        "the cited advisory) and refresh composer.lock with "
        "``composer update vendor/package``. If the advisory "
        "has no patched release, pin to the last known-good "
        "version and add a follow-up TODO to replace or remove "
        "the dependency. After the bump, re-run the scan; if "
        "COMPOSER-007 still fires, an indirect dependency is "
        "pulling the bad version back in — use ``composer "
        "why vendor/package`` to find the path."
    ),
    docs_note=(
        "Reads the curated registry under "
        "``pipeline_check.core.checks.composer._compromised_"
        "packages`` (table of ``(package, malicious_versions, "
        "advisory)`` entries) and fires when any dependency — "
        "direct ``require`` or ``require-dev`` — matches an "
        "entry. The registry is hand-curated and append-only; "
        "adding a new entry is a one-line table edit plus the "
        "citing advisory in the commit message.\n\n"
        "Mirrors NPM-006 / PYPI-005 / MVN-006 / NUGET-005 / "
        "GOMOD-006 / CARGO-006 and shares the version-matching "
        "primitive "
        "(``_primitives.compromised.match_version``). The "
        "version literal compared is whatever the manifest "
        "declares; operators wanting *resolved* version "
        "coverage should also commit composer.lock "
        "(COMPOSER-001), at which point the lockfile-side "
        "audit can lift the rule's matching from manifest to "
        "resolved-graph."
    ),
    known_fp=(
        "A manifest may legitimately pin a known-bad version "
        "because the consumer has applied a downstream patch or "
        "sandbox. The rule still fires; suppress per dep with a "
        "one-line rationale naming the patch.",
    ),
    incident_refs=(
        "Composer ecosystem has had a steady stream of "
        "maintainer-account compromises (PHP-FIG / Symfony "
        "supply-chain incidents in 2023-2024). Future entries "
        "follow the same shape: append "
        "``(package, version, advisory)`` to "
        "_compromised_packages.py with the citing advisory "
        "in the commit message.",
    ),
    exploit_example=(
        "// Vulnerable: manifest pins an exact version named in\n"
        "// a published advisory.\n"
        "{\n"
        "  \"require\": {\n"
        "    \"guzzlehttp/guzzle\": \"7.8.0\"\n"
        "  }\n"
        "}\n"
        "\n"
        "// Safe: bump to a patched release.\n"
        "{\n"
        "  \"require\": {\n"
        "    \"guzzlehttp/guzzle\": \"7.8.2\"\n"
        "  }\n"
        "}\n"
        "// Then ``composer update guzzlehttp/guzzle`` to\n"
        "// refresh composer.lock."
    ),
)


def check(pom: ComposerFile) -> Finding:
    offenders: list[tuple[str, str, str]] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        spec = dep.constraint.lstrip("=").strip()
        # Drop ``v`` prefix for the lookup so ``v1.2.3`` matches
        # ``1.2.3`` in the registry.
        if spec[:1] in ("v", "V"):
            spec = spec[1:]
        entry = lookup(dep.name, spec)
        if entry is None:
            continue
        offenders.append((dep.name, dep.constraint, entry.advisory))
        locations.append(Location(
            path=pom.path,
            start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    if passed:
        desc = (
            "No composer.json dependency matches the curated "
            "compromised-package registry."
        )
    else:
        rendered = ", ".join(
            f"{name}@{ver} ({advisory})"
            for name, ver, advisory in offenders[:5]
        )
        suffix = "…" if len(offenders) > 5 else ""
        desc = (
            f"{len(offenders)} dependency / dependencies match a "
            f"known-compromised registry entry: {rendered}{suffix}. "
            f"Bump to a patched version named in the cited "
            f"advisory and refresh composer.lock."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
