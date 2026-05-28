"""CARGO-006. Cargo.toml requires a known-compromised crate version."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from .._compromised_crates import lookup
from ..base import CargoFile

RULE = Rule(
    id="CARGO-006",
    title="Cargo.toml requires a known-compromised crate version",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Bump the offending dep to a patched version (named in the "
        "cited advisory) and refresh Cargo.lock with ``cargo "
        "update -p <crate>``. If the advisory has no patched "
        "release, pin to the last known-good version and add a "
        "follow-up TODO to replace or remove the dependency. After "
        "the bump, re-run the scan; if CARGO-006 still fires, an "
        "indirect dependency is pulling the bad version back in — "
        "use ``cargo tree -i <crate>@<version>`` to find the path."
    ),
    docs_note=(
        "Reads the curated registry under "
        "``pipeline_check.core.checks.cargo._compromised_crates`` "
        "(table of ``(crate, malicious_versions, advisory)`` entries) "
        "and fires when any dependency — direct or workspace-"
        "inherited — matches an entry. The registry is hand-curated "
        "and append-only; adding a new entry is a one-line table "
        "edit plus the citing advisory in the commit message.\n\n"
        "Mirrors NPM-006 / PYPI-005 / MVN-006 / NUGET-005 / "
        "GOMOD-006 and shares the version-matching primitive "
        "(``_primitives.compromised.match_version``). The version "
        "literal compared is whatever the manifest declares "
        "(``\"1.2.3\"``, ``\"=1.2.3\"``, ``\"^1.2\"``); operators "
        "wanting *resolved* version coverage should also commit "
        "Cargo.lock (CARGO-003), at which point the lockfile-side "
        "audit can lift the rule's matching from manifest to "
        "resolved-graph."
    ),
    known_fp=(
        "A manifest may legitimately pin a known-bad version because "
        "the consumer has applied a downstream patch or sandbox "
        "(``unsafe`` removal, panic-handler change). The rule still "
        "fires; suppress per dep with a one-line rationale naming "
        "the patch.",
    ),
    incident_refs=(
        "RUSTSEC-2024-0388: rustls vulnerability surfaced via "
        "RUSTSEC-2024-0388. Future entries follow the same shape: "
        "append ``(crate, version, advisory)`` to "
        "_compromised_crates.py with the citing advisory in the "
        "commit message.",
    ),
    exploit_example=(
        "# Vulnerable: manifest pins an exact version named in a\n"
        "# published RUSTSEC advisory.\n"
        "[dependencies]\n"
        "rustls = \"=0.21.2\"\n"
        "\n"
        "# Attack: the published RUSTSEC advisory enumerates the\n"
        "# affected versions; downstream consumers triggering the\n"
        "# vulnerable code path (a specific TLS handshake edge\n"
        "# case in RUSTSEC-2024-0388) face the leak surface the\n"
        "# advisory documents.\n"
        "\n"
        "# Safe: bump to a patched release.\n"
        "[dependencies]\n"
        "rustls = \"=0.22.0\"  # or the latest patched line\n"
        "# Then ``cargo update -p rustls`` to refresh Cargo.lock."
    ),
)


def check(pom: CargoFile) -> Finding:
    offenders: list[tuple[str, str, str]] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        if dep.version is None:
            continue
        # Strip the leading ``=`` so an exact-pin ``"=1.2.3"`` matches
        # the registry's ``"1.2.3"`` literal. Other prefixes (``^`` /
        # ``~``) are matched as-is since their semantics differ from
        # exact equality.
        version_lookup = dep.version.lstrip("=").strip()
        entry = lookup(dep.name, version_lookup)
        if entry is None:
            continue
        offenders.append((dep.name, dep.version, entry.advisory))
        locations.append(Location(
            path=pom.path, start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    if passed:
        desc = (
            "No Cargo.toml dependency matches the curated "
            "compromised-crate registry."
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
            f"Bump to a patched version named in the cited advisory "
            f"and refresh Cargo.lock."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
