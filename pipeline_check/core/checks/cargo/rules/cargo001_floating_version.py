"""CARGO-001. Cargo.toml dependency uses a floating version spec."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import CargoFile, is_floating_version

RULE = Rule(
    id="CARGO-001",
    title="Cargo.toml dependency uses a floating version spec",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Replace floating version specifiers (caret-equivalent "
        "``\"1.2\"``, explicit caret ``\"^1.2\"``, tilde "
        "``\"~1.2\"``, wildcard ``\"1.*\"``, comparison "
        "``\">=1.2, <2\"``) with an exact pin ``\"=1.2.3\"``. "
        "Cargo's default specifier is caret-equivalent: a bare "
        "``\"1.2.3\"`` matches any version >= 1.2.3 and < 2.0.0. "
        "A compromised patch release upstream is silently picked "
        "up on the next ``cargo build`` unless a committed "
        "``Cargo.lock`` (CARGO-003) holds the line.\n\n"
        "Pin the manifest *and* commit the lockfile, both belt and "
        "suspenders. The lockfile alone leaves a window between "
        "``cargo update`` runs; the manifest alone leaves a window "
        "before the first build refreshes the lockfile."
    ),
    docs_note=(
        "Fires on any ``[dependencies]`` / ``[dev-dependencies]`` / "
        "``[build-dependencies]`` / ``[target.<...>.dependencies]`` / "
        "``[workspace.dependencies]`` entry whose version specifier "
        "evaluates as floating per "
        "Cargo's semver grammar (any leading ``^`` / ``~`` / "
        "``>=`` / ``<`` / ``*``, or bare versions which Cargo "
        "interprets as caret-equivalent). Exact pins (``=N.M.P``) "
        "pass. Entries without a version (``git`` / ``path``) are "
        "handled by CARGO-002 / CARGO-004 respectively, not here."
    ),
    known_fp=(
        "Library crates published to crates.io legitimately use "
        "loose specifiers so downstream consumers can deduplicate "
        "transitive deps; the pin-the-manifest guidance applies "
        "primarily to *binary* / *application* crates. Suppress "
        "per crate when the crate is itself a published library.",
    ),
    incident_refs=(
        "Long-running pattern in Rust application crates that "
        "publish a wildcard caret spec for an HTTP client. A "
        "patch-version compromise upstream is picked up at the "
        "next build; the ``Cargo.toml`` doesn't change, so a "
        "diff-based review misses it. The committed lockfile is "
        "the load-bearing control, but the manifest pin makes "
        "the intent legible at audit time.",
    ),
    exploit_example=(
        "# Vulnerable: caret-equivalent spec admits future\n"
        "# patches.\n"
        "[dependencies]\n"
        "serde = \"1.0\"\n"
        "\n"
        "# Attack: serde 1.0.190 is published with a poisoned\n"
        "# deserializer. The lockfile is regenerated on the next\n"
        "# ``cargo update``; build picks up the bad version with\n"
        "# no manifest diff to flag at review.\n"
        "\n"
        "# Safe: exact pin in the manifest.\n"
        "[dependencies]\n"
        "serde = \"=1.0.190\"\n"
        "# Lockfile commit (CARGO-003) covers the no-update path."
    ),
)


def check(pom: CargoFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        if dep.from_workspace or dep.is_git or dep.is_path:
            continue
        if dep.version is None:
            continue
        if not is_floating_version(dep.version):
            continue
        offenders.append(f"{dep.name} = {dep.version!r}")
        locations.append(Location(
            path=pom.path, start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    desc = (
        "Every Cargo.toml dependency uses an exact-pin version."
        if passed else
        f"{len(offenders)} dependency / dependencies use a floating "
        f"version spec: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. ``cargo update`` "
        f"can lift the lockfile to a future patch release that "
        f"matches the floating range without any Cargo.toml diff."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
