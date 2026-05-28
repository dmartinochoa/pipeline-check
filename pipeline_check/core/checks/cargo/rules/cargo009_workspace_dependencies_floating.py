"""CARGO-009. [workspace.dependencies] entry uses a floating version spec."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import CargoFile, is_floating_version

RULE = Rule(
    id="CARGO-009",
    title="[workspace.dependencies] entry uses a floating version spec",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Pin every entry in ``[workspace.dependencies]`` to an "
        "exact version (``=1.2.3``). Workspace-level "
        "dependencies act as the single source of truth for "
        "every workspace-member crate that opts into them via "
        "``workspace = true``; a floating spec at the workspace "
        "root cascades to every member, so a poisoned patch "
        "release upstream rolls across the entire workspace on "
        "the next ``cargo build``.\n\n"
        "Pair the exact pin with a committed "
        "``Cargo.lock`` at the workspace root (CARGO-003) so "
        "lockfile-based audits work across all members."
    ),
    docs_note=(
        "Walks ``[workspace.dependencies]`` table entries on "
        "each ``Cargo.toml`` (workspace roots typically declare "
        "this) and fires on the same floating shapes CARGO-001 "
        "catches for per-crate dependencies. Git / path / "
        "workspace-inherited entries are skipped — they're "
        "handled by CARGO-002 / CARGO-004 / the workspace "
        "root audit itself.\n\n"
        "Distinct from CARGO-001 because the scope is wider: a "
        "single floating workspace-deps entry cascades to every "
        "member crate that uses ``workspace = true``, which on "
        "a multi-member workspace amplifies the risk surface "
        "significantly compared to a per-crate floating spec."
    ),
    known_fp=(
        "Library-style workspaces published as a cohesive "
        "crate family may deliberately use loose specifiers at "
        "the workspace root so all members participate in "
        "version-resolution dedup. Application/binary "
        "workspaces should pin.",
    ),
    incident_refs=(
        "Pattern in Rust workspace consumers: a single "
        "floating workspace-deps spec for a popular crate "
        "(``serde``, ``tokio``) cascades a poisoned patch to "
        "every member on the next build, multiplying the "
        "blast radius compared to a per-crate dep.",
    ),
    exploit_example=(
        "# Vulnerable: workspace-level floating spec.\n"
        "# Cargo.toml (workspace root)\n"
        "[workspace]\n"
        "members = [\"crate-a\", \"crate-b\", \"crate-c\"]\n"
        "\n"
        "[workspace.dependencies]\n"
        "serde = \"1.0\"\n"
        "\n"
        "# Each member crate uses workspace = true:\n"
        "# crate-a/Cargo.toml\n"
        "[dependencies]\n"
        "serde = { workspace = true }\n"
        "\n"
        "# Attack: a poisoned serde 1.0.999 ships; every member\n"
        "# of the workspace pulls it on the next build.\n"
        "\n"
        "# Safe: pin at the workspace root.\n"
        "[workspace.dependencies]\n"
        "serde = \"=1.0.190\""
    ),
)


def check(pom: CargoFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        # The base parser tags workspace.<section> entries with the
        # ``workspace.dependencies`` (or .dev-/build-) section name.
        if not dep.section.startswith("workspace."):
            continue
        if dep.is_git or dep.is_path:
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
        "Every [workspace.dependencies] entry uses an exact-pin "
        "version."
        if passed else
        f"{len(offenders)} workspace-dep(s) use a floating spec: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Every member crate "
        f"that opts into the workspace inheritance picks up the "
        f"same drift on the next build."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
