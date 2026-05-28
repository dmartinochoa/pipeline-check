"""CARGO-003. Cargo.toml present without a sibling Cargo.lock."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CargoFile

RULE = Rule(
    id="CARGO-003",
    title="Cargo.toml present without a sibling Cargo.lock",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-345",),
    recommendation=(
        "For binary / application crates, commit ``Cargo.lock`` to "
        "the repository. The lockfile records exact resolved "
        "versions for every transitive dependency in the graph, so "
        "every build (locally and in CI) installs the same crates. "
        "Without it, ``cargo build`` re-resolves the manifest each "
        "time and is free to pick the latest matching patch under "
        "any floating spec (CARGO-001). \n\n"
        "For library crates published to crates.io, Cargo's "
        "guidance is the opposite — leave Cargo.lock uncommitted so "
        "downstream consumers can deduplicate. This rule still fires "
        "on those manifests; suppress per crate when the crate is a "
        "published library. The default posture (Cargo.lock "
        "committed) is correct for applications, build tools, CLI "
        "utilities, and internal services."
    ),
    docs_note=(
        "Fires when the manifest's directory has no ``Cargo.lock`` "
        "sibling and the workspace root one directory up has no "
        "``Cargo.lock`` either. Workspace-root manifests "
        "(``[workspace]``-only, no ``[package]``) are skipped — the "
        "lockfile lives at the workspace root for the whole "
        "workspace, so each per-crate sub-manifest legitimately "
        "lacks one. Crates that legitimately publish without a "
        "lockfile (library crates) need a per-file suppression "
        "with a one-line rationale."
    ),
    known_fp=(
        "Library crates published to crates.io intentionally omit "
        "Cargo.lock from version control so downstream applications "
        "can deduplicate transitive deps; this rule fires on those, "
        "suppress per crate with a one-line rationale naming the "
        "crate-as-library posture. Workspace-root manifests are "
        "skipped automatically.",
    ),
    incident_refs=(
        "Long-running pattern of internal Rust applications that "
        "ignore Cargo.lock in .gitignore (a habit imported from "
        "library development). CI builds use a fresh lockfile every "
        "run; a transient registry-side bad patch release lands on "
        "the build the moment it's published, then disappears on "
        "the next run, leaving no audit trail and no reproducer.",
    ),
    exploit_example=(
        "# Vulnerable: lockfile excluded from version control.\n"
        "$ cat .gitignore\n"
        "Cargo.lock\n"
        "\n"
        "# Risk: every CI build re-resolves caret-spec deps. A\n"
        "# poisoned patch release published upstream is picked up\n"
        "# the moment CI next runs; rolled back at the next build\n"
        "# once the upstream pulls the version. No diff, no\n"
        "# reproducer, no audit trail.\n"
        "\n"
        "# Safe: commit Cargo.lock. Combined with exact-pin specs\n"
        "# in Cargo.toml (CARGO-001), reproducibility is locked\n"
        "# at the cost of explicit ``cargo update`` calls when\n"
        "# upgrades are wanted."
    ),
)


def check(pom: CargoFile) -> Finding:
    if pom.is_workspace_root:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "Workspace-root manifest; lockfile lives at the "
                "workspace root rather than next to this file."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if not pom.dependencies:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "Cargo.toml declares no dependencies; absent "
                "Cargo.lock is a no-op."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if pom.has_lockfile:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                f"Lockfile present at ``{pom.lockfile_path}``."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            f"No Cargo.lock alongside ``{pom.path}`` or at the "
            f"workspace root. Every ``cargo build`` re-resolves "
            f"the manifest; a poisoned patch release upstream is "
            f"silently picked up on the next run."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
