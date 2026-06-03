"""CARGO-007. [build-dependencies] entry uses a floating version spec."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import CargoFile, is_floating_version

RULE = Rule(
    id="CARGO-007",
    title="[build-dependencies] entry uses a floating version spec",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-7"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Pin every ``[build-dependencies]`` entry to an exact "
        "version (``=1.2.3``). Build-dependencies are crates used "
        "exclusively at compile time by ``build.rs`` (the "
        "Rust-side analog of npm install scripts or Python "
        "setup.py): they run arbitrary Rust code in the build "
        "environment before the consuming crate's own source "
        "ever compiles. A poisoned patch release of a build "
        "dependency executes in the build environment with the "
        "same privileges any other build code would have, and "
        "runs on every developer's machine and every CI runner.\n\n"
        "Distinct from CARGO-001 (regular runtime "
        "``[dependencies]``): runtime deps execute at *app* "
        "runtime, build deps execute at *build* time, before any "
        "test or runtime sandbox is in place. The xz-utils-style "
        "build-step backdoor is directly applicable to any "
        "build-dependency that ships a build.rs hook."
    ),
    docs_note=(
        "Walks ``[build-dependencies]``, "
        "``[target.<target>.build-dependencies]``, and "
        "``[workspace.build-dependencies]`` entries on each "
        "``Cargo.toml`` and fires when the version spec is "
        "floating per Cargo's semver model (bare numeric / "
        "caret / tilde / wildcard / range). Exact pins "
        "(``=X.Y.Z``) pass. Only ``workspace = true``-inherited "
        "entries are skipped (the workspace root's audit is the "
        "right surface for those, and CARGO-009 covers that table "
        "specifically)."
    ),
    known_fp=(
        "Library crates published to crates.io legitimately use "
        "loose build-dep specifiers so downstream consumers "
        "can deduplicate at integration time. The application/"
        "binary distinction applies the same way as for CARGO-"
        "001: app crates should pin, library crates may suppress "
        "with a published-library rationale.",
    ),
    incident_refs=(
        "Build-time supply-chain pattern: a popular build-dep "
        "crate (a code-generator, a protobuf compiler wrapper, "
        "a static linker helper) ships a poisoned patch release "
        "with a malicious build.rs hook. Every downstream "
        "consumer with a floating build-dep spec picks up the "
        "bad version on the next ``cargo build``; the hook runs "
        "in the build environment and inherits CI runner "
        "privileges before any test sandbox executes.",
    ),
    exploit_example=(
        "# Vulnerable: build-dependency with caret-equivalent spec.\n"
        "[build-dependencies]\n"
        "tonic-build = \"0.12\"\n"
        "\n"
        "# Attack: a poisoned tonic-build 0.12.99 ships with a\n"
        "# malicious build.rs hook that runs at compile time.\n"
        "# Every cargo build picks it up via the caret spec;\n"
        "# the hook inherits the build environment's privileges\n"
        "# before any test runs.\n"
        "\n"
        "# Safe: exact pin.\n"
        "[build-dependencies]\n"
        "tonic-build = \"=0.12.3\""
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
        # Scope to build-dependencies (and target-specific build-deps).
        section = dep.section
        if "build-dependencies" not in section:
            continue
        if not is_floating_version(dep.version):
            continue
        offenders.append(f"{dep.name} = {dep.version!r}")
        locations.append(Location(
            path=pom.path, start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    desc = (
        "Every [build-dependencies] entry uses an exact-pin "
        "version."
        if passed else
        f"{len(offenders)} build-dependency / build-dependencies "
        f"use a floating spec: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each one runs "
        f"during the build via build.rs hooks; a poisoned "
        f"patch release executes in the build environment."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
