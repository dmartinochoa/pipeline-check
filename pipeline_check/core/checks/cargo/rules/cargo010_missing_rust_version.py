"""CARGO-010. Cargo.toml lacks an explicit rust-version field."""
from __future__ import annotations

import tomllib
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CargoFile

RULE = Rule(
    id="CARGO-010",
    title="Cargo.toml lacks an explicit rust-version field",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1395",),
    recommendation=(
        "Add a ``rust-version`` field to ``[package]`` naming "
        "the minimum supported Rust toolchain:\n\n"
        "    [package]\n"
        "    name = \"my-crate\"\n"
        "    version = \"0.1.0\"\n"
        "    rust-version = \"1.75\"\n\n"
        "The field tells cargo to error early if the consumer's "
        "toolchain is older than the named version, which "
        "catches the silent-incompatibility class of bug where "
        "a new language feature lands in a recent compiler but "
        "the consumer's CI image hasn't been updated. The field "
        "also documents the project's compatibility posture so "
        "downstream consumers can audit the toolchain matrix."
    ),
    docs_note=(
        "Reads ``[package].rust-version`` and fires when the "
        "field is missing on a non-workspace-root manifest. "
        "Workspace roots are skipped — they declare "
        "``[workspace.package].rust-version`` instead, and the "
        "member crates inherit it via ``rust-version.workspace "
        "= true``.\n\n"
        "Single-rule LOW: a missing rust-version isn't a "
        "vulnerability, it's a posture / maintenance signal. "
        "Parallels GOMOD-005 (missing Go toolchain directive)."
    ),
    known_fp=(
        "Some chart-generation / scaffolding templates emit a "
        "Cargo.toml without ``rust-version`` to defer the "
        "decision to the consumer. The rule still fires; "
        "suppress per file with a one-line rationale, or — "
        "better — add the explicit field once the project's "
        "compatibility surface stabilizes.",
    ),
    incident_refs=(
        "Posture-drift class commonly surfaced in internal-tool "
        "audits of long-lived Rust projects: no ``rust-version`` "
        "field, CI runner pinned to a Rust release from years "
        "ago, several CVEs in the standard library quietly in "
        "scope. Adding the explicit field forces the runner-"
        "image bump or a hard build failure.",
    ),
    exploit_example=(
        "# Vulnerable: no rust-version.\n"
        "[package]\n"
        "name = \"my-crate\"\n"
        "version = \"0.1.0\"\n"
        "\n"
        "[dependencies]\n"
        "serde = \"=1.0.190\"\n"
        "\n"
        "# Risk: the build picks up whatever Rust toolchain is\n"
        "# installed on the runner. A long-lived CI image may\n"
        "# still run Rust 1.60 with several patched-in-newer-\n"
        "# releases stdlib CVEs in scope. No build-time signal\n"
        "# warns the operator that the toolchain assumption is\n"
        "# stale.\n"
        "\n"
        "# Safe: pin the minimum.\n"
        "[package]\n"
        "name = \"my-crate\"\n"
        "version = \"0.1.0\"\n"
        "rust-version = \"1.75\"\n"
        "\n"
        "[dependencies]\n"
        "serde = \"=1.0.190\""
    ),
)


def _has_rust_version(text: str) -> bool:
    try:
        data: Any = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return False
    if not isinstance(data, dict):
        return False
    package = data.get("package")
    if not isinstance(package, dict):
        return False
    rv = package.get("rust-version")
    if isinstance(rv, str) and rv.strip():
        return True
    # Workspace-inherited form: rust-version.workspace = true
    if isinstance(rv, dict) and rv.get("workspace") is True:
        return True
    return False


def check(pom: CargoFile) -> Finding:
    if pom.is_workspace_root:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "Workspace-root manifest; rust-version lives in "
                "[workspace.package] which member crates inherit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if _has_rust_version(pom.text):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description="Cargo.toml declares [package].rust-version.",
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            "Cargo.toml has no [package].rust-version field. The "
            "build picks up whatever Rust toolchain happens to "
            "be installed; long-lived CI runners often carry "
            "older releases that lack recent security fixes."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
