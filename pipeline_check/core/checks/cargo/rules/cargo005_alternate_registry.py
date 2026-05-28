"""CARGO-005. Cargo.toml dependency sourced from an alternate registry."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import CargoFile

RULE = Rule(
    id="CARGO-005",
    title="Cargo.toml dependency sourced from an alternate registry",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Alternate-registry dependencies (``registry = \"my-internal\"``) "
        "bypass crates.io and resolve against whatever URL is "
        "configured under ``[registries.my-internal]`` in "
        "``.cargo/config.toml``. The substitution is fine when the "
        "alternate is a well-known internal registry that the operator "
        "controls; it's a supply-chain risk when the registry name is "
        "ambiguous (collides with a public registry name) or when the "
        "configured URL is committed alongside the manifest without "
        "an explicit allowlist.\n\n"
        "Audit each alternate-registry entry: confirm that the "
        "registry URL is well-known to the team, that it's served "
        "over HTTPS, and that pushes to the registry are gated by "
        "the same review process that gates the source repo. If the "
        "dependency is also available on crates.io at the same "
        "version, prefer the default registry — fewer moving parts, "
        "and the public crates.io trust signals (download counts, "
        "yanked-version tracking) are not available against private "
        "registries."
    ),
    docs_note=(
        "Fires on any dependency entry that sets ``registry = "
        "\"...\"``. The rule operates on the manifest text only — it "
        "doesn't fetch the configured ``[registries.<name>]`` URL "
        "from ``.cargo/config.toml`` to verify it's well-formed or "
        "HTTPS. Operators wanting URL-level checks should audit the "
        "config file separately; this rule's value is surfacing the "
        "fact that an alternate registry is in use, leaving the URL "
        "audit to the operator."
    ),
    known_fp=(
        "Internal-registry setups where every crate is intentionally "
        "sourced from a private feed trip this rule by design. The "
        "right operator response is a project-level suppression "
        "(``pipelinecheckignore``) for the specific registry name, "
        "with a one-line rationale naming the registry's owner.",
    ),
    incident_refs=(
        "Crate-name-collision pattern: a private registry hosts a "
        "crate ``foo``, the public crates.io also has a ``foo``. A "
        "contributor edits ``.cargo/config.toml`` to remove the "
        "registry override (intentionally or via merge conflict), "
        "the next build pulls the public ``foo`` and links against "
        "it. This rule surfaces the alternate-registry dependency "
        "so the operator can decide whether the override is still "
        "load-bearing.",
    ),
    exploit_example=(
        "# Vulnerable / risky: alternate registry pulled in but the\n"
        "# registry URL isn't pinned at the manifest layer.\n"
        "[dependencies]\n"
        "internal-utils = { version = \"1.2.3\", registry = \"corp\" }\n"
        "\n"
        "# .cargo/config.toml (not committed):\n"
        "# [registries.corp]\n"
        "# index = \"https://crates.corp.example/git\"\n"
        "\n"
        "# Risk: a future contributor renames the registry mapping\n"
        "# in .cargo/config.toml (or removes it entirely). Builds\n"
        "# fail loudly in the obvious case; in the\n"
        "# crates.io-also-has-a-crate-named-internal-utils case,\n"
        "# they silently link against the public crate.\n"
        "\n"
        "# Safe: when the alternate registry is intentional, pin\n"
        "# the URL in .cargo/config.toml at the workspace root and\n"
        "# review it as part of the manifest audit."
    ),
)


def check(pom: CargoFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    seen: set[str] = set()
    for dep in pom.dependencies:
        if not dep.registry:
            continue
        offenders.append(f"{dep.name} (registry: {dep.registry})")
        if dep.registry not in seen:
            seen.add(dep.registry)
        locations.append(Location(
            path=pom.path, start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    if passed:
        desc = (
            "Every Cargo.toml dependency resolves against the "
            "default (crates.io) registry."
        )
    else:
        desc = (
            f"{len(offenders)} dependency / dependencies sourced "
            f"from alternate registries: {', '.join(offenders[:5])}"
            f"{'…' if len(offenders) > 5 else ''}. Each entry "
            f"resolves against whatever URL is configured under "
            f"``[registries.<name>]`` in ``.cargo/config.toml``."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
