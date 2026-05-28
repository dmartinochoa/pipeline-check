"""CARGO-002. Cargo.toml git dependency uses a mutable ref (no rev)."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import CargoFile

RULE = Rule(
    id="CARGO-002",
    title="Cargo.toml git dependency uses a mutable ref (no rev)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Pin every git dependency to an exact commit SHA via "
        "``rev = \"<40-char-sha>\"``. Cargo's other git-source "
        "selectors all carry mutable semantics: ``branch = \"main\"`` "
        "resolves the branch head on every fetch, ``tag = \"v1\"`` "
        "follows the tag if it's force-moved, and an unspecified "
        "selector means ``branch = \"HEAD\"``. None of those survive "
        "a force-push or maintainer-account compromise.\n\n"
        "Example safe form:\n\n"
        "    foo = { git = \"https://github.com/example/foo\", "
        "rev = \"a1b2c3d4e5f6...\" }\n\n"
        "If the upstream genuinely needs to track a moving target "
        "(an internal fork still on its own branch), vendor the "
        "code into the repo or run a private crate registry "
        "where you control the publish event."
    ),
    docs_note=(
        "Fires on any dependency entry that sets ``git = \"...\"`` "
        "without a ``rev`` key, regardless of whether ``branch`` / "
        "``tag`` is set. Cargo treats ``tag``-pinned entries as "
        "mutable because git tags can be reassigned without rewriting "
        "history (Cargo notes the tag's resolved commit in the "
        "lockfile, but the manifest still doesn't bind to it). "
        "``rev`` is the only specifier that pins to immutable "
        "content."
    ),
    known_fp=(
        "Some workspaces use git ``tag`` with a strict "
        "release-tag-immutability policy (signed tags, no force-"
        "move). The rule still fires because the manifest can't "
        "express that policy. Suppress per dep with a one-line "
        "rationale naming the upstream's tag-immutability "
        "guarantee.",
    ),
    incident_refs=(
        "Tag-following pattern in Rust application crates: a "
        "popular utility crate's maintainer account is compromised, "
        "force-moves the ``v1.2.3`` tag to a malicious commit. "
        "Every downstream consumer's next ``cargo build`` with "
        "the tag-pinned entry pulls the rewritten commit; rev-"
        "pinned consumers are unaffected because their lockfile "
        "and manifest both reference the original commit.",
    ),
    exploit_example=(
        "# Vulnerable: tag pin tracks the moving target.\n"
        "[dependencies]\n"
        "utility = { git = \"https://github.com/example/utility\", tag = \"v1.2.3\" }\n"
        "\n"
        "# Attack: maintainer account compromised; the v1.2.3 tag\n"
        "# is force-moved to a malicious commit. Downstream\n"
        "# ``cargo update`` resolves the tag, lockfile records the\n"
        "# new SHA, build accepts it.\n"
        "\n"
        "# Safe: rev pin.\n"
        "[dependencies]\n"
        "utility = { git = \"https://github.com/example/utility\", rev = \"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0\" }"
    ),
)


def check(pom: CargoFile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        if not dep.is_git or not dep.git_mutable:
            continue
        offenders.append(dep.name)
        locations.append(Location(
            path=pom.path, start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    desc = (
        "Every git dependency in Cargo.toml is pinned to a rev."
        if passed else
        f"{len(offenders)} git dependency / dependencies pinned to "
        f"a mutable ref (branch / tag / unspecified): "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each entry resolves "
        f"to whatever the upstream's git ref points at on the next "
        f"fetch."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
