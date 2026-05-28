"""CARGO-004. Cargo.toml dependency is a local-path entry."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import CargoFile

RULE = Rule(
    id="CARGO-004",
    title="Cargo.toml dependency is a local-path entry",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Local-path entries (``path = \"../local\"``) bypass the "
        "Cargo registry and the lockfile's content-hash gate. They "
        "exist for two legitimate use cases — workspace members "
        "(handled by Cargo's workspace mechanism, which uses "
        "``[workspace]`` not per-dep paths) and active dev loops "
        "where a contributor is editing two crates side-by-side. "
        "Neither belongs in a committed manifest that runs on CI.\n\n"
        "Three remediation patterns:\n\n"
        "* If the dependency is a sibling workspace member, declare "
        "the workspace at the root (``[workspace.members = ...]``) "
        "and let Cargo resolve siblings automatically — no per-dep "
        "``path =`` needed.\n"
        "* If the dependency is a local fork being actively patched, "
        "publish the fork to a private crate registry and pin to "
        "it from the manifest.\n"
        "* If the path entry is a dev-loop leftover that should "
        "never have been committed, remove it and add the upstream "
        "back to the regular ``[dependencies]`` table."
    ),
    docs_note=(
        "Fires on any dependency entry that sets ``path = \"...\"``. "
        "Workspace-root manifests aren't audited for path entries "
        "since the ``[workspace.dependencies]`` table is the normal "
        "place to centralize workspace-member references."
    ),
    known_fp=(
        "Multi-crate dev repos that pre-date Cargo workspaces "
        "(Rust 2018) sometimes still use per-dep ``path =`` instead "
        "of ``[workspace.members]``. The right fix is the "
        "workspace migration; suppress per dep if the migration is "
        "tracked as separate technical debt.",
    ),
    incident_refs=(
        "Common contributor-laptop leakage in Rust monorepos: "
        "``foo = { path = \"../foo-fork\" }`` lands in a PR because "
        "the local dev loop pointed at a sibling clone, tests "
        "passed on the contributor's machine, CI's lenient "
        "resolution swallowed the missing path. Production builds "
        "either fail or — worse — pick up whatever sibling "
        "directory happens to live next to the runner's working "
        "tree.",
    ),
    exploit_example=(
        "# Vulnerable: committed path dep.\n"
        "[dependencies]\n"
        "foo = { path = \"../foo-fork\" }\n"
        "\n"
        "# Risk: CI runner needs the sibling path to exist. Either\n"
        "# build fails outright (the obvious case) or, on a runner\n"
        "# image where some unrelated directory happens to live at\n"
        "# the path, Cargo silently builds against that.\n"
        "\n"
        "# Safe: declare the workspace at the repo root.\n"
        "# [workspace]\n"
        "# members = [\"foo\", \"bar\"]\n"
        "# Per-crate manifests no longer need path = ... ; Cargo\n"
        "# resolves sibling workspace members automatically."
    ),
)


def check(pom: CargoFile) -> Finding:
    if pom.is_workspace_root:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pom.path,
            description=(
                "Workspace-root manifest; path entries here are the "
                "normal mechanism for workspace-member references."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    locations: list[Location] = []
    for dep in pom.dependencies:
        if not dep.is_path:
            continue
        offenders.append(dep.name)
        locations.append(Location(
            path=pom.path, start_line=dep.line_no, end_line=dep.line_no,
        ))
    passed = not offenders
    desc = (
        "No local-path dependency entries in Cargo.toml."
        if passed else
        f"{len(offenders)} local-path dependency entries: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Each entry bypasses "
        f"the registry and the lockfile's content-hash gate; CI "
        f"builds depend on whatever sibling directory exists on "
        f"the runner."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pom.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
