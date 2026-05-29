"""NPM-009, new transitive dependency added since the base ref."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import (
    NpmContext,
    NpmLock,
    iter_lock_packages,
    iter_manifest_dependencies,
)

RULE = Rule(
    id="NPM-009",
    title="New transitive dependency added since the base ref",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829", "CWE-1357"),
    recommendation=(
        "Audit the new transitive dependency before letting it "
        "land. Confirm the maintainer of the parent direct "
        "dependency intentionally added it (read the changelog of "
        "the patch / minor bump that introduced it). The axios -> "
        "plain-crypto-js backdoor (March 2026) was a single new "
        "transitive sneaked into a patch release; lockfile pinning "
        "alone is no defense when the new transient *is* the "
        "malicious payload. If the new transitive is unexpected, "
        "pin the parent dep to the previous version, file a "
        "registry advisory, and rotate any secret a CI build with "
        "the lockfile had access to. Pair with NPM-006 (known-"
        "compromised package) and NPM-008 (cooldown gate) so the "
        "catch isn't reliant on a single signal."
    ),
    docs_note=(
        "Needs ``--npm-base-ref <ref>`` to materialize each "
        "lockfile's contents at the base ref via ``git show``. "
        "Compares the set of package names in the current vs. "
        "base lockfile and subtracts top-level direct dependencies "
        "(those are NPM-008's territory). Fires HIGH per lockfile "
        "when any name appears in the current set that isn't in "
        "the base set, after the direct-dep subtraction. Silent-"
        "passes when ``--npm-base-ref`` isn't set, the base ref "
        "can't be resolved by git, or the lockfile is brand new "
        "to this branch (no base counterpart). Diffs by package "
        "*name* only — version bumps of an existing transitive "
        "are out of scope (NPM-006 covers known-bad version pins; "
        "NPM-008 covers fresh-publication windows). Both "
        "``package-lock.json`` (npm 7+) and ``pnpm-lock.yaml`` / "
        "``yarn.lock`` are covered through the shared lockfile-"
        "shape synthesizers, which carry each package's declared "
        "dependency edges. Every new transitive is annotated with "
        "the direct dependency that pulled it in (``<name> (via "
        "<parent>)``), traced through the edge graph to the nearest "
        "manifest dependency, so reviewers know whose changelog to "
        "read. A deep transitive with no resolvable manifest "
        "ancestor falls back to its immediate declaring parent."
    ),
    known_fp=(
        "A legitimate maintainer bump can introduce new "
        "transitives by design (a library splitting an internal "
        "helper into a separate package, an upstream switching "
        "from a vendored copy to a published dep). Suppress per-"
        "resource via ``--ignore-file`` once a human audits the "
        "new transitive and confirms it's expected.",
        "Branches that delete a direct dep also delete its "
        "transitives from the lockfile; re-adding the direct dep "
        "later resurrects the transitives. The rule fires on the "
        "re-add because the names are 'new' relative to the base "
        "ref. Review by reading the diff, then suppress.",
    ),
    incident_refs=(
        "axios -> plain-crypto-js (March 2026): a malicious "
        "transitive was added in a patch release of axios. "
        "Consumers who diffed transitives against their previous "
        "lockfile saw the new package land before ``npm install`` "
        "executed the payload.",
        "ua-parser-js (October 2021): a maintainer-account "
        "takeover published versions that quietly pulled in new "
        "transitives carrying a coinminer and credential stealer. "
        "Lockfile-pinning consumers who diffed transitives "
        "spotted the unexpected new packages before install.",
    ),
    exploit_example=(
        "// Vulnerable: a patch-level bump of ``axios`` quietly\n"
        "// brings in a new transitive that nobody on the team\n"
        "// audited. Lockfile pinning closes the bytes-swap window\n"
        "// for KNOWN transitives but is no defense when the\n"
        "// malicious code is the NEW transitive itself. The\n"
        "// axios -> plain-crypto-js compromise (Mar 2026) used\n"
        "// exactly this shape — a single new name in the lockfile\n"
        "// diff before ``npm install`` ran the payload.\n"
        "//\n"
        "// Lockfile delta visible at PR time:\n"
        "//   + node_modules/plain-crypto-js      (NEW transitive)\n"
        "//   ~ node_modules/axios                (1.6.0 -> 1.6.1)\n"
        "//\n"
        "// Without ``--npm-base-ref``, the diff is invisible to\n"
        "// the scanner and gets merged.\n"
        "\n"
        "// Safe: gate the lockfile in CI with\n"
        "// ``pipeline_check --pipeline npm --npm-base-ref origin/main``.\n"
        "// The rule materializes both lockfile states, subtracts\n"
        "// direct deps, and HIGH-fires on any new transitive name.\n"
        "// Reviewers either confirm the new transitive is intended\n"
        "// (read the parent's changelog and approve) or block the\n"
        "// merge until the compromised release is rotated off the\n"
        "// registry.\n"
        "// .github/workflows/audit.yml (caller of pipeline_check)\n"
        "- run: |\n"
        "    pipeline_check --pipeline npm \\\n"
        "      --npm-base-ref origin/main \\\n"
        "      --fail-on HIGH"
    ),
)


def _name_from_install_path(install_path: str) -> str | None:
    """Extract the package name from a lockfile install path.

    Handles npm 7+ ``node_modules/<name>``, scoped names
    ``node_modules/@scope/<name>``, nested transitives
    ``node_modules/foo/node_modules/bar``, the pnpm / yarn-1
    synthesizer's ``+<version>`` multi-version disambig suffix, and
    the npm 6 legacy v1 tree shape where install paths look like
    ``foo`` / ``foo/bar`` / ``foo/@scope/bar`` without the
    ``node_modules/`` prefix.
    """
    if not install_path:
        return None
    marker = "node_modules/"
    idx = install_path.rfind(marker)
    if idx >= 0:
        tail = install_path[idx + len(marker):]
    else:
        parts = install_path.split("/")
        if len(parts) >= 2 and parts[-2].startswith("@"):
            tail = f"{parts[-2]}/{parts[-1]}"
        else:
            tail = parts[-1]
    if tail.startswith("@") and "/" in tail:
        scope, _, rest = tail.partition("/")
        name = rest.split("+", 1)[0]
        if not name:
            return None
        return f"{scope}/{name}"
    name = tail.split("+", 1)[0]
    return name or None


def _lock_package_names(lock: NpmLock) -> set[str]:
    out: set[str] = set()
    for install_path, _record in iter_lock_packages(lock):
        name = _name_from_install_path(install_path)
        if name:
            out.add(name)
    return out


def _direct_dep_names(ctx: NpmContext) -> set[str]:
    out: set[str] = set()
    for manifest in ctx.manifests:
        for _section, name, _spec in iter_manifest_dependencies(manifest):
            out.add(name)
    return out


#: Per-record dependency maps that name child packages. npm 7+ writes
#: these on every ``packages`` entry; the npm 6 ``requires`` map is
#: added in :func:`_build_child_to_parents` when the lock is v1.
_RECORD_DEP_SECTIONS: tuple[str, ...] = (
    "dependencies", "optionalDependencies", "peerDependencies",
)


def _build_child_to_parents(lock: NpmLock) -> dict[str, set[str]]:
    """Map each declared child package name to the packages that declare it.

    Reads the per-record dependency maps the lockfile carries:
    ``dependencies`` / ``optionalDependencies`` / ``peerDependencies``
    on npm 7+ entries, plus the npm 6 ``requires`` map. The result is
    the declared-edge graph (parent names keyed by child name).

    The synthesized pnpm / yarn locks drop these maps (their
    synthesizers project only name / version / integrity / resolved),
    so the dict comes back empty for them and parent attribution
    degrades to silence rather than guessing.
    """
    sections = _RECORD_DEP_SECTIONS + (
        ("requires",) if lock.lockfile_version < 2 else ()
    )
    edges: dict[str, set[str]] = {}
    for install_path, record in iter_lock_packages(lock):
        parent = _name_from_install_path(install_path)
        if not parent:
            continue
        for section in sections:
            block = record.get(section)
            if not isinstance(block, dict):
                continue
            for child in block:
                if isinstance(child, str) and child:
                    edges.setdefault(child, set()).add(parent)
    return edges


def _attribute_introducers(
    transitive: str,
    child_to_parents: dict[str, set[str]],
    direct: set[str],
    *,
    max_depth: int = 8,
    max_results: int = 3,
) -> list[str]:
    """Return the direct dependency / dependencies that pulled *transitive* in.

    Walks the declared-edge graph upward from *transitive* toward the
    manifest's own deps. Each direct dependency reached is an
    introducer the developer actually controls (the one whose bump
    should explain the new transitive in its changelog). When the
    chain never reaches a manifest dep (a deep tree whose top isn't
    declared locally, or a lock format that carries no edges) it
    falls back to the immediate declaring parents so the finding
    still names something concrete.

    Cycle-guarded via ``seen`` and depth-bounded via ``max_depth`` so
    a pathological lockfile can't spin. Result is capped at
    ``max_results`` and sorted for stable output.
    """
    immediate = child_to_parents.get(transitive)
    if not immediate:
        return []
    direct_ancestors: set[str] = set()
    seen: set[str] = {transitive}
    frontier = set(immediate)
    depth = 0
    while frontier and depth < max_depth:
        nxt: set[str] = set()
        for node in frontier:
            if node in seen:
                continue
            seen.add(node)
            if node in direct:
                direct_ancestors.add(node)
                continue  # don't climb past a direct dep
            nxt |= child_to_parents.get(node, set())
        frontier = nxt
        depth += 1
    chosen = sorted(direct_ancestors) or sorted(immediate)
    return chosen[:max_results]


def check(lock: NpmLock, ctx: NpmContext | None = None) -> Finding:
    if ctx is None or not ctx.base_locks:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=lock.path,
            description=(
                "No base-ref lockfile available (re-run with "
                "``--npm-base-ref <ref>`` to enable transitive-"
                "diff analysis)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    base = next(
        (b for b in ctx.base_locks if b.path == lock.path), None,
    )
    if base is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=lock.path,
            description=(
                "No base-ref counterpart for this lockfile (new "
                "file in this branch, or not tracked at the base "
                "ref)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    current_names = _lock_package_names(lock)
    base_names = _lock_package_names(base)
    new_names = current_names - base_names
    direct = _direct_dep_names(ctx)
    new_transitive = sorted(n for n in new_names if n not in direct)
    child_to_parents = _build_child_to_parents(lock)

    def _label(name: str) -> str:
        introducers = _attribute_introducers(
            name, child_to_parents, direct,
        )
        if not introducers:
            return name
        return f"{name} (via {', '.join(introducers)})"

    locations: list[Location] = []
    for name in new_transitive[:5]:
        idx = lock.text.find(f'"{name}"')
        line_no = lock.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=lock.path, start_line=line_no, end_line=line_no,
        ))
    displayed = [_label(name) for name in new_transitive[:5]]
    passed = not new_transitive
    desc = (
        "Every package name in this lockfile was present at the "
        "base ref."
        if passed else
        f"{len(new_transitive)} new transitive dependency / "
        f"dependencies appeared in this lockfile that weren't in "
        f"the base-ref version: "
        f"{', '.join(displayed)}"
        f"{'…' if len(new_transitive) > 5 else ''}. A patch / "
        f"minor bump shouldn't introduce new transitives without "
        f"a clear changelog reason; review before letting this "
        f"land."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=lock.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
