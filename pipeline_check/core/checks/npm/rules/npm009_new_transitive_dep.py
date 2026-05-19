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
        "shape synthesizers."
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
    locations: list[Location] = []
    for name in new_transitive[:5]:
        idx = lock.text.find(f'"{name}"')
        line_no = lock.text[:idx].count("\n") + 1 if idx >= 0 else 1
        locations.append(Location(
            path=lock.path, start_line=line_no, end_line=line_no,
        ))
    passed = not new_transitive
    desc = (
        "Every package name in this lockfile was present at the "
        "base ref."
        if passed else
        f"{len(new_transitive)} new transitive dependency / "
        f"dependencies appeared in this lockfile that weren't in "
        f"the base-ref version: "
        f"{', '.join(new_transitive[:5])}"
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
