"""NUGET-006, no NuGet lock file for reproducible restores."""
from __future__ import annotations

import posixpath

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetContext, NuGetProject


def _dir_of(path: str) -> str:
    return posixpath.dirname(path.replace("\\", "/"))

RULE = Rule(
    id="NUGET-006",
    title="No NuGet lock file for reproducible restores",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-353",),
    recommendation=(
        "Enable NuGet lock files by setting "
        "``<RestorePackagesWithLockFile>true"
        "</RestorePackagesWithLockFile>`` in the csproj (or "
        "``Directory.Build.props`` for solution-wide coverage) and "
        "commit the generated ``packages.lock.json``. In CI, restore "
        "with ``dotnet restore --locked-mode`` so the build fails if "
        "the lock file disagrees with the project file. Without a "
        "lock file, ``dotnet restore`` silently upgrades transitive "
        "dependencies to whatever the feed currently serves."
    ),
    docs_note=(
        "Fires when a csproj project has no ``packages.lock.json`` in "
        "its own directory. A lock file for a sibling project elsewhere "
        "in the tree doesn't make this project's restore reproducible."
    ),
)


def check(project: NuGetProject, ctx: NuGetContext) -> Finding:
    # Only relevant for csproj-based projects; packages.config
    # projects have a different resolution model.
    if project.path.lower().endswith("packages.config"):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=project.path,
            description=(
                "packages.config project; lock file check not "
                "applicable."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    # ``dotnet restore --locked-mode`` needs each project's OWN
    # ``packages.lock.json`` (written alongside the csproj), so a lock
    # for a sibling project doesn't cover this one.
    proj_dir = _dir_of(project.path)
    has_lock = any(_dir_of(lock.path) == proj_dir for lock in ctx.locks)
    desc = (
        "A co-located packages.lock.json was found; reproducible "
        "restores are possible with ``--locked-mode``."
        if has_lock else
        "No packages.lock.json found alongside this project. Without a "
        "lock file, ``dotnet restore`` silently upgrades transitive "
        "dependencies to whatever the feed currently serves."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=project.path, description=desc,
        recommendation=RULE.recommendation, passed=has_lock,
    )
