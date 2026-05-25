"""NUGET-006, no NuGet lock file for reproducible restores."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import NuGetContext, NuGetProject

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
        "Fires when a csproj project exists but no "
        "``packages.lock.json`` was found."
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
    has_lock = bool(ctx.locks)
    desc = (
        "At least one packages.lock.json found; reproducible "
        "restores are possible with ``--locked-mode``."
        if has_lock else
        "No packages.lock.json found. Without a lock file, "
        "``dotnet restore`` silently upgrades transitive "
        "dependencies to whatever the feed currently serves."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=project.path, description=desc,
        recommendation=RULE.recommendation, passed=has_lock,
    )
