"""DF-002, image runs as root (no ``USER`` directive, or ``USER root``)."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Dockerfile, iter_instructions

RULE = Rule(
    id="DF-002",
    title="Container runs as root (missing or root USER directive)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-250",),
    recommendation=(
        "Add a ``USER <non-root>`` directive after package install steps "
        "(e.g. ``USER 1001`` or ``USER appuser``). Running as root inside "
        "a container is not isolation, a kernel CVE, a misconfigured "
        "mount, or a mis-applied capability collapses straight into the "
        "host."
    ),
    docs_note=(
        "Multi-stage builds: only the final stage matters for runtime "
        "identity, since intermediate stages don't ship. The check "
        "scopes USER to the *last* FROM through end-of-file."
    ),
    incident_refs=(
        "CVE-2019-5736 (runC host breakout): a malicious container "
        "running as root could overwrite the host's runC binary and "
        "compromise every other container on the node. Non-root "
        "containers were not exploitable. "
        "https://www.cve.org/CVERecord?id=CVE-2019-5736",
        "CVE-2022-0492 (cgroups v1 escape via release_agent): root "
        "inside a container with CAP_SYS_ADMIN could write to the "
        "host's release_agent file and execute arbitrary host code. "
        "Containers running as a non-root UID side-stepped the "
        "exploit class entirely. "
        "https://www.cve.org/CVERecord?id=CVE-2022-0492",
    ),
)


def _last_stage_user(df: Dockerfile) -> tuple[str | None, int | None, int | None]:
    """Return ``(user, user_line, final_from_line)`` for the final stage.

    ``user`` is the USER value active at the end of the final stage
    (None if absent). ``user_line`` is the line of the offending USER
    directive when one is present (None if absent). ``final_from_line``
    is the line of the final ``FROM``, used as the location anchor
    when no USER directive exists in the final stage.
    """
    final_user: str | None = None
    final_user_line: int | None = None
    final_from_line: int | None = None
    saw_final_from = False
    for ins in df.instructions:
        if ins.directive == "FROM":
            saw_final_from = True
            final_user = None
            final_user_line = None
            final_from_line = ins.line_no
            continue
        if saw_final_from and ins.directive == "USER":
            final_user = ins.args.strip()
            final_user_line = ins.line_no
    return final_user, final_user_line, final_from_line


def check(df: Dockerfile) -> Finding:
    # If no FROM at all, this isn't a runnable Dockerfile, silent pass
    # (DF-001 will already have flagged a missing image).
    if not any(ins.directive == "FROM" for ins in iter_instructions(df, directive="FROM")):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=df.path,
            description="Dockerfile contains no FROM directive, runtime identity not applicable.",
            recommendation="No action required.", passed=True,
        )
    user, user_line, final_from_line = _last_stage_user(df)
    locations: list[Location] = []
    if user is None:
        passed = False
        desc = (
            "Final stage has no ``USER`` directive, the image runs as "
            "root by default, which collapses container isolation in the "
            "presence of any kernel CVE or mount misconfiguration."
        )
        # Anchor on the final FROM, that's where the absent USER
        # directive's stage starts.
        if final_from_line is not None:
            locations.append(Location(
                path=df.path, start_line=final_from_line,
                end_line=final_from_line,
            ))
    elif user.lower() in ("root", "0", "0:0"):
        passed = False
        desc = (
            f"Final stage explicitly sets ``USER {user}``, equivalent "
            f"to running as root. Switch to a dedicated non-root user "
            f"(``useradd --uid 1001 app && USER app``)."
        )
        if user_line is not None:
            locations.append(Location(
                path=df.path, start_line=user_line, end_line=user_line,
            ))
    else:
        passed = True
        desc = f"Final stage runs as ``USER {user}`` (non-root)."
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
