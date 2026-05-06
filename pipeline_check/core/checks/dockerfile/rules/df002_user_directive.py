"""DF-002 — image runs as root (no ``USER`` directive, or ``USER root``)."""
from __future__ import annotations

from ...base import Finding, Severity
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
        "a container is not isolation — a kernel CVE, a misconfigured "
        "mount, or a mis-applied capability collapses straight into the "
        "host."
    ),
    docs_note=(
        "Multi-stage builds: only the final stage matters for runtime "
        "identity, since intermediate stages don't ship. The check "
        "scopes USER to the *last* FROM through end-of-file."
    ),
)


def _last_stage_user(df: Dockerfile) -> str | None:
    """Return the USER value active at the end of the final stage,
    or None if no USER directive exists in that stage."""
    final_user: str | None = None
    saw_final_from = False
    for ins in df.instructions:
        if ins.directive == "FROM":
            # New stage — reset USER tracking; only the final stage
            # determines the runtime identity.
            saw_final_from = True
            final_user = None
            continue
        if saw_final_from and ins.directive == "USER":
            final_user = ins.args.strip()
    return final_user


def check(df: Dockerfile) -> Finding:
    # If no FROM at all, this isn't a runnable Dockerfile — silent pass
    # (DF-001 will already have flagged a missing image).
    if not any(ins.directive == "FROM" for ins in iter_instructions(df, directive="FROM")):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=df.path,
            description="Dockerfile contains no FROM directive — runtime identity not applicable.",
            recommendation="No action required.", passed=True,
        )
    user = _last_stage_user(df)
    if user is None:
        passed = False
        desc = (
            "Final stage has no ``USER`` directive — the image runs as "
            "root by default, which collapses container isolation in the "
            "presence of any kernel CVE or mount misconfiguration."
        )
    elif user.lower() in ("root", "0", "0:0"):
        passed = False
        desc = (
            f"Final stage explicitly sets ``USER {user}`` — equivalent "
            f"to running as root. Switch to a dedicated non-root user "
            f"(``useradd --uid 1001 app && USER app``)."
        )
    else:
        passed = True
        desc = f"Final stage runs as ``USER {user}`` (non-root)."
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
