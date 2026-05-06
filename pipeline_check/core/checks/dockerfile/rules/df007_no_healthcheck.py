"""DF-007 — image declares no ``HEALTHCHECK``."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, has_directive, iter_instructions

RULE = Rule(
    id="DF-007",
    title="No HEALTHCHECK directive declared",
    severity=Severity.LOW,
    owasp=(),
    cwe=("CWE-693",),
    recommendation=(
        "Declare a ``HEALTHCHECK`` so the orchestrator can detect "
        "stuck or zombie containers. Example: ``HEALTHCHECK --interval"
        "=30s --timeout=5s --retries=3 CMD curl -fsS http://localhost"
        "/healthz || exit 1``. Skip this for builder/multi-stage "
        "intermediate images — only the runtime image needs one."
    ),
    docs_note=(
        "This is a defense-in-depth signal rather than an exploitation "
        "indicator — severity is LOW. A missing healthcheck doesn't "
        "create a vulnerability on its own, but downstream orchestrators "
        "(Kubernetes, ECS, Compose) cannot recover an unhealthy "
        "container they cannot detect, and that turns a soft failure "
        "(slow leak, deadlock) into a stale-process incident."
    ),
)


def check(df: Dockerfile) -> Finding:
    # Multi-stage builds: the rule only matters for the *final* stage,
    # since intermediate stages don't ship. If any HEALTHCHECK exists
    # *after* the last FROM, treat the image as healthchecked.
    saw_final_from = False
    final_has_hc = False
    for ins in df.instructions:
        if ins.directive == "FROM":
            saw_final_from = True
            final_has_hc = False
            continue
        if saw_final_from and ins.directive == "HEALTHCHECK":
            # Skip ``HEALTHCHECK NONE`` — that's an explicit opt-out
            # which is worse than no healthcheck (it suppresses the
            # base image's healthcheck too).
            if ins.args.strip().upper() != "NONE":
                final_has_hc = True
    # If the dockerfile has no FROM at all, the rule isn't applicable.
    if not has_directive(df, "FROM") and not any(
        ins.directive == "FROM" for ins in iter_instructions(df, directive="FROM")
    ):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=df.path,
            description="Dockerfile contains no FROM directive — runtime healthcheck not applicable.",
            recommendation="No action required.", passed=True,
        )
    passed = final_has_hc
    desc = (
        "Final stage declares a ``HEALTHCHECK``."
        if passed else
        "Final stage has no ``HEALTHCHECK`` (or sets ``HEALTHCHECK NONE``). "
        "Orchestrators can't detect a stuck container without one."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
