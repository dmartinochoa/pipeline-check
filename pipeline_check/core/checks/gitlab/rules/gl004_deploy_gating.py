"""GL-004 — deploy jobs must be gated by manual approval or environment."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import DEPLOY_RE, rules_manual

RULE = Rule(
    id="GL-004",
    title="Deploy job lacks manual approval or environment gate",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    recommendation=(
        "Add `when: manual` (optionally with `rules:` for protected "
        "branches) or bind the job to an `environment:` with a "
        "deployment tier so approvals and audit are enforced by "
        "GitLab's environment controls."
    ),
    docs_note=(
        "A job whose stage or name contains `deploy` / `release` / "
        "`publish` / `promote` should either require manual approval "
        "or declare an `environment:` binding. Otherwise any push to "
        "the trigger branch ships to the target."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    ungated: list[str] = []
    for name, job in iter_jobs(doc):
        stage = job.get("stage")
        is_deploy = (
            (isinstance(stage, str) and DEPLOY_RE.search(stage))
            or DEPLOY_RE.search(name)
        )
        if not is_deploy:
            continue
        manual = job.get("when") == "manual" or rules_manual(job.get("rules"))
        has_env = bool(job.get("environment"))
        if not (manual or has_env):
            ungated.append(name)
    passed = not ungated
    desc = (
        "All deploy-like jobs are gated by manual approval or environment."
        if passed else
        f"{len(ungated)} deploy job(s) run automatically without a manual "
        f"gate or `environment:` binding: {', '.join(ungated)}. Any push "
        f"to the trigger branch will ship to the target."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
