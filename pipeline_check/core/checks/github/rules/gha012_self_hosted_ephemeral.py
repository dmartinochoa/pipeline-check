"""GHA-012 — self-hosted runners must carry the `ephemeral` marker."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="GHA-012",
    title="Self-hosted runner without ephemeral marker",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    recommendation=(
        "Configure the self-hosted runner to register with "
        "`--ephemeral` (the runner exits after one job and is "
        "freshly registered), and add an `ephemeral` label so this "
        "check can verify it. Consider actions-runner-controller "
        "for ephemeral pools."
    ),
    docs_note=(
        "Self-hosted runners that don't tear down between jobs leak "
        "filesystem and process state. A PR-triggered job writes to "
        "`/tmp`; a subsequent prod-deploy job on the same runner "
        "reads it. The mitigation is the runner's `--ephemeral` "
        "mode — the runner exits after one job and re-registers "
        "fresh. The check looks for an `ephemeral` label on the "
        "`runs-on` value; without one, the runner is presumed "
        "reusable. Recognises all three `runs-on` shapes: string, "
        "list, and `{ group, labels }` dict form."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offending: list[str] = []
    for job_id, job in iter_jobs(doc):
        runs_on = job.get("runs-on")
        labels: list[str] = []
        if isinstance(runs_on, str):
            labels = [runs_on]
        elif isinstance(runs_on, list):
            labels = [str(x) for x in runs_on]
        elif isinstance(runs_on, dict):
            ll = runs_on.get("labels")
            if isinstance(ll, list):
                labels = [str(x) for x in ll]
            elif isinstance(ll, str):
                labels = [ll]
        label_set = {lbl.lower() for lbl in labels}
        if "self-hosted" not in label_set:
            continue
        if "ephemeral" not in label_set:
            offending.append(job_id)
    passed = not offending
    desc = (
        "No self-hosted job runs without an ephemeral marker."
        if passed else
        f"{len(offending)} self-hosted job(s) lack an `ephemeral` "
        f"label: {', '.join(offending)}. Without ephemeral runners "
        f"the worker keeps filesystem and process state across "
        f"jobs, letting a PR-triggered job seed data that a later "
        f"deploy job reads."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
