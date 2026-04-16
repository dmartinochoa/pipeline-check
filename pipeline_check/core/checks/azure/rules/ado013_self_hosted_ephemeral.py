"""ADO-013 — self-hosted pools should demand an ephemeral marker."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import MS_HOSTED_NAMES

RULE = Rule(
    id="ADO-013",
    title="Self-hosted pool without explicit ephemeral marker",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    recommendation=(
        "Configure the agent pool with autoscaling + ephemeral "
        "agents (the Azure VM Scale Set agent), and add `demands: "
        "[ephemeral -equals true]` on the pool block so this check "
        "can verify it."
    ),
    docs_note=(
        "`pool: { name: <agent-pool> }` (or the bare string form "
        "`pool: <name>`) targets a self-hosted agent pool. Without "
        "an explicit ephemeral arrangement, agents reuse state "
        "across jobs. Microsoft-hosted pools (`vmImage:` or the "
        "`Azure Pipelines` / `Default` names) are skipped."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offending: list[str] = []

    def _classify(pool: Any, where: str) -> None:
        if pool is None:
            return
        if isinstance(pool, str):
            if pool.lower() in MS_HOSTED_NAMES:
                return
            offending.append(f"{where}: pool='{pool}'")
            return
        if isinstance(pool, dict):
            if "vmImage" in pool:
                return
            name = pool.get("name")
            demands = pool.get("demands") or []
            demand_text = (
                " ".join(demands).lower()
                if isinstance(demands, list)
                else str(demands).lower()
            )
            if isinstance(name, str) and name.lower() not in MS_HOSTED_NAMES:
                if "ephemeral" not in demand_text:
                    offending.append(f"{where}: pool.name='{name}'")

    _classify(doc.get("pool"), "<top>")
    for job_loc, job in iter_jobs(doc):
        _classify(job.get("pool"), job_loc)
    passed = not offending
    desc = (
        "No self-hosted pool runs without an explicit ephemeral marker."
        if passed else
        f"{len(offending)} self-hosted pool reference(s) lack an "
        f"`ephemeral` demand: {', '.join(offending[:5])}"
        f"{'…' if len(offending) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
