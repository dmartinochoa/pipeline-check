"""CP-003. CodePipeline Source action uses polling instead of event trigger."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CP-003",
    title="Source stage using polling instead of event-driven trigger",
    severity=Severity.LOW,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-400",),
    recommendation=(
        "Set PollForSourceChanges=false and configure an Amazon EventBridge "
        "rule or CodeCommit trigger to start the pipeline on change. This "
        "reduces latency, API usage, and improves auditability."
    ),
    docs_note=(
        "``PollForSourceChanges=true`` polls the source repo every "
        "minute or two. Beyond the API-quota and latency cost, "
        "polling produces a less-useful CloudTrail story than "
        "event-driven triggers. You see the poll calls, not the "
        "specific commit that started the pipeline. EventBridge / "
        "CodeCommit triggers tie each pipeline start to the "
        "originating event."
    ),
    known_fp=(
        "``PollForSourceChanges=true`` is the CFN default for "
        "CodeCommit sources, so legacy templates can carry the flag "
        "without an active design decision behind it. The rule is "
        "advisory (consider EventBridge / CodeStarSourceConnection) "
        "rather than a real risk; defaults to LOW confidence so CI "
        "gates default-filter it.",
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for pipeline in catalog.codepipeline_pipelines():
        name = pipeline.get("name", "<unnamed>")
        polling_sources: list[str] = []
        for stage in pipeline.get("stages", []) or []:
            for action in stage.get("actions", []) or []:
                category = action.get("actionTypeId", {}).get("category", "")
                if category != "Source":
                    continue
                config = action.get("configuration", {}) or {}
                if str(config.get("PollForSourceChanges", "")).lower() == "true":
                    polling_sources.append(action.get("name", "unnamed"))
        passed = not polling_sources
        if passed:
            desc = "All source actions use event-driven change detection."
        else:
            desc = (
                f"Source action(s) {polling_sources} use polling "
                f"(PollForSourceChanges=true). Polling-based triggers have higher "
                f"latency, consume API quota, and may miss rapid successive changes."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
