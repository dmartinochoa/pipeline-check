"""CP-007 — CodePipeline v2 pull-request trigger lacks branch scope."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CP-007",
    title="CodePipeline v2 PR trigger accepts all branches",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-284",),
    recommendation=(
        "On V2 pipelines, add an ``includes`` filter under the trigger's "
        "``branches`` block (and optionally ``pullRequest.events``) so "
        "only PRs targeting specific branches run. Without a filter, "
        "any fork-PR can execute the pipeline's build and deploy stages."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for pipeline in catalog.codepipeline_pipelines():
        if pipeline.get("pipelineType") != "V2":
            continue
        name = pipeline.get("name", "<unnamed>")
        open_triggers: list[str] = []
        for idx, trig in enumerate(pipeline.get("triggers", []) or []):
            if trig.get("providerType") not in ("CodeStarSourceConnection",):
                continue
            git_config = trig.get("gitConfiguration") or {}
            pr_cfg = git_config.get("pullRequest") or []
            # Unconfigured PR triggers = any branch, any event.
            if not pr_cfg:
                continue
            for pr in pr_cfg:
                branches = pr.get("branches") or {}
                includes = branches.get("includes") or []
                if not includes or "*" in includes:
                    open_triggers.append(f"triggers[{idx}]")
                    break
        if not open_triggers:
            continue
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name,
            description=(
                f"V2 pipeline '{name}' PR trigger(s) {open_triggers} accept "
                "PRs against any branch."
            ),
            recommendation=RULE.recommendation, passed=False,
        ))
    return findings
