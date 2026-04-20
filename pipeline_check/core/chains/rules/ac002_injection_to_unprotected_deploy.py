"""AC-002 — Script Injection to Unprotected Production Deploy.

A workflow that interpolates untrusted PR/issue input into a shell
step (script-injection) and deploys without a gated environment
gives a PR opener a path straight to production.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-002",
    title="Script Injection to Unprotected Deploy",
    severity=Severity.CRITICAL,
    summary=(
        "A workflow interpolates untrusted GitHub event data into a "
        "shell command (script-injection) and the same workflow "
        "deploys without an environment-gated approval. An attacker "
        "with PR/issue access can hijack the deploy."
    ),
    mitre_attack=(
        "T1059.004",  # Command and Scripting Interpreter: Unix Shell
        "T1190",      # Exploit Public-Facing Application
        "T1648",      # Serverless Execution
    ),
    kill_chain_phase="initial-access -> execution -> impact",
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution-PPE",
        "https://github.blog/security/application-security/four-tips-to-keep-your-github-actions-workflows-secure/",
    ),
    recommendation=(
        "Pipe untrusted input through an env-var (one-shot quoting) and "
        "add `environment: production` with required reviewers to the "
        "deploy job. Either fix alone narrows the chain."
    ),
    providers=("github",),
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["GHA-003", "GHA-014"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["GHA-003"], ck_map["GHA-014"]]
        narrative = (
            f"In `{resource}`:\n"
            "  1. A shell `run:` step interpolates "
            "`${{ github.event.* }}` directly (GHA-003) — an attacker "
            "controls the value via PR title/body/branch name.\n"
            "  2. A deploy step in the same workflow has no `environment:` "
            "binding (GHA-014), so no required-reviewer gate fires.\n"
            "  3. Attacker submits a PR whose title contains a shell "
            "payload; the runner executes it and the deploy step pushes "
            "attacker artefacts to production."
        )
        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=min_confidence(triggers),
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=["GHA-003", "GHA-014"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
