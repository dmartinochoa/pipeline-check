"""SCM-039. Active ruleset doesn't pin a required workflow."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    github_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-039",
    title="Active ruleset doesn't pin a required workflow",
    severity=Severity.LOW,
    owasp=("CICD-SEC-1", "CICD-SEC-3"),
    esf=("ESF-S-CHANGE-CONTROL", "ESF-D-CI-COVERAGE"),
    cwe=("CWE-693",),
    recommendation=(
        "Add a ``workflows`` rule to the ruleset (Settings → "
        "Rules → <ruleset> → Add rule → Require workflows to "
        "pass before merging) and pin at least one workflow by "
        "repository + path + ref. The ``workflows`` ruleset rule "
        "differs from ``required_status_checks`` (SCM-033) in a "
        "load-bearing way: status checks gate on a context "
        "*name* that the workflow chooses to report — if the PR "
        "edits the workflow YAML to remove or rename that "
        "context, the check vanishes and the gate documents "
        "intent rather than reality. The ``workflows`` rule "
        "pins the workflow file at a vetted ref (``main`` or a "
        "specific SHA) and forces *that* workflow to run "
        "against the PR's code regardless of what the PR did to "
        "the workflow YAML in its own branch. Closes the "
        "scan-removal supply-chain shape (attacker opens a PR "
        "that deletes ``.github/workflows/security-scan.yml`` "
        "and submits malicious code in the same PR).\n\n"
        "Pin the workflow ref to either a long-lived branch the "
        "ruleset bypass actors don't have write access to or a "
        "specific SHA. A ref pinned to a branch the PR author "
        "controls undoes the protection."
    ),
    docs_note=(
        "For every active ruleset, walks the merged ``rules`` "
        "array looking for an entry with ``type: \"workflows\"`` "
        "whose ``parameters.workflows`` is a non-empty list. An "
        "empty workflows list is treated as no rule (it "
        "documents the gate without filling it). Passes silently "
        "when no rulesets are configured — required workflows "
        "have no legacy branch-protection analog, so absence of "
        "rulesets means the gate simply doesn't exist (not that "
        "it's carried elsewhere)."
    ),
    known_fp=(
        "Repos that don't run any workflow-based gating at all "
        "(pure code-review + signed-commits posture) legitimately "
        "ship without this rule. Suppress with a rationale that "
        "names the compensating controls. The rule fires LOW "
        "because most teams' security posture comes from "
        "status-checks (SCM-033); the workflows rule is the "
        "stricter scan-removal-resistant variant.",
    ),
)


def _has_workflows_rule(rules: Any) -> bool:
    if not isinstance(rules, list):
        return False
    for entry in rules:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "workflows":
            continue
        params = entry.get("parameters")
        if not isinstance(params, dict):
            # Bare ``workflows`` with no params is malformed; treat
            # as not-satisfied.
            continue
        workflows = params.get("workflows")
        if isinstance(workflows, list) and workflows:
            return True
    return False


def check(snapshot: SCMRepoSnapshot) -> Finding:
    skip = github_only_skip(snapshot)
    if skip is not None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=skip,
            recommendation=RULE.recommendation, passed=True,
        )
    if label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=f"Repo is {label}; ruleset required-workflows check skipped.",
            recommendation=RULE.recommendation, passed=True,
        )
    rulesets = snapshot.rulesets
    if rulesets is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "repos/rulesets endpoint unavailable (token "
                "likely lacks ``admin`` scope on the repo)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if not rulesets:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "No repository rulesets configured; required-"
                "workflows enforcement has no legacy branch-"
                "protection analog and is not separately "
                "evaluated."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    unavailable: list[str] = []
    for rs in rulesets:
        if rs.get("enforcement") != "active":
            continue
        name = rs.get("name")
        rs_id = rs.get("id")
        rs_label = name if isinstance(name, str) and name else (
            f"ruleset:{rs_id}" if isinstance(rs_id, int) else "(unnamed)"
        )
        if rs.get("_detail_unavailable") is True:
            unavailable.append(rs_label)
            continue
        if _has_workflows_rule(rs.get("rules")):
            continue
        offenders.append(rs_label)
    passed = not offenders
    if passed and unavailable:
        desc = (
            f"Ruleset detail unavailable for {len(unavailable)} "
            f"active ruleset(s): {', '.join(unavailable[:3])}"
            f"{'…' if len(unavailable) > 3 else ''}. Required-"
            "workflows posture not fully evaluated."
        )
    elif passed:
        desc = (
            "Every active ruleset pins at least one required "
            "workflow."
        )
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) don't pin a "
            f"required workflow: {', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. A PR that "
            "removes or renames a security-scan workflow in its "
            "own branch can land without that scan running, "
            "even when ``required_status_checks`` (SCM-033) is "
            "set on the context name."
        )
        if unavailable:
            desc += (
                f" Additionally, {len(unavailable)} ruleset(s) had "
                "detail-endpoint errors and were not evaluated."
            )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
