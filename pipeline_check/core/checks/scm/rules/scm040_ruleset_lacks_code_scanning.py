"""SCM-040. Active ruleset doesn't gate on code scanning results."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    active_rulesets_targeting_default,
    archived_state_label,
    default_branch_name,
    github_only_skip,
    repo_resource,
    ruleset_label,
)

RULE = Rule(
    id="SCM-040",
    title="Active ruleset doesn't gate on code scanning results",
    severity=Severity.LOW,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-S-CHANGE-CONTROL", "ESF-D-CI-COVERAGE"),
    cwe=("CWE-693",),
    recommendation=(
        "Add a ``code_scanning`` rule to the ruleset (Settings → "
        "Rules → <ruleset> → Add rule → Require code scanning "
        "results) and pin at least one tool (CodeQL, the most "
        "common choice) with a non-empty alerts threshold. The "
        "rule turns a passive code-scanning configuration "
        "(SCM-003 — default setup is on) into an active merge "
        "gate: the PR can't merge until the scan completes for "
        "the head SHA *and* the configured threshold isn't "
        "crossed (e.g. ``security_alerts_threshold: "
        "\"high_or_higher\"`` rejects merges that introduce "
        "high-severity findings). Closes the asymmetry between "
        "code scanning being enabled and the org actually "
        "blocking on its results.\n\n"
        "If your org doesn't license GHAS (the underlying "
        "feature), this rule type isn't available. Suppress with "
        "a rationale that names the licensing constraint and "
        "carry the gate via ``required_status_checks`` (SCM-033) "
        "pointed at the named context the scan tool reports."
    ),
    docs_note=(
        "For every active ruleset, walks the merged ``rules`` "
        "array looking for an entry with ``type: "
        "\"code_scanning\"`` whose "
        "``parameters.code_scanning_tools`` lists at least one "
        "tool. An empty tools list documents the gate without "
        "filling it and is treated as no rule. Passes silently "
        "when no rulesets are configured — the rule_type is "
        "ruleset-only and has no legacy branch-protection "
        "analog, so absence of rulesets means the gate simply "
        "doesn't exist (not that it's enforced elsewhere)."
    ),
    known_fp=(
        "GHAS-licensing constraint: the ``code_scanning`` "
        "ruleset rule type requires GitHub Advanced Security on "
        "the repo. Repos on free / team tier can't configure "
        "this rule even when they run code scanning via "
        "third-party tools. Suppress with the licensing "
        "rationale and ensure SCM-033 carries the merge gate "
        "via the scan tool's reported status-check context.",
    ),
)


def _has_code_scanning_rule(rules: Any) -> bool:
    if not isinstance(rules, list):
        return False
    for entry in rules:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "code_scanning":
            continue
        params = entry.get("parameters")
        if not isinstance(params, dict):
            # Bare ``code_scanning`` with no params is malformed;
            # treat as not-satisfied.
            continue
        tools = params.get("code_scanning_tools")
        if isinstance(tools, list) and tools:
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
            description=f"Repo is {label}; ruleset code-scanning check skipped.",
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
                "No repository rulesets configured; code-"
                "scanning gating has no legacy branch-"
                "protection analog and is not separately "
                "evaluated."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    targeting, unavailable_rs, scoped_away = (
        active_rulesets_targeting_default(snapshot)
    )
    if not targeting and scoped_away:
        labels = [ruleset_label(rs) for rs in scoped_away]
        default = default_branch_name(snapshot)
        desc = (
            f"{len(scoped_away)} active ruleset(s) configured "
            f"but none target the default branch "
            f"(refs/heads/{default}): "
            f"{', '.join(labels[:3])}"
            f"{'…' if len(labels) > 3 else ''}. Code-"
            f"scanning gating has no legacy branch-"
            f"protection analog, so the default branch has "
            f"no merge-gate on scan results."
        )
        if unavailable_rs:
            desc += (
                f" Additionally, {len(unavailable_rs)} active "
                "ruleset(s) had detail-endpoint errors and were "
                "not evaluated."
            )
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=desc,
            recommendation=RULE.recommendation, passed=False,
        )
    if not targeting and not unavailable_rs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "No active rulesets target the default branch; "
                "code-scanning gating has no legacy branch-"
                "protection analog and is not separately "
                "evaluated."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    # GitHub aggregates rules across every ruleset targeting a ref, so
    # the gate is satisfied when ANY targeting ruleset carries it. Fire
    # only when none does (the whole targeting set then lists as the
    # offenders: no ruleset on the default branch carries the gate).
    covered = any(_has_code_scanning_rule(rs.get("rules")) for rs in targeting)
    offenders: list[str] = (
        [] if covered else [ruleset_label(rs) for rs in targeting]
    )
    unavailable = [ruleset_label(rs) for rs in unavailable_rs]
    passed = not offenders
    if passed and unavailable:
        desc = (
            f"Ruleset detail unavailable for {len(unavailable)} "
            f"active ruleset(s): {', '.join(unavailable[:3])}"
            f"{'…' if len(unavailable) > 3 else ''}. Code-"
            "scanning gating posture not fully evaluated."
        )
    elif passed:
        desc = (
            "Every active ruleset targeting the default branch "
            "gates on code scanning results."
        )
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) targeting the "
            f"default branch don't gate on code scanning "
            f"results: {', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. Scans may be "
            "configured (SCM-003) but their results aren't "
            "blocking merges."
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
