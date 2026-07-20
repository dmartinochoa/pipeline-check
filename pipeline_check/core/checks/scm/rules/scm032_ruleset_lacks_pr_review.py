"""SCM-032. Active ruleset doesn't require a PR review."""
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
    id="SCM-032",
    title="Active ruleset doesn't require a PR review (governance theater)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-5"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-269", "CWE-862"),
    recommendation=(
        "Add a ``pull_request`` rule to every active ruleset and "
        "set ``parameters.required_approving_review_count`` to at "
        "least 1 (Settings → Rules → <ruleset> → Add rule → "
        "Require a pull request before merging → Required "
        "approvals). An active ruleset without a PR-review gate is "
        "the same shape as legacy branch protection without "
        "required reviews (SCM-002): the ruleset is enforced — "
        "force-push denial, signed commits, status checks may all "
        "fire — but pushes / merges still go through without "
        "human review. Operators commonly create rulesets for "
        "specific governance signals (e.g., commit-message "
        "patterns for compliance) and forget that the PR-review "
        "gate is a separate rule type that has to be added "
        "explicitly.\n\n"
        "SCM-032 aggregates across rulesets the way GitHub does: "
        "the default branch is covered when any ruleset targeting "
        "it carries a PR-review rule, so a layered config (an "
        "org-level ruleset that requires reviews plus a repo-level "
        "ruleset that only enforces a commit-message pattern) "
        "passes. It fires only when no ruleset targeting the "
        "default branch requires a PR review. It stays within the "
        "ruleset layer and doesn't consult legacy branch "
        "protection; SCM-002 covers that side, and the two "
        "together describe the full review-control surface."
    ),
    docs_note=(
        "Across the active rulesets targeting the default branch, "
        "looks for an entry with ``type: \"pull_request\"`` whose "
        "``parameters.required_approving_review_count`` is at "
        "least 1. Fires only when none of them carries one "
        "(GitHub aggregates rules across every ruleset targeting a "
        "ref). Non-active rulesets are SCM-029's surface; rulesets "
        "with unavailable detail are surfaced with an evaluation-"
        "gap note (the same pattern SCM-030 uses). Tag- and push-"
        "targeted rulesets are ignored (they don't protect "
        "branches).\n\n"
        "Pairs with SCM-002 (legacy branch-protection required "
        "reviews) and SCM-029 (ruleset not enforced). The three "
        "rules together cover the required-review surface: "
        "SCM-002 for legacy BP, SCM-029 for the existence of an "
        "active ruleset, SCM-032 for whether that ruleset "
        "actually requires a PR."
    ),
    known_fp=(
        "Some rulesets are deliberately scoped to enforce only "
        "non-PR-review controls (e.g., a ``commit_message_"
        "pattern`` ruleset for changelog compliance, or a "
        "``tag_name_pattern`` ruleset for release tagging). The "
        "right pattern is to ALSO have a separate ruleset that "
        "enforces PR reviews on the same refs; SCM-032 fires "
        "when the *combination* leaves a gap. Suppress on the "
        "specific ruleset id with a rationale that names the "
        "PR-review channel (separate ruleset or legacy branch "
        "protection).",
    ),
    exploit_example=(
        "# Vulnerable: the ruleset is enforced (governance theater\n"
        "# checks pass) but doesn't include a ``pull_request``\n"
        "# rule. Pushes to ``main`` still require a PR (via\n"
        "# ``deletion`` / ``non_fast_forward`` rules), but the PR\n"
        "# itself doesn't need any review. A single author\n"
        "# self-merges into production.\n"
        "# GET /repos/myorg/myrepo/rulesets/123:\n"
        "{\n"
        "  \"name\": \"main-protection\",\n"
        "  \"enforcement\": \"active\",\n"
        "  \"rules\": [\n"
        "    {\"type\": \"deletion\"},\n"
        "    {\"type\": \"non_fast_forward\"}\n"
        "  ]\n"
        "}\n"
        "\n"
        "# Safe: add a ``pull_request`` rule with at least one\n"
        "# required reviewer. Pair with ``dismiss_stale_reviews_\n"
        "# on_push: true`` so a re-push invalidates the approval\n"
        "# and forces a fresh review.\n"
        "# PUT /repos/myorg/myrepo/rulesets/123:\n"
        "{\n"
        "  \"name\": \"main-protection\",\n"
        "  \"enforcement\": \"active\",\n"
        "  \"rules\": [\n"
        "    {\"type\": \"deletion\"},\n"
        "    {\"type\": \"non_fast_forward\"},\n"
        "    {\"type\": \"pull_request\",\n"
        "     \"parameters\": {\n"
        "       \"required_approving_review_count\": 1,\n"
        "       \"dismiss_stale_reviews_on_push\": true\n"
        "     }}\n"
        "  ]\n"
        "}"
    ),
)


def _has_pr_review_rule(rules: Any) -> bool:
    """True when *rules* (the ``rules`` array on a ruleset detail
    body) contains a ``pull_request`` entry with at least one
    required approving review."""
    if not isinstance(rules, list):
        return False
    for entry in rules:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "pull_request":
            continue
        params = entry.get("parameters")
        if not isinstance(params, dict):
            # ``pull_request`` rule with no parameters block is a
            # GitHub API quirk on older rulesets; default review
            # count is 1 in that case. Treat as satisfied.
            return True
        count = params.get("required_approving_review_count")
        if isinstance(count, int) and count >= 1:
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
            description=(
                f"Repo is {label}; ruleset PR-review check skipped."
            ),
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
                "No repository rulesets configured; legacy branch-"
                "protection (SCM-002) carries the PR-review gate."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    targeting, unavailable, scoped_away = (
        active_rulesets_targeting_default(snapshot)
    )
    if not targeting and scoped_away:
        # Active rulesets exist but none target the default branch.
        # The PR-review gate (where this rule looks for it) isn't
        # applied to refs/heads/<default>. Legacy SCM-002 still
        # carries the gate on the default branch, but the operator's
        # explicit ruleset configuration leaves the default branch
        # uncovered at the ruleset layer.
        labels = [ruleset_label(rs) for rs in scoped_away]
        default = default_branch_name(snapshot)
        desc = (
            f"{len(scoped_away)} active ruleset(s) configured "
            f"but none target the default branch "
            f"(refs/heads/{default}): "
            f"{', '.join(labels[:3])}"
            f"{'…' if len(labels) > 3 else ''}. The PR-review "
            f"gate isn't applied to the default branch at the "
            f"ruleset layer; SCM-002 covers the legacy "
            f"branch-protection carry."
        )
        if unavailable:
            desc += (
                f" Additionally, {len(unavailable)} active "
                "ruleset(s) had detail-endpoint errors and were "
                "not evaluated."
            )
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=desc,
            recommendation=RULE.recommendation, passed=False,
        )
    if not targeting and not unavailable:
        # All rulesets are non-active. SCM-029 covers; the per-rule
        # check is silent on the default branch.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "No active rulesets target the default branch; "
                "legacy branch-protection (SCM-002) carries the "
                "PR-review gate."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    # GitHub aggregates rules across every ruleset targeting a ref, so
    # the gate is satisfied when ANY targeting ruleset carries it. Fire
    # only when none does (the whole targeting set then lists as the
    # offenders: no ruleset on the default branch carries the gate).
    covered = any(_has_pr_review_rule(rs.get("rules")) for rs in targeting)
    offenders: list[str] = (
        [] if covered else [ruleset_label(rs) for rs in targeting]
    )
    unavailable_details = [ruleset_label(rs) for rs in unavailable]
    passed = not offenders
    if passed and unavailable_details:
        desc = (
            "Ruleset detail endpoint unavailable for "
            f"{len(unavailable_details)} active ruleset(s): "
            f"{', '.join(unavailable_details[:3])}"
            f"{'…' if len(unavailable_details) > 3 else ''}. "
            "PR-review posture was not fully evaluated; ensure "
            "the token has admin scope on the repo."
        )
    elif passed:
        desc = (
            "Every active ruleset targeting the default branch "
            "includes a ``pull_request`` rule with at least 1 "
            "required review."
        )
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) targeting the "
            f"default branch don't require a PR review: "
            f"{', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. The ruleset "
            f"is enforced but pushes / merges land without human "
            f"review — governance documented, not gated."
        )
        if unavailable_details:
            desc += (
                f" Additionally, {len(unavailable_details)} "
                "ruleset(s) had detail-endpoint errors and were "
                "not evaluated."
            )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
