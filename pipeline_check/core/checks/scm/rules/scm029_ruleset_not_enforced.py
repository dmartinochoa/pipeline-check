"""SCM-029. Repository ruleset is in evaluate or disabled mode."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    github_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-029",
    title="Repository ruleset is in evaluate / disabled mode (not enforced)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-5"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-693", "CWE-269"),
    recommendation=(
        "Flip every non-enforcing ruleset to ``enforcement: "
        "active`` (Settings → Rules → Rulesets → <name> → "
        "Enforcement status → Active). The ``evaluate`` mode is "
        "intentionally permissive: it runs the rule logic and "
        "surfaces what *would* have been blocked, but it never "
        "actually blocks the push, merge, or commit. ``disabled`` "
        "is the explicit off-switch. Both modes silently document "
        "intent without enforcing the policy — operators commonly "
        "create rulesets in ``evaluate`` to preview their effect "
        "and forget to flip them, leaving the repo with the audit "
        "appearance of governance and the behavior of none.\n\n"
        "Note: the legacy-branch-protection rules in this pack "
        "(SCM-001..010) do NOT see rulesets. An org that has "
        "fully migrated to rulesets can pass the entire SCM-NNN "
        "legacy pack while every actual governance signal is "
        "in evaluate mode."
    ),
    docs_note=(
        "Walks ``GET /repos/{owner}/{repo}/rulesets`` and flags "
        "every entry whose ``enforcement`` is anything other than "
        "``\"active\"``. Two failure shapes are typical:\n\n"
        "* ``enforcement: \"evaluate\"`` — preview / dry-run mode; "
        "  the ruleset logic runs but doesn't block.\n"
        "* ``enforcement: \"disabled\"`` — explicit off; rule "
        "  exists in the UI but takes no effect.\n\n"
        "Passes silently when no rulesets are configured "
        "(``[]``); in that case the SCM-001..010 legacy branch-"
        "protection rules carry the governance load. Requires "
        "admin scope on the repo; without it the endpoint returns "
        "403 / 404 and the rule passes silently with an "
        "unavailability note."
    ),
    known_fp=(
        "A freshly-authored ruleset legitimately sits in "
        "``evaluate`` mode for a short audit window before "
        "promotion to ``active``. Suppress for that specific "
        "ruleset id with a calendar-bound rationale; the rule "
        "should keep flagging until the promotion lands so the "
        "transition window doesn't quietly become permanent.",
    ),
)


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
                f"Repo is {label}; rulesets check skipped."
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
                "protection rules (SCM-001..010) carry the "
                "governance load."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for rs in rulesets:
        enforcement = rs.get("enforcement")
        if enforcement == "active":
            continue
        name = rs.get("name")
        rs_id = rs.get("id")
        label = name if isinstance(name, str) and name else (
            f"ruleset:{rs_id}" if isinstance(rs_id, int) else "(unnamed)"
        )
        mode = enforcement if isinstance(enforcement, str) else "unknown"
        offenders.append(f"{label} ({mode})")
    passed = not offenders
    desc = (
        f"All {len(rulesets)} ruleset(s) are actively enforced."
        if passed else
        f"{len(offenders)} ruleset(s) not actively enforced: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The ruleset's "
        f"rules run but do not block (evaluate) or do not run at "
        f"all (disabled) — governance documented, not enforced."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
