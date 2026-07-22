"""SCM-030. Ruleset bypass actor configured with bypass_mode: always."""
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
    id="SCM-030",
    title="Repository ruleset has bypass actor with bypass_mode: always",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-2", "CICD-SEC-5"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-269", "CWE-693"),
    recommendation=(
        "For every bypass actor flagged, switch ``bypass_mode`` "
        "from ``always`` to ``pull_request`` in the ruleset "
        "configuration (Settings → Rules → <ruleset> → Bypass "
        "list → <actor> → Bypass mode). The ``pull_request`` mode "
        "requires the bypass to be requested via a PR review "
        "thread, which leaves an audit trail and gives reviewers "
        "a chance to push back. ``always`` mode is an unaudited "
        "override: the actor pushes / merges as if the ruleset "
        "weren't there, and no record names who or why. If the "
        "bypass is genuinely needed for emergency response, "
        "scope it to a specific GitHub App (the rule does not "
        "flag ``Integration`` bypasses by default) rather than "
        "a human role; an App is callable through your existing "
        "ticketing / approval flow."
    ),
    docs_note=(
        "For each ``active`` ruleset, walks ``bypass_actors`` "
        "(populated by the per-ruleset detail fetch) and flags "
        "every entry with ``bypass_mode: \"always\"`` whose "
        "``actor_type`` is not ``\"Integration\"`` (GitHub Apps). "
        "Non-app actors are listed by ``actor_type`` + "
        "``actor_id``; the rule does not resolve those IDs to "
        "human-readable names (that would require another API "
        "round-trip per actor; the operator already sees the "
        "names in the UI when they go to fix it).\n\n"
        "Rulesets in non-active enforcement modes are skipped — "
        "SCM-029 owns the not-enforced-at-all case and a "
        "non-active ruleset's bypass list is moot since the "
        "rules don't run anyway. Integration bypasses pass: a "
        "scoped GitHub App is a typical legitimate emergency-fix "
        "channel and shipping the bypass through the App's audit "
        "flow is the documented pattern. Requires admin scope; "
        "without it the ruleset-detail endpoint returns 403 / 404 "
        "and the rule passes silently."
    ),
    known_fp=(
        "Some orgs grant ``always`` bypass to a tightly-scoped "
        "automation team for after-hours emergency response. The "
        "right pattern is a GitHub App with auditable triggering "
        "(PagerDuty, Slack); ``always`` bypass for a human team "
        "leaves no record of the override. Suppress on the "
        "specific ruleset id with a calendar-bound rationale that "
        "names the audit channel and the next promotion review.",
    ),
    exploit_example=(
        "# Vulnerable: the repo ruleset names a bypass actor with\n"
        "# ``bypass_mode: always``. That actor (here a broad\n"
        "# repository role) skips every rule the ruleset enforces,\n"
        "# on every push, without any audit signal. Anyone holding\n"
        "# that role lands any change into ``main`` unreviewed.\n"
        "# (Integration / GitHub-App actors are a deliberate\n"
        "# carve-out and are NOT flagged.)\n"
        "# GET /repos/myorg/myrepo/rulesets/123:\n"
        "{\n"
        "  \"name\": \"main-protection\",\n"
        "  \"bypass_actors\": [\n"
        "    {\"actor_id\": 5, \"actor_type\": \"RepositoryRole\",\n"
        "     \"bypass_mode\": \"always\"}\n"
        "  ]\n"
        "}\n"
        "\n"
        "# Safe: ``bypass_mode: pull_request`` (the bot can open\n"
        "# its own bypass-eligible PR but must still pass review)\n"
        "# or remove the bypass actor entirely.\n"
        "# PUT /repos/myorg/myrepo/rulesets/123:\n"
        "{\n"
        "  \"name\": \"main-protection\",\n"
        "  \"bypass_actors\": [\n"
        "    {\"actor_id\": 5, \"actor_type\": \"RepositoryRole\",\n"
        "     \"bypass_mode\": \"pull_request\"}\n"
        "  ]\n"
        "}"
    ),
)


def _iter_bypass_offenders(ruleset: dict[str, Any]) -> list[str]:
    """Return labels of bypass actors with ``bypass_mode: "always"``
    on this ruleset, excluding Integration (GitHub App) bypasses."""
    bypass_actors = ruleset.get("bypass_actors")
    if not isinstance(bypass_actors, list):
        return []
    out: list[str] = []
    for actor in bypass_actors:
        if not isinstance(actor, dict):
            continue
        if actor.get("bypass_mode") != "always":
            continue
        actor_type = actor.get("actor_type")
        if actor_type == "Integration":
            # GitHub App bypasses are scoped + auditable through
            # the App's invocation channel; not the rule's surface.
            continue
        actor_id = actor.get("actor_id")
        label = (
            f"{actor_type}:{actor_id}"
            if isinstance(actor_type, str) and isinstance(actor_id, int)
            else "unrecognized bypass actor"
        )
        out.append(label)
    return out


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
                f"Repo is {label}; ruleset-bypass check skipped."
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
            description="No repository rulesets configured.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    unavailable_details: list[str] = []
    for rs in rulesets:
        # Non-active rulesets are SCM-029's surface; their bypass
        # configuration doesn't change runtime behavior.
        if rs.get("enforcement") != "active":
            continue
        name = rs.get("name")
        rs_id = rs.get("id")
        rs_label = name if isinstance(name, str) and name else (
            f"ruleset:{rs_id}" if isinstance(rs_id, int) else "(unnamed)"
        )
        # The per-ruleset detail fetch can fail independently
        # (403 / 404 / timeout). Without ``bypass_actors`` the rule
        # can't evaluate this ruleset; treat that as an explicit
        # unavailability signal instead of silently passing.
        if rs.get("_detail_unavailable") is True:
            unavailable_details.append(rs_label)
            continue
        labels = _iter_bypass_offenders(rs)
        if not labels:
            continue
        offenders.append(f"{rs_label} ({', '.join(labels)})")
    passed = not offenders
    if passed and unavailable_details:
        # Nothing to flag, but the bypass posture of at least one
        # active ruleset couldn't be evaluated. Surface as a
        # passing finding with the gap noted rather than failing.
        desc = (
            "Ruleset detail endpoint unavailable for "
            f"{len(unavailable_details)} active ruleset(s): "
            f"{', '.join(unavailable_details[:3])}"
            f"{'…' if len(unavailable_details) > 3 else ''}. "
            "Bypass-actor posture was not fully evaluated; ensure "
            "the token has admin scope on the repo to enable "
            "complete coverage."
        )
    elif passed:
        desc = (
            "No active ruleset configures ``always``-bypass for a "
            "non-Integration actor."
        )
    else:
        desc = (
            f"{len(offenders)} active ruleset(s) grant unaudited "
            f"bypass: {', '.join(offenders[:3])}"
            f"{'…' if len(offenders) > 3 else ''}. The listed actors "
            f"push / merge as if the ruleset weren't there, with no "
            f"PR-review audit trail."
        )
        if unavailable_details:
            desc += (
                f" Additionally, {len(unavailable_details)} "
                "ruleset(s) had their detail endpoint return an "
                "error and were not evaluated."
            )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
