"""GHA-091. Workflow references an action whose upstream namespace is takeover-eligible.

Inspired by zizmor proposal #479 (repojacking). The owner of
``uses: vendor/setup-foo@<sha>`` renamed or deleted the org; the
name is now claimable by anyone. The next time a tag or branch ref
is resolved (``@v1`` / ``@main``) the workflow runs whatever the
new owner pushes. Even SHA-pinned references degrade gracefully: a
maintainer who later un-pins (because the action got a new tag with
a fix) hits the takeover.

Network-dependent: needs ``--resolve-remote`` to populate
``ctx.action_fetch_failures`` (the set of ``owner/repo`` slugs whose
``GET /repos/{o}/{r}`` fetch returned no payload, the 404 the
repojacking signal anchors on). The same per-action repo fetch the
GHA-041..043 reputation rules ride on, no new HTTP call.

Pairs with GHA-001 (unpinned ``uses:``) and GHA-040 (compromised
SHA / tag).
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitHubContext, Workflow, iter_jobs, iter_steps
from ..uses_parser import parse_uses

RULE = Rule(
    id="GHA-091",
    title="Action upstream repo is missing (takeover-eligible namespace)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829"),
    recommendation=(
        "Confirm the upstream namespace status. If the owner / repo "
        "was genuinely deleted (the resolver returns 404 while the "
        "workflow still references it), vendor the action under your "
        "org's control immediately, pin to your fork's SHA, and "
        "audit any prior workflow runs that used a non-SHA ref "
        "(``@v1`` / ``@main``). If the owner was renamed and the new "
        "name carries the canonical project, update the ``uses:`` "
        "slug. Pairs with the no-name-squatting posture, every "
        "external action your CI runs should resolve to a namespace "
        "your org controls or one the upstream maintainer still "
        "owns."
    ),
    docs_note=(
        "Reads from ``ctx.action_fetch_failures``, the set of "
        "``owner/repo`` slugs whose ``GET /repos/{o}/{r}`` fetch "
        "returned no payload during the ``--resolve-remote`` pass. "
        "Unanimous-failure shape (every referenced action's fetch "
        "failed) is treated as rate-limit / resolver noise rather "
        "than repojacking, the rule passes silently with a one-line "
        "nudge so the operator surfaces the network issue. "
        "Single-action failures are real signals because all the "
        "other actions in the same scan fetched fine, the "
        "infrastructure is up and the 404 is specifically this "
        "namespace. Both step-level and reusable-workflow "
        "``uses:`` are covered. HIGH severity, the takeover-"
        "eligibility window opens the moment the namespace flips "
        "and stays open until the workflow no longer references "
        "the slug."
    ),
    known_fp=(
        "Private upstreams that pipeline-check can't see without a "
        "token may show up here. Confirm the 404 by hitting the URL "
        "from a browser with the appropriate auth; if the repo is "
        "private but reachable for your org, the resolver's "
        "unauthenticated probe is the false positive and "
        "``--gh-token`` fixes it. Persistent / by-design private "
        "actions should be suppressed per-finding with a rationale "
        "that names the access boundary.",
    ),
    incident_refs=(
        "rentbcn / tj-actions namespace-deletion incidents "
        "(2024-2025): the upstream owner deleted the org and the "
        "name became registrable. Any workflow that re-resolved a "
        "non-SHA ref afterward ran the new owner's code. The shape "
        "is the canonical example for repojacking write-ups from "
        "Aikido, Wiz, and Snyk Research.",
    ),
    exploit_example=(
        "# Vulnerable: the upstream owner deleted the org.\n"
        "# pipeline-check's resolver got a 404 on /repos/legacy/\n"
        "# abandoned. The slug is now registrable by anyone, and a\n"
        "# subsequent re-pin to ``@v2`` (because v1 had a CVE)\n"
        "# pulls the attacker's first release.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: legacy/abandoned@<sha>\n"
        "      - run: ./build.sh\n"
        "\n"
        "# Safe: vendored under your org's control.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: yourorg/abandoned-fork@<sha>\n"
        "      - run: ./build.sh"
    ),
)


def _scan_uses(
    value: Any,
    ctx: GitHubContext,
    seen: set[str],
    matches: list[str],
) -> None:
    ref = parse_uses(value)
    if ref is None:
        return
    if ref.kind not in {"remote-action", "remote-workflow"}:
        return
    if not ref.owner or not ref.repo:
        return
    key = f"{ref.owner.lower()}/{ref.repo.lower()}"
    if key in seen:
        return
    seen.add(key)
    if key in ctx.action_fetch_failures:
        matches.append(f"{ref.owner}/{ref.repo}")


def _total_referenced_actions(ctx: GitHubContext) -> int:
    """Count distinct ``owner/repo`` slugs referenced across every
    loaded workflow.

    Drives the all-or-some heuristic: unanimous failure is rate-
    limit noise, not repojacking.
    """
    from .._action_reputation import collect_referenced_actions
    return len(collect_referenced_actions(ctx))


def check(
    path: str, doc: dict[str, Any], wf: Workflow, ctx: GitHubContext,
) -> Finding:
    matches: list[str] = []
    seen: set[str] = set()
    for _, job in iter_jobs(doc):
        _scan_uses(job.get("uses"), ctx, seen, matches)
        for step in iter_steps(job):
            _scan_uses(step.get("uses"), ctx, seen, matches)
    # Did the resolver run at all? If neither metadata nor failure
    # info is present, the flag is off and we pass silently with a
    # nudge.
    resolver_active = bool(ctx.action_metadata) or bool(ctx.action_fetch_failures)
    if not resolver_active:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No repo-fetch data available. Rerun with "
                "``--resolve-remote`` (and optionally ``--gh-token`` "
                "for the higher rate-limit ceiling) to enable "
                "repojacking detection on referenced actions."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    # Unanimous-failure heuristic: if every referenced action's
    # fetch failed and none succeeded, treat as rate-limit / network
    # noise. Requires at least two referenced actions to apply (one
    # failure is a real signal, the resolver had no peer to compare
    # against).
    total_referenced = _total_referenced_actions(ctx)
    if (
        total_referenced >= 2
        and not ctx.action_metadata
        and len(ctx.action_fetch_failures) >= 2
    ):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Every referenced action's repo-fetch failed; "
                "treating as resolver / rate-limit noise rather than "
                "repojacking. Rerun with --gh-token to lift the "
                "unauthenticated rate-limit ceiling."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    passed = not matches
    if passed:
        desc = (
            "Every action referenced by this workflow resolves to a "
            "live upstream repo (no 404 / takeover-eligible "
            "namespace detected)."
        )
    else:
        sample = ", ".join(sorted(matches)[:3])
        if len(matches) > 3:
            sample += f" (+{len(matches) - 3} more)"
        desc = (
            f"{len(matches)} action(s) reference a missing upstream "
            f"repo (the namespace is takeover-eligible): {sample}. "
            f"Even SHA-pinned references degrade once the namespace "
            f"is re-registered: the next un-pin operation pulls "
            f"attacker code under the same ``uses:`` slug."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
