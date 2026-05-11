"""GHA-041. Workflow uses an action whose upstream repo has a single contributor.

A single-maintainer action is a single point of compromise: one
phished credential, one stolen device, one disgruntled departure
maps directly to a malicious release the caller's workflow consumes
on the next run. The risk is the same shape as a 1-of-1 PyPI / npm
package; tj-actions / reviewdog were both single-maintainer repos
at the time of compromise.

Network-dependent: needs ``--resolve-remote`` (or an explicit
fixture set in tests) to populate ``ctx.action_metadata``. Without
it the rule passes silently with a note pointing at the flag.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitHubContext, Workflow, iter_jobs, iter_steps
from ..uses_parser import parse_uses

RULE = Rule(
    id="GHA-041",
    title="Action upstream repo has a single contributor",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Audit the action repo's contributor list. If the repo "
        "genuinely has one maintainer, pin to a vendored fork "
        "under your org's control (so a future compromise on the "
        "upstream doesn't reach your build runtime) or move to a "
        "first-party action covering the same surface. The "
        "single-maintainer pattern is what made tj-actions / "
        "reviewdog one-day compromises so widely-blast."
    ),
    docs_note=(
        "Reads the contributor count from "
        "``ctx.action_metadata[owner/repo].contributor_count`` "
        "(populated by the ``--resolve-remote`` path; the GitHub "
        "REST ``/contributors`` endpoint, capped at two entries — "
        "the rule only cares about == 1). When the fetch failed or "
        "the flag is off, the rule passes silently. Forks and "
        "archived repos that ALSO have a single contributor fire "
        "the rule; the fork / archived state is part of the same "
        "supply-chain risk story."
    ),
    known_fp=(
        "Some well-maintained single-author actions (high-quality "
        "personal-account repos that the maintainer simply hasn't "
        "open-sourced governance for) are not actually compromised. "
        "Suppress via ignore-file when a security review has "
        "confirmed the maintainer's identity and 2FA posture.",
    ),
    incident_refs=(
        "tj-actions / reviewdog March 2025 compromises (CVE-2025-"
        "30066 / CVE-2025-30154): both upstream repos had a single "
        "primary contributor at the time of compromise. The "
        "single-maintainer pattern was central to the blast radius "
        "(no second pair of eyes on the malicious commit, no "
        "auto-rollback when the tag move landed).",
    ),
)


def check(
    path: str, doc: dict[str, Any], wf: Workflow, ctx: GitHubContext,
) -> Finding:
    matches: list[str] = []
    seen: set[str] = set()
    # Pre-collect the unique action refs in this workflow so the
    # finding description doesn't list ``actions/checkout`` 20 times
    # for a workflow that uses it on every job.
    for _, job in iter_jobs(doc):
        _scan_value(job.get("uses"), ctx, seen, matches)
        for step in iter_steps(job):
            _scan_value(step.get("uses"), ctx, seen, matches)
    passed = not matches
    if not ctx.action_metadata:
        # Opt-in flag is off (or fetch failed for every action). The
        # rule passes silently with a discovery nudge — the same
        # pattern GHA-001 + GHA-025 use when the resolver is off.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No action metadata available. Rerun with "
                "``--resolve-remote`` (and optionally ``--gh-token`` "
                "for the higher rate-limit ceiling) to enable "
                "single-maintainer detection on referenced actions."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if passed:
        desc = (
            "Every action referenced by this workflow has more than "
            "one upstream contributor."
        )
    else:
        sample = ", ".join(sorted(matches)[:3])
        if len(matches) > 3:
            sample += f" (+{len(matches) - 3} more)"
        desc = (
            f"{len(matches)} action(s) reference a single-contributor "
            f"upstream repo: {sample}. A single maintainer is a "
            f"single point of compromise — the same posture that "
            f"made tj-actions / reviewdog March 2025 a one-day "
            f"supply-chain incident."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )


def _scan_value(
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
    meta = ctx.action_metadata.get(key)
    if meta is None:
        return  # no data, can't decide; rule passes silently
    if meta.contributor_count is None:
        return
    if meta.contributor_count <= 1:
        matches.append(f"{ref.owner}/{ref.repo}")
