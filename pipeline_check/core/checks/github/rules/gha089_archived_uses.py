"""GHA-089. Workflow references an action whose upstream repo is archived.

Mirrors zizmor's ``archived-uses`` audit. Online-only: the
``archived`` bit lives on ``GET /repos/{o}/{r}``, routed through the
``--resolve-remote`` path that GHA-041..043 already use to populate
``ctx.action_metadata``. No new HTTP call, the same per-action repo
fetch carries the field.

The dependency still works today but won't receive security patches;
eventually a maintainer relinquishes the namespace and someone else
can claim it (the repojacking shape GHA-091 fires on).
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitHubContext, Workflow, iter_jobs, iter_steps
from ..uses_parser import parse_uses

RULE = Rule(
    id="GHA-089",
    title="Action upstream repo is archived",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Migrate to an actively-maintained action covering the "
        "same surface. Archived upstreams stop receiving security "
        "patches the day the archive bit lands; vulnerabilities "
        "discovered afterward stay unpatched, and the namespace is "
        "eligible to be reclaimed by anyone once the original "
        "owner deletes or transfers the repo (the repojacking "
        "shape, see also GHA-091). If a fork under "
        "your org's control is the only path forward, vendor the "
        "action and pin to your fork's SHA, so an upstream takeover "
        "can't reach your build runtime."
    ),
    docs_note=(
        "Reads the archived bit from "
        "``ctx.action_metadata[owner/repo].archived`` (populated "
        "by ``--resolve-remote``; the same per-action repo fetch "
        "the GHA-041..043 reputation rules consume). When the "
        "metadata is empty (flag off, fetch failed, private repo "
        "with no token), the rule passes silently with a one-line "
        "nudge pointing at the flag. Covers both step-level "
        "``uses:`` (action references) and job-level ``uses:`` "
        "(reusable workflow references); MEDIUM severity, the "
        "archived bit alone is not an exploit primitive but it is "
        "a documented precondition for the takeover shapes "
        "GHA-091 and GHA-040 catch."
    ),
    known_fp=(
        "An action that an upstream maintainer archived because a "
        "first-party replacement ships (e.g., a legacy migration "
        "helper deprecated in favor of a built-in feature) is "
        "archived for legitimate reasons, not abandonment. The "
        "fork-and-vendor recommendation is still the right call "
        "for security posture, but suppress per-finding with a "
        "rationale once the operator has confirmed the migration "
        "path is on a roadmap.",
    ),
    incident_refs=(
        "tj-actions / reviewdog March 2025 (CVE-2025-30066 / "
        "CVE-2025-30154): both action namespaces were briefly "
        "archived during the compromise window; pinned consumers "
        "ran the malicious tag on the next sync. Archived state is "
        "one of the pre-conditions the post-incident timelines "
        "highlight.",
    ),
    exploit_example=(
        "# Vulnerable: archived upstream still in use. The next\n"
        "# discovered vulnerability in the action's runtime won't\n"
        "# get a fix; the namespace is eligible for repojacking\n"
        "# the moment the owner deletes the repo.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: legacy-org/abandoned-action@v3\n"
        "      - run: ./build.sh\n"
        "\n"
        "# Safe: same surface, actively maintained replacement.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: ./build.sh"
    ),
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
        return
    if meta.archived:
        matches.append(f"{ref.owner}/{ref.repo}")


def check(
    path: str, doc: dict[str, Any], wf: Workflow, ctx: GitHubContext,
) -> Finding:
    matches: list[str] = []
    seen: set[str] = set()
    for _, job in iter_jobs(doc):
        _scan_value(job.get("uses"), ctx, seen, matches)
        for step in iter_steps(job):
            _scan_value(step.get("uses"), ctx, seen, matches)
    if not ctx.action_metadata:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No action metadata available. Rerun with "
                "``--resolve-remote`` (and optionally ``--gh-token`` "
                "for the higher rate-limit ceiling) to enable "
                "archived-uses detection on referenced actions."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    passed = not matches
    if passed:
        desc = (
            "Every action referenced by this workflow has an "
            "actively-maintained (not archived) upstream repo."
        )
    else:
        sample = ", ".join(sorted(matches)[:3])
        if len(matches) > 3:
            sample += f" (+{len(matches) - 3} more)"
        desc = (
            f"{len(matches)} action(s) reference an archived "
            f"upstream repo: {sample}. Archived dependencies stop "
            f"receiving security patches and become eligible for "
            f"namespace takeover the moment the owner deletes the "
            f"repo."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
