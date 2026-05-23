"""GHA-094. Action SHA pin is the current tip of an upstream branch.

Mirrors zizmor's ``stale-action-refs`` from the opposite angle:
zizmor flags SHA pins that don't point at any tag (drift indicator,
"this SHA isn't a release"). Pipeline-check fires on the higher-
risk shape: a pinned SHA that equals the *current* tip of an
upstream branch.

Why this matters: a maintainer who can push to a branch can re-
point the branch HEAD. If your workflow pins to a SHA that happens
to be the current tip of ``main`` / ``release/x`` / a feature
branch, the maintainer's next push moves the tip; your pin stays
on the old commit, but anyone re-pinning to "the latest branch
HEAD" picks up the new code. Worse, a freshly-pushed branch HEAD
(the cooldown shape GHA-047 catches) might be unreviewed work the
maintainer pushed under time pressure, the SHA pin gives the
illusion of immutability without the audit guarantee.

Network-dependent: needs ``--resolve-remote`` to populate
``ctx.action_metadata[*].branch_head_shas`` (the
``/repos/{o}/{r}/branches?per_page=100`` snapshot). Without it the
rule passes silently with a note pointing at the flag.

Pairs with GHA-047 (fresh referenced ref), GHA-001 (unpinned
``uses:``), and GHA-090 (impostor-commit, the cross-network sibling
of this in-network risk).
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..._primitives.sha_ref import SHA_RE_IGNORECASE as _SHA_RE
from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitHubContext, Workflow, iter_jobs, iter_steps
from ..uses_parser import parse_uses

RULE = Rule(
    id="GHA-094",
    title="Action SHA pin matches the current tip of an upstream branch",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Re-pin to a SHA that's tagged in the upstream repo (a "
        "release commit) rather than the current tip of an active "
        "branch. Branch HEADs are mutable, the maintainer's next "
        "push can move the tip even when your pin stays still, and "
        "anyone re-pinning to \"latest\" picks up unaudited code. "
        "A SHA that lives only at a tag (``v4.1.7`` -> commit X) "
        "is a stable target: re-tagging is a louder, more visible "
        "action than a normal push, and a release-flavored tag "
        "implies a review pass the maintainer staged. If the "
        "action has no tagged releases at all, vendor the action "
        "under your org's control or accept the inherent drift "
        "risk by suppressing this finding with a rationale."
    ),
    docs_note=(
        "Reads the branch-tip set from "
        "``ctx.action_metadata[owner/repo].branch_head_shas`` "
        "(populated by ``--resolve-remote``; one ``/branches?per_"
        "page=100`` call per action with at least one SHA-shaped "
        "``uses: owner/repo@<sha>``). For each SHA pin, fires "
        "when ``<sha>`` is the tip of any branch in the snapshot. "
        "Repos with more than 100 branches are an edge case; the "
        "rule skips additional pages. Tag-pinned refs (``@v4``, "
        "``@main``) are out of scope, they don't carry the in-"
        "network mutability surface this rule targets. Both step-"
        "level and reusable-workflow ``uses:`` are covered, "
        "case-insensitive matching against the lower-cased SHA "
        "snapshot. MEDIUM severity, the maintainer's ability to "
        "re-point the branch is a latent risk rather than an "
        "in-progress exploit; pair with GHA-047 to escalate when "
        "the branch tip is also freshly committed."
    ),
    known_fp=(
        "An action whose tagged-release flow lags real activity "
        "(maintainers push to ``main`` continuously but tag "
        "rarely) shows every recent SHA as a branch tip. The "
        "right fix is upstream: ask the maintainer to tag, or "
        "pin to a tagged ancestor SHA. If suppression is the only "
        "path, do it per-finding with a rationale that names the "
        "specific SHA and the audit you did against the upstream "
        "release notes.",
    ),
    incident_refs=(
        "GitHub Security Lab + Boost Security \"unsigned-tag\" "
        "research (2024-2025) documenting the re-pointed-branch "
        "shape, several supply-chain compromises landed by "
        "advancing a ``main`` branch under a SHA that consumers "
        "had pinned to. The SHA pin's audit value evaporates the "
        "moment the maintainer's next push moves the tip and a "
        "consumer team's automation reaches for \"latest.\"",
    ),
    exploit_example=(
        "# Vulnerable: the pinned SHA is the current ``main`` tip.\n"
        "# The maintainer's next push moves ``main`` forward; the\n"
        "# pin stays on the old commit but a Dependabot ``main``-\n"
        "# tracker bumps consumers to the new tip on the next run.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: vendor/action@<branch-tip-sha>\n"
        "      - run: ./build.sh\n"
        "\n"
        "# Safe: pinned SHA is a tagged release commit.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: vendor/action@<tagged-release-sha>   # v4.1.7\n"
        "      - run: ./build.sh"
    ),
)


def _iter_sha_uses(
    doc: dict[str, Any],
) -> Iterator[tuple[str, str, str, str]]:
    """Yield ``(label, owner, repo, sha)`` for every ``uses:`` whose
    ref is a 40-char hex SHA."""
    for job_id, job in iter_jobs(doc):
        job_uses = job.get("uses")
        ref = parse_uses(job_uses)
        if ref and ref.kind in {"remote-action", "remote-workflow"} and _SHA_RE.match(ref.ref):
            yield job_id, ref.owner, ref.repo, ref.ref
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses")
            ref = parse_uses(uses)
            if ref and ref.kind in {"remote-action", "remote-workflow"} and _SHA_RE.match(ref.ref):
                yield f"{job_id}[{idx}]", ref.owner, ref.repo, ref.ref


def check(
    path: str, doc: dict[str, Any], wf: Workflow, ctx: GitHubContext,
) -> Finding:
    sha_uses = list(_iter_sha_uses(doc))
    total_unique = len({
        (owner.lower(), repo.lower(), sha.lower())
        for _, owner, repo, sha in sha_uses
    })
    stale_refs: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    probed = 0
    for label, owner, repo, sha in sha_uses:
        key = (owner.lower(), repo.lower(), sha.lower())
        if key in seen:
            continue
        seen.add(key)
        meta = ctx.action_metadata.get(f"{owner.lower()}/{repo.lower()}")
        if meta is None or meta.branch_head_shas is None:
            continue
        probed += 1
        if sha.lower() in meta.branch_head_shas:
            stale_refs.append(f"{label}: {owner}/{repo}@{sha[:12]}…")
    if total_unique > 0 and (not ctx.action_metadata or probed == 0):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No branch-head data available. Rerun with "
                "``--resolve-remote`` (and optionally ``--gh-token`` "
                "for the higher rate-limit ceiling) to enable "
                "stale-action-refs detection on SHA-pinned action "
                "refs."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    passed = not stale_refs
    if passed:
        if probed < total_unique:
            # Partial coverage: name the gap so the pass description
            # doesn't claim more audit than was actually performed.
            desc = (
                f"No stale SHA refs in probed actions "
                f"({probed}/{total_unique} unique SHA refs checked); "
                f"the remainder lacked branch-head metadata."
            )
        else:
            desc = (
                "Every SHA-pinned action reference lives below an "
                "upstream branch tip rather than at one."
            )
    else:
        sample = "; ".join(stale_refs[:3])
        if len(stale_refs) > 3:
            sample += f" (+{len(stale_refs) - 3} more)"
        desc = (
            f"{len(stale_refs)} SHA-pinned action reference(s) "
            f"match the current tip of an upstream branch: {sample}. "
            f"Branch HEADs are mutable, the SHA pin's immutability "
            f"value evaporates the moment the maintainer pushes."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
