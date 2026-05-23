"""GHA-095. Action SHA pin does not match its ``# vX.Y.Z`` comment.

Mirrors zizmor's ``ref-version-mismatch`` audit. A SHA pin commented
as ``# v4.1.1`` should resolve to the ``v4.1.1`` tag on the upstream
repo. Drift between the SHA and the comment is the canonical impostor-
commit setup, the SHA fetches *something*, the comment lies about
what. A reviewer skimming the diff anchors on the comment and trusts
the SHA without re-querying the network.

How drift happens in the wild, in rough order of frequency:

* Pin-maintenance tools (Dependabot, Renovate) updated the comment
  but not the SHA, or vice versa, on a manual conflict resolution.
* A maintainer copy-pasted a SHA from one tag into a comment naming
  a different tag.
* An attacker who controlled the PR substituted a fork SHA into the
  ``@`` slot while leaving the original ``# v4.1.1`` comment intact,
  betting that the reviewer reads the comment, not the SHA.

Network-dependent: needs ``--resolve-remote`` to populate
``ctx.action_metadata[*].tag_shas`` (one ``/commits/{tag}`` call per
distinct comment-mentioned tag, deduped across the workflow set).
Without the flag the rule passes silently with a one-line nudge.

Pairs with GHA-040 (compromised SHA / tag), GHA-090 (impostor-commit,
SHA absent from the head repo's reachability set), and GHA-001
(unpinned ``uses:``). HIGH severity, the drift carries the same
exec-on-runner authority as any other supply-chain compromise.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from .._version_comments import (
    iter_version_comment_refs,
    tag_alternates,
)
from ..base import GitHubContext, Workflow

RULE = Rule(
    id="GHA-095",
    title="Action SHA pin does not match its version comment",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357", "CWE-829", "CWE-345"),
    recommendation=(
        "Re-resolve the comment-named tag against the upstream repo "
        "and update either the SHA pin or the comment so they agree. "
        "``gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`` "
        "returns the canonical SHA the comment claims; substitute it "
        "into the ``@`` slot, or fix the comment to name the tag the "
        "SHA actually belongs to. Pin-maintenance tools (Dependabot, "
        "Renovate) write both halves atomically; drift between them "
        "is either tool misconfiguration or an attacker hoping "
        "reviewers skim the human-readable side rather than the "
        "machine-readable one."
    ),
    docs_note=(
        "Walks each workflow's raw text (``Workflow.raw_text``, "
        "populated by ``GitHubContext.from_path``) for lines of the "
        "shape ``uses: owner/repo@<40-hex-sha>  # <comment>`` and "
        "extracts a version-shaped token (``v4``, ``v4.1.1``, "
        "``1.0-beta``) from the comment body. Looks the token up in "
        "``ctx.action_metadata[owner/repo].tag_shas`` (populated by "
        "``--resolve-remote``; one ``/commits/{tag}`` call per "
        "distinct comment-mentioned tag). Fires when the resolved "
        "tag SHA differs from the pin. Tags that don't resolve "
        "(404, deleted tag, internal alias the comment names that "
        "the upstream repo never published) pass silently — the "
        "rule treats unverifiable comments as benign rather than "
        "guessing. ``v``-prefix variants (``v4`` vs ``4``) are tried "
        "both ways so a comment convention swap doesn't false-fire."
    ),
    known_fp=(
        "A comment that pins to a synthetic tag (``# internal-"
        "release-2024-Q4``) the upstream repo doesn't carry resolves "
        "to nothing and passes silently, no FP. Genuine false "
        "positives appear when the upstream maintainer re-points an "
        "existing tag (a force-push to the tag ref) to a different "
        "SHA after the consumer pinned, the consumer's pin is now "
        "correct and the comment is stale relative to the moved "
        "tag. Update the comment (or repin) once the audit "
        "establishes the tag-move was legitimate. Suppress per-"
        "finding only after that audit.",
    ),
    incident_refs=(
        "zizmor ``ref-version-mismatch`` audit "
        "(https://docs.zizmor.sh/audits/#ref-version-mismatch). "
        "Synacktiv / Octoscan supply-chain write-ups consistently "
        "highlight comment-vs-SHA drift as the cheapest cross-check "
        "to add once SHA pinning becomes table stakes — the SHA "
        "passes review eyes because reviewers anchor on the human-"
        "readable annotation.",
    ),
    exploit_example=(
        "# Vulnerable: the SHA below does not resolve to ``v4.1.1``\n"
        "# on actions/checkout. The comment lies about what the\n"
        "# runner will actually fetch; a reviewer who trusts the\n"
        "# comment never queries the SHA against the tag history.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha-that-is-not-v4.1.1>  # v4.1.1\n"
        "      - run: ./build.sh\n"
        "\n"
        "# Safe: SHA and comment agree, the runner fetches the\n"
        "# commit the comment names.\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<canonical-sha-of-v4.1.1>  # v4.1.1\n"
        "      - run: ./build.sh"
    ),
)


def _format_site(owner: str, repo: str, sha: str, tag: str, line: int) -> str:
    return f"line {line}: {owner}/{repo}@{sha[:12]}… (comment: {tag})"


def check(
    path: str, doc: dict[str, Any], wf: Workflow, ctx: GitHubContext,
) -> Finding:
    # Resolver-synthesized workflows (composite-action bodies, remote
    # callees) don't have on-disk raw text, so the comment shape is
    # unobservable. Pass silently; the source repo's own scan covers
    # those lines through its own ``raw_text`` path.
    if wf.raw_text is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Workflow has no raw text available (synthesized "
                "composite-action or resolver callee); GHA-095 only "
                "operates on the on-disk pre-parse layer."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    mismatches: list[str] = []
    any_probed = False
    seen: set[tuple[str, str, str]] = set()
    for site in iter_version_comment_refs(wf.raw_text):
        key = (site.owner.lower(), site.repo.lower(), site.sha.lower())
        if key in seen:
            continue
        seen.add(key)
        meta = ctx.action_metadata.get(f"{site.owner.lower()}/{site.repo.lower()}")
        if meta is None or meta.tag_shas is None:
            continue
        resolved: str | None = None
        for candidate in tag_alternates(site.comment_tag):
            candidate_sha = meta.tag_shas.get(candidate)
            if candidate_sha is not None:
                resolved = candidate_sha
                break
        if resolved is None:
            # Comment-tag didn't resolve. Could be a deleted tag, an
            # internal alias the upstream repo never published, or a
            # transient API failure. Treat as unverifiable rather
            # than firing — the conservative choice keeps the false-
            # positive rate where the rest of the GHA-09x pack sits.
            continue
        any_probed = True
        if resolved != site.sha.lower():
            mismatches.append(
                _format_site(
                    site.owner, site.repo, site.sha, site.comment_tag,
                    site.line_no,
                ),
            )

    if not ctx.action_metadata or not any_probed:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No tag-resolution data available. Rerun with "
                "``--resolve-remote`` (and optionally ``--gh-token`` "
                "for the higher rate-limit ceiling) to enable "
                "ref-version-mismatch detection on SHA-pinned action "
                "refs carrying a ``# vX.Y.Z`` comment."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    passed = not mismatches
    if passed:
        desc = (
            "Every SHA-pinned action with a version comment resolves "
            "to the commit that comment names."
        )
    else:
        sample = "; ".join(mismatches[:3])
        if len(mismatches) > 3:
            sample += f" (+{len(mismatches) - 3} more)"
        desc = (
            f"{len(mismatches)} SHA-pinned action reference(s) carry "
            f"a version comment that names a different commit than "
            f"the pin: {sample}. Drift between the SHA and the "
            f"comment is the canonical impostor-commit setup — the "
            f"reviewer trusts the comment, the runner fetches the "
            f"SHA."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
