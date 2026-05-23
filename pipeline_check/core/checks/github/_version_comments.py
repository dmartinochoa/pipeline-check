"""Parse ``uses: owner/repo@<sha>  # vX.Y.Z`` shape from raw workflow text.

PyYAML drops standalone comments during parsing, so the version
annotation that downstream pin-maintenance tools (Dependabot,
Renovate, ``stay-pinned``, hand-edits) leave next to a SHA pin is
gone by the time the rule pack sees the parsed document. This module
walks the raw file text line-by-line and extracts every
``(owner, repo, sha, comment_tag)`` quad it can find.

GHA-095 consumes this to decide whether the SHA pin and the comment
tag actually agree. The same shape feeds
:func:`collect_referenced_action_version_comments`, which the
``--resolve-remote`` populate pass uses to seed
:meth:`~pipeline_check.core.checks.github._action_reputation.ActionMetadataFetcher.fetch_tag_shas`
with the tag names worth resolving.

Single-line scope: we don't try to reconstruct ``uses:`` whose value
sits on a folded / block-scalar continuation line. Workflows that
write ``uses:`` across multiple lines are vanishingly rare in
practice (no major linter / template emits that shape), and the
single-line shape is what every pin-maintenance tool produces.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import GitHubContext, Workflow

#: Matches a single-line ``uses:`` entry whose ref is a 40-char hex
#: SHA followed by an inline comment. Captures owner, repo, sha, and
#: the post-``#`` comment body. The pattern is deliberately
#: permissive on quoting (single, double, or none) and tolerant of
#: trailing whitespace before the ``#``.
_USES_WITH_COMMENT_RE = re.compile(
    r"""
    ^
    \s*-?\s*                            # optional list dash + spaces
    uses\s*:\s*                         # uses: key
    ['"]?                               # optional opening quote
    ([A-Za-z0-9][A-Za-z0-9_.-]*)        # owner
    /
    ([A-Za-z0-9][A-Za-z0-9_.-]*)        # repo
    (?:/[^@'\"]*)?                      # optional subpath (.github/workflows/...)
    @
    ([0-9a-fA-F]{40})                   # SHA pin
    ['"]?                               # optional closing quote
    [ \t]*                              # gap before comment
    \#\s*                               # comment marker
    (.+?)                               # comment body
    \s*$
    """,
    re.VERBOSE,
)

#: Matches a version-shaped token anywhere in the comment body.
#: Accepts ``v4``, ``v4.1``, ``v4.1.1``, ``4.1.1``, ``v1.0-beta``,
#: ``1.0.0+sha.deadbeef``. Anchored on a word boundary so
#: ``branch-v4-fix`` doesn't yield ``v4``.
_VERSION_TOKEN_RE = re.compile(
    r"""
    (?<![A-Za-z0-9.])                   # not preceded by alphanum/dot
    (
        v?\d+                           # leading digit, optional v
        (?:\.\d+){0,2}                  # optional minor, patch
        (?:[-+][A-Za-z0-9.-]+)?         # optional pre-release / build
    )
    (?![A-Za-z0-9])                     # not followed by alphanum
    """,
    re.VERBOSE,
)


@dataclass(frozen=True, slots=True)
class VersionCommentRef:
    """One ``uses: o/r@<sha>  # <tag>`` site located in raw text.

    ``line_no`` is 1-indexed. ``owner`` and ``repo`` are returned
    case-preserving (consumers lower-case for keying), since the SHA
    pin is also case-preserving and the rule reports the
    site verbatim.
    """

    line_no: int
    owner: str
    repo: str
    sha: str
    comment_tag: str


def _extract_version_token(comment: str) -> str | None:
    """Pull the first version-shaped token out of *comment*.

    Returns the token verbatim (``v4.1.1``, ``1.0-beta``) or ``None``
    when the comment carries no recognizable version. Conservative on
    purpose: a comment that doesn't fit the version shape stays out
    of the lookup table rather than producing speculative API calls.
    """
    m = _VERSION_TOKEN_RE.search(comment)
    if m is None:
        return None
    return m.group(1)


def iter_version_comment_refs(
    raw_text: str,
) -> Iterator[VersionCommentRef]:
    """Yield one :class:`VersionCommentRef` per matching line.

    Lines without a ``uses:`` + SHA + comment shape, or whose comment
    body doesn't carry a version-shaped token, are skipped. Duplicate
    detection (same owner/repo/sha) is left to callers — the rule
    deduplicates for reporting, while the fetcher aggregates into a
    set naturally.
    """
    if not raw_text:
        return
    for idx, line in enumerate(raw_text.splitlines(), start=1):
        m = _USES_WITH_COMMENT_RE.match(line)
        if m is None:
            continue
        owner, repo, sha, comment = m.group(1), m.group(2), m.group(3), m.group(4)
        tag = _extract_version_token(comment)
        if tag is None:
            continue
        yield VersionCommentRef(
            line_no=idx,
            owner=owner,
            repo=repo,
            sha=sha,
            comment_tag=tag,
        )


def collect_referenced_action_version_comments(
    ctx: GitHubContext,
) -> dict[tuple[str, str], set[str]]:
    """Walk every workflow's raw text, return ``{(owner, repo): {tag, ...}}``.

    Keyed lower-case to match
    :func:`~pipeline_check.core.checks.github._action_reputation.collect_referenced_actions`.
    Workflows whose ``raw_text`` is ``None`` (resolver-synthesized
    composite-action bodies, remote callees) contribute nothing — the
    rule equally skips them, so the tag set never carries entries the
    consuming side can't verify.

    Returns ``{}`` when no workflow surfaces any comment-tagged SHA
    pin; the populate pass then skips the per-tag fetch entirely
    rather than producing API calls with empty input sets.
    """
    out: dict[tuple[str, str], set[str]] = {}
    for wf in ctx.workflows:
        text = wf.raw_text
        if text is None:
            continue
        for ref in iter_version_comment_refs(text):
            key = (ref.owner.lower(), ref.repo.lower())
            out.setdefault(key, set()).add(ref.comment_tag)
    return out


def tag_alternates(tag: str) -> Iterable[str]:
    """Yield the tag plus its ``v``-prefix swap variant.

    Comments commonly drop the ``v`` (``# 4.1.1``) even when the
    upstream tag is ``v4.1.1``, and vice versa. The lookup tries
    both forms before declaring the tag unresolvable so the rule
    doesn't false-pass on a benign comment convention. The original
    tag yields first; the variant only fires when the primary lookup
    returned nothing.
    """
    yield tag
    if tag.startswith(("v", "V")) and len(tag) > 1 and tag[1].isdigit():
        yield tag[1:]
    elif tag[:1].isdigit():
        yield f"v{tag}"
