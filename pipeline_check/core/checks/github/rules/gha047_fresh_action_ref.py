"""GHA-047. Workflow pins an action to a tag/SHA committed recently.

A maintainer takeover (compromised npm/PyPI/GitHub account, hostile
fork-and-push, accidental publish of secrets) typically surfaces in
the action's commit log within 24-72 hours. The cooldown pattern
borrowed from Renovate's ``minimumReleaseAge`` and npm's stability
quarantine turns that detection window into a defense: wait N days
after a release before consuming it. By then the maintainer
community, scanning tools, or the affected user base has had a chance
to yank or revoke a poisoned tag.

Distinct from GHA-042: GHA-042 fires when the *upstream repo* itself
is young (typosquat / impersonation signal). GHA-047 fires when the
*referenced tag or commit* is fresh on an otherwise mature repo
(compromised-release signal). A five-year-old repo with a malicious
tag pushed yesterday passes GHA-042 and fails GHA-047.

Trusted publishers
------------------

A `v4` floating major maintained by ``actions/`` (or ``aws-actions``,
``azure``, etc.) gets re-tagged whenever the owning org cuts a new
release; firing on every legitimate retag would drown the rule. The
default :data:`_TRUSTED_PUBLISHERS` allowlist skips first-party
publishers whose threat model is different (their compromise shows up
via GHA-040 / GHA-041 / GHA-043 instead). Pin to a 40-char SHA if you
want freshness gating on a trusted publisher; SHA pins are
deterministic and don't move.

Network-dependent: needs ``--resolve-remote`` to populate
``ctx.action_metadata`` with per-ref commit dates. Without the opt-in
flag the rule passes silently with a nudge.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitHubContext, Workflow, iter_jobs, iter_steps
from ..uses_parser import parse_uses

#: Referenced refs whose commit date is younger than this fire the
#: rule. Picked at 7 days to match the typical industry takedown
#: window for a poisoned release: long enough for community signal to
#: appear, short enough not to gate ops on routine release cadence.
MIN_REF_AGE_DAYS = 7

#: Owners whose published refs are exempt from the cooldown gate by
#: default. The threat model for first-party / well-known publishers
#: is different — a legitimate retag of ``actions/checkout@v4`` is a
#: routine event and firing on it would drown the rule. A compromise
#: of one of these orgs is detected via the other GHA-04x reputation
#: signals (single maintainer, low stars, very young repo are
#: structurally absent here) or via the static ``GHA-040`` known-bad
#: registry. Users who want freshness gating on these publishers
#: should pin to a 40-char SHA, which doesn't move under a retag.
_TRUSTED_PUBLISHERS: frozenset[str] = frozenset({
    "actions",
    "github",
    "aws-actions",
    "azure",
    "google-github-actions",
    "docker",
    "hashicorp",
    "microsoft",
})


RULE = Rule(
    id="GHA-047",
    title="Action ref resolves to a recently committed tag or SHA",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Wait until the referenced tag or commit has had time to be "
        "reviewed by the upstream community before pulling it into "
        "CI. The default cooldown is seven days. Either bump the "
        f"pinned ref to an older release, or wait {MIN_REF_AGE_DAYS} "
        "days and re-run. If the action is internal / first-party "
        "and the freshness gate is unwanted, pin to a 40-char commit "
        "SHA — SHA pins don't move under a retag and are the "
        "preferred long-term mitigation."
    ),
    docs_note=(
        "Reads ``ref_committed_at`` from "
        "``ctx.action_metadata[owner/repo]`` (populated by the "
        "``--resolve-remote`` path via ``GET "
        "/repos/{owner}/{repo}/commits/{ref}``). Fires when the "
        "referenced ref's commit date is younger than "
        f"``MIN_REF_AGE_DAYS`` ({MIN_REF_AGE_DAYS}). Trusted "
        "publishers (``actions``, ``aws-actions``, ``azure``, ...) "
        "are skipped by default to avoid firing on legitimate "
        "retags of floating majors; pin to a SHA to opt those back "
        "in. Without ``--resolve-remote`` the rule passes silently "
        "with a discovery nudge."
    ),
    known_fp=(
        "A legitimate first-party action that's outside the default "
        "trusted-publisher allowlist (a small vendor org that "
        "publishes a real action; you'd like it included) will fire "
        "after every release for the cooldown window. Either pin to "
        "a SHA (preferred) or suppress via ignore-file with a dated "
        "note; the suppression decays once the ref ages past the "
        "threshold.",
    ),
    incident_refs=(
        "Multiple action-tag compromises (ua-parser-js npm 2021, "
        "tj-actions/changed-files 2025) followed the same shape: a "
        "tag was re-pointed at a malicious commit and consumers "
        "pulling on the next CI run executed the payload. Cooldown "
        "gating turns the community-detection window into a "
        "defense.",
    ),
)


def check(
    path: str, doc: dict[str, Any], wf: Workflow, ctx: GitHubContext,
) -> Finding:
    if not ctx.action_metadata:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No action metadata available. Rerun with "
                "``--resolve-remote`` (and optionally ``--gh-token``) "
                "to enable fresh-ref detection."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    matches: list[tuple[str, int]] = []
    seen: set[tuple[str, str, str]] = set()
    for _, job in iter_jobs(doc):
        _scan_value(job.get("uses"), ctx, seen, matches)
        for step in iter_steps(job):
            _scan_value(step.get("uses"), ctx, seen, matches)
    passed = not matches
    if passed:
        desc = (
            "Every action referenced by this workflow points at a "
            "tag or SHA whose commit date is older than the "
            f"{MIN_REF_AGE_DAYS}-day cooldown window."
        )
    else:
        sample = ", ".join(
            f"{label} ({age} day(s) old)" for label, age in matches[:3]
        )
        if len(matches) > 3:
            sample += f" (+{len(matches) - 3} more)"
        desc = (
            f"{len(matches)} action ref(s) point at a tag or SHA "
            f"committed within the {MIN_REF_AGE_DAYS}-day cooldown "
            f"window: {sample}. A fresh ref on a mature action is "
            f"the canonical compromised-release shape; wait out the "
            f"window or pin to a SHA you've audited."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )


def _scan_value(
    value: Any,
    ctx: GitHubContext,
    seen: set[tuple[str, str, str]],
    matches: list[tuple[str, int]],
) -> None:
    ref = parse_uses(value)
    if ref is None:
        return
    if ref.kind not in {"remote-action", "remote-workflow"}:
        return
    if not ref.owner or not ref.repo or not ref.ref:
        return
    owner_lc = ref.owner.lower()
    if owner_lc in _TRUSTED_PUBLISHERS and not ref.is_pinned_to_sha:
        # Floating-tag refs on trusted publishers re-point under every
        # release; firing on every legitimate retag would drown the
        # rule. A 40-char SHA pin is deterministic and signals the
        # caller is opting back into freshness gating for this ref
        # (matches the top-of-module docstring and the recommendation
        # text), so don't short-circuit when the ref is a SHA.
        return
    key = (owner_lc, ref.repo.lower(), ref.ref)
    if key in seen:
        return
    seen.add(key)
    meta = ctx.action_metadata.get(f"{owner_lc}/{ref.repo.lower()}")
    if meta is None:
        return
    if meta.ref_committed_at is None:
        # No per-ref data fetched for this action. The dataclass's
        # ``None`` slot is distinct from "looked up, came back empty"
        # which is a per-key ``None`` inside the dict — see below.
        return
    iso = meta.ref_committed_at.get(ref.ref)
    if iso is None:
        # Either the ref wasn't looked up (workflow uses something we
        # didn't collect) or the API didn't carry a usable date.
        return
    age_days = _age_days(iso)
    if age_days is None:
        return
    if age_days < MIN_REF_AGE_DAYS:
        matches.append((f"{ref.owner}/{ref.repo}@{ref.ref}", age_days))


def _age_days(iso8601: str) -> int | None:
    """Days between *iso8601* and now, or ``None`` when unparseable.

    GitHub's ``commit.committer.date`` is RFC 3339 with a ``Z`` suffix.
    The same normalization GHA-042 does on ``repo.created_at`` applies
    here — strip ``Z``, accept ``+00:00``, default missing tzinfo to
    UTC.
    """
    text = iso8601.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        committed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if committed.tzinfo is None:
        committed = committed.replace(tzinfo=UTC)
    delta = datetime.now(tz=UTC) - committed
    return delta.days
