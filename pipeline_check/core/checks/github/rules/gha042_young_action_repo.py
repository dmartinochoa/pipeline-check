"""GHA-042. Workflow uses an action whose upstream repo is newly created.

Typosquats and supply-chain-impersonation actions look like the real
thing in the workflow YAML but were created days or weeks ago by an
unrelated identity. A young repo paired with a recognized-name
prefix (``actoins/checkout``, ``acitons/setup-node``) is the entry
point for a single-PR attack that fans out the moment a victim CI
run hits the malicious action.

Network-dependent: needs ``--resolve-remote`` to populate
``ctx.action_metadata``. The rule reads the ``created_at`` timestamp
from the GitHub repo metadata and fires when the repo is younger
than ``MIN_AGE_DAYS``. Default threshold is 90 days; configurable
via the per-rule overrides config block once a user reports a
legitimate FP.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitHubContext, Workflow, iter_jobs, iter_steps
from ..uses_parser import parse_uses

#: Repos younger than this fire the rule. Picked to span the typical
#: typosquat-detection window (the squat usually surfaces within a
#: few weeks; 90 days gives the upstream community time to flag and
#: report) without spamming on every just-released new action by a
#: trusted maintainer.
MIN_AGE_DAYS = 90


RULE = Rule(
    id="GHA-042",
    title="Action upstream repo is newly created",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-1357",),
    recommendation=(
        "Verify the action repo is the real upstream and not a "
        "typosquat. Compare the spelling and owner against the "
        "intended action (``actions/checkout`` vs "
        "``actoins/checkout``); check the repo description, stars, "
        "and prior releases. If the action is genuinely new but "
        "trusted, suppress via ignore-file with a dated note; the "
        "suppression decays naturally as the repo ages past the "
        f"{MIN_AGE_DAYS}-day threshold."
    ),
    docs_note=(
        "Reads ``created_at`` from "
        "``ctx.action_metadata[owner/repo]`` (populated by the "
        "``--resolve-remote`` path). Fires when the repo's age in "
        f"days is below ``MIN_AGE_DAYS`` ({MIN_AGE_DAYS}). Without "
        "the opt-in flag the rule passes silently with a nudge."
    ),
    known_fp=(
        "Newly-released first-party actions from a trusted org "
        "(say, a freshly-launched ``actions/foo`` rolled out by "
        "GitHub itself) fire while they're still young. Suppress "
        "via ignore-file with a dated note; the entry expires "
        "naturally once the repo crosses the age threshold.",
    ),
    incident_refs=(
        "GitGuardian / StepSecurity typosquat reports (2023-2024) "
        "document several action-naming impersonations that "
        "appeared as newly-registered repos and reached production "
        "CI before the legitimate owner was notified.",
    ),
)


def check(
    path: str, doc: dict[str, Any], wf: Workflow, ctx: GitHubContext,
) -> Finding:
    matches: list[tuple[str, int]] = []
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
                "``--resolve-remote`` (and optionally ``--gh-token``) "
                "to enable young-action-repo detection."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    passed = not matches
    if passed:
        desc = (
            "Every action referenced by this workflow has an "
            f"upstream repo older than {MIN_AGE_DAYS} days."
        )
    else:
        sample = ", ".join(
            f"{name} ({age} day(s) old)" for name, age in matches[:3]
        )
        if len(matches) > 3:
            sample += f" (+{len(matches) - 3} more)"
        desc = (
            f"{len(matches)} action(s) reference an upstream repo "
            f"younger than {MIN_AGE_DAYS} days: {sample}. Verify the "
            f"repo is the legitimate upstream and not a typosquat / "
            f"impersonation registered to receive a single victim "
            f"CI run."
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
    matches: list[tuple[str, int]],
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
    if meta.created_at is None:
        return
    age_days = _age_days(meta.created_at)
    if age_days is None:
        return
    if age_days < MIN_AGE_DAYS:
        matches.append((f"{ref.owner}/{ref.repo}", age_days))


def _age_days(iso8601: str) -> int | None:
    """Return the integer number of days between ``iso8601`` (the
    repo's ``created_at``) and the current UTC time. Returns ``None``
    when the timestamp can't be parsed so the caller treats it as
    "unknown" rather than firing.

    GitHub serializes ``created_at`` in RFC 3339 form
    (``2024-12-01T08:42:11Z``). Older fixtures and a few API quirks
    use a ``+00:00`` offset; ``datetime.fromisoformat`` since Python
    3.11 handles both. The trailing ``Z`` is normalized to ``+00:00``
    explicitly for safety against pre-3.11 fromisoformat behavior.
    """
    text = iso8601.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        created = datetime.fromisoformat(text)
    except ValueError:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    delta = datetime.now(tz=UTC) - created
    return delta.days
