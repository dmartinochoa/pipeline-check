"""GHA-043. Low-star action runs in a job that grants sensitive permissions.

A low-popularity action whose body the caller never reviewed
becomes a much larger problem when the calling job grants it
``contents: write`` / ``packages: write`` / ``id-token: write`` /
``actions: write``. The combination is the canonical compromised-
action vector: the attacker's payload runs with enough scope to
push code, publish packages, mint cloud OIDC tokens, or rewrite
workflow runs. Low star count is a heuristic for "no community
review has happened" — popular actions get pinned, audited, and
vendored over time.

Network-dependent: needs ``--resolve-remote`` for the star count.
Without the opt-in flag the rule passes silently.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    GitHubContext,
    Workflow,
    effective_permissions,
    iter_jobs,
    iter_steps,
)
from ..uses_parser import parse_uses

#: Star threshold under which we consider an action low-popularity.
#: Picked at 25 to keep the rule from firing on actions with even
#: minimal community uptake; supply-chain reviews and write-ups
#: typically focus on actions below this floor.
MAX_STARS = 25

#: Permission scopes that turn a benign action body into a
#: blast-radius primitive. Values are matched against the per-job
#: ``permissions.<scope>`` setting; ``write`` is the trigger value
#: across GitHub Actions' scope-keyed permissions.
_SENSITIVE_SCOPES: tuple[str, ...] = (
    "contents",
    "packages",
    "id-token",
    "actions",
    "deployments",
)


RULE = Rule(
    id="GHA-043",
    title="Low-star action runs with sensitive permissions",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-5"),
    esf=("ESF-S-VERIFY-DEPS", "ESF-C-LEAST-PRIV"),
    cwe=("CWE-829", "CWE-250"),
    recommendation=(
        "Either narrow the calling job's ``permissions:`` to the "
        "minimum the action actually needs (drop ``contents: "
        "write`` / ``id-token: write`` / ``packages: write`` / "
        "``actions: write`` / ``deployments: write`` unless the "
        "action's documented surface requires them), or replace "
        "the action with a community-reviewed alternative. The "
        "rule fires the COMBINATION of low community review and "
        "elevated permissions; either side alone is fine."
    ),
    docs_note=(
        "Reads ``stargazers_count`` from "
        "``ctx.action_metadata[owner/repo]`` and the effective "
        "``permissions:`` block (job-level wins; falls back to "
        "workflow-top-level; falls back to the caller's "
        "inherited block for resolved reusable workflows). Fires "
        f"when stars < ``MAX_STARS`` ({MAX_STARS}) AND any of "
        f"{', '.join(repr(s) for s in _SENSITIVE_SCOPES)} is set "
        "to ``write`` on the calling job. ``permissions: "
        "write-all`` is treated as all scopes set to write."
    ),
    known_fp=(
        "Internal first-party actions hosted in a private org repo "
        "legitimately have low public star counts; their threat "
        "model is different and the rule does not distinguish "
        "internal from third-party. Suppress via ignore-file when "
        "the action is in-org and trusted.",
    ),
    incident_refs=(
        "GitGuardian 2023 supply-chain audit: a handful of "
        "low-popularity actions with ``contents: write`` were "
        "weaponized via single-PR maintainer-impersonation "
        "compromises; the elevated permission was the privilege "
        "amplifier that let the attacker push code back to the "
        "victim's default branch on the same workflow run.",
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
                "to enable low-star + sensitive-permission detection."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    inherited = wf.inherited_permissions if wf is not None else None
    top_perms = doc.get("permissions")
    matches: list[str] = []
    seen: set[tuple[str, str]] = set()
    for job_id, job in iter_jobs(doc):
        job_perms = job.get("permissions")
        effective = job_perms if job_perms is not None else (
            top_perms if top_perms is not None else inherited
        )
        sensitive = _sensitive_scopes_granted(effective)
        if not sensitive:
            # No elevated permission on this job; the rule doesn't
            # fire even on a low-star action because the
            # blast-radius leg of the heuristic is absent.
            continue
        for step in iter_steps(job):
            ref = parse_uses(step.get("uses"))
            if ref is None:
                continue
            if ref.kind not in {"remote-action", "remote-workflow"}:
                continue
            if not ref.owner or not ref.repo:
                continue
            key = (ref.owner.lower(), ref.repo.lower())
            seen_key = (job_id, f"{key[0]}/{key[1]}")
            if seen_key in seen:
                continue
            seen.add(seen_key)
            meta = ctx.action_metadata.get(f"{key[0]}/{key[1]}")
            if meta is None:
                continue
            if meta.stargazers_count is None:
                continue
            if meta.stargazers_count >= MAX_STARS:
                continue
            matches.append(
                f"{ref.owner}/{ref.repo} "
                f"({meta.stargazers_count} stars) in job "
                f"``{job_id}`` with {'+'.join(sorted(sensitive))} "
                f"write"
            )
    passed = not matches
    if passed:
        desc = (
            "No low-star action runs in a job that grants "
            f"sensitive permissions ({', '.join(_SENSITIVE_SCOPES)})."
        )
    else:
        sample = "; ".join(matches[:3])
        if len(matches) > 3:
            sample += f"; (+{len(matches) - 3} more)"
        desc = (
            f"{len(matches)} low-popularity action(s) run with "
            f"sensitive permissions: {sample}. Either pin to a "
            f"reviewed fork or narrow the calling job's "
            f"``permissions:`` to drop the write scope the action "
            f"doesn't actually need."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )


def _sensitive_scopes_granted(perms: Any) -> set[str]:
    """Return the subset of ``_SENSITIVE_SCOPES`` granted ``write``
    access by *perms*.

    Handles every shape the GHA permissions block can take:

      * ``"write-all"`` → every sensitive scope.
      * ``"read-all"`` / ``None`` → empty.
      * ``{"contents": "write", "packages": "read"}`` → the writes
        that intersect ``_SENSITIVE_SCOPES``.
    """
    if isinstance(perms, str):
        if perms.strip().lower() == "write-all":
            return set(_SENSITIVE_SCOPES)
        return set()
    if isinstance(perms, dict):
        out: set[str] = set()
        for scope in _SENSITIVE_SCOPES:
            value = perms.get(scope)
            if isinstance(value, str) and value.strip().lower() == "write":
                out.add(scope)
        return out
    return set()
