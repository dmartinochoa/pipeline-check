"""GHA-052. ``actions/cache`` key derived from untrusted PR input."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-052",
    title="actions/cache key includes untrusted PR-controllable input",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-4"),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-345", "CWE-353"),
    recommendation=(
        "Build the cache key from values an attacker cannot "
        "control. ``hashFiles('**/package-lock.json')`` and "
        "the like are safe — the hash changes only when the "
        "tracked files change, which is itself the trust signal. "
        "Avoid ``github.head_ref``, ``github.event.pull_"
        "request.*``, ``github.event.issue.*``, and any "
        "``inputs.*`` whose value can be set by a "
        "``workflow_dispatch`` from an untrusted actor.\n\n"
        "The attack is cache poisoning: an attacker opens a PR "
        "whose branch name (``head_ref``) is crafted so that "
        "``actions/cache`` stores a malicious payload under a "
        "key that a subsequent privileged run (e.g., on "
        "``main``) consumes. The next run hits the poisoned "
        "cache, executes the attacker's code under the trusted "
        "workflow's permissions, and the original PR never has "
        "to be merged. Pin keys to ``hashFiles`` of "
        "lockfiles or branch-restricted ``github.ref_name`` "
        "(post-checkout, only commits already in the trusted "
        "branch generate that ref name)."
    ),
    docs_note=(
        "Walks every step using ``actions/cache@*`` (or the "
        "``cache-save`` / ``cache-restore`` variants) and "
        "checks ``with.key:`` (plus ``with.restore-keys:``) "
        "for references to attacker-controllable expression "
        "contexts: ``github.head_ref``, ``github.event.pull_"
        "request.*``, ``github.event.issue.*``, ``github.event."
        "comment.*``, and the actor / sender fields when used "
        "in a key.\n\n"
        "Pairs with GHA-027 (``pull_request_target`` on "
        "untrusted input) and GHA-046 (manual PR-head fetches "
        "on untrusted triggers): the same set of expression "
        "contexts that flow into a shell are also the contexts "
        "that flow into cache key construction. References to "
        "``github.ref`` / ``github.ref_name`` / ``runner.os`` / "
        "``hashFiles(...)`` are safe and pass."
    ),
    known_fp=(
        "Some workflows legitimately scope cache keys per "
        "feature branch by including ``github.head_ref`` in a "
        "``pull_request`` workflow where the cache is segmented "
        "by ref (so cross-branch poisoning is impossible). The "
        "right pattern is to prefix the key with a non-"
        "attacker-controllable namespace AND rely on "
        "``restore-keys`` only for read-fallback. Suppress on "
        "the specific step with a rationale that documents the "
        "namespacing.",
    ),
)


_CACHE_USES_RE = re.compile(
    r"^actions/(?:cache|cache-save|cache-restore)(/|@|$)", re.IGNORECASE
)
# Expression contexts an attacker can craft via a pull-request.
_UNTRUSTED_CONTEXTS: tuple[str, ...] = (
    "github.head_ref",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.sha",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.number",
    "github.event.pull_request.user.login",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.issue.user.login",
    "github.event.comment.body",
    "github.event.comment.user.login",
    "github.event.review.body",
    "github.event.review_comment.body",
)


def _uses_cache(uses: Any) -> bool:
    if not isinstance(uses, str):
        return False
    return bool(_CACHE_USES_RE.match(uses.strip()))


def _matches_untrusted(value: Any) -> list[str]:
    """Return the list of untrusted-context tokens in *value*."""
    if not isinstance(value, str):
        return []
    hits: list[str] = []
    for token in _UNTRUSTED_CONTEXTS:
        if token in value:
            hits.append(token)
    return hits


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            if not _uses_cache(step.get("uses")):
                continue
            with_block = step.get("with")
            if not isinstance(with_block, dict):
                continue
            step_label = step.get("name") or step.get("id") or f"steps[{idx}]"
            for field in ("key", "restore-keys"):
                value = with_block.get(field)
                if isinstance(value, list):
                    # restore-keys is a list of fallback prefixes.
                    for sub in value:
                        hits = _matches_untrusted(sub)
                        if hits:
                            offenders.append(
                                f"{job_id}.{step_label}.{field}: "
                                f"{', '.join(hits[:2])}"
                            )
                else:
                    hits = _matches_untrusted(value)
                    if hits:
                        offenders.append(
                            f"{job_id}.{step_label}.{field}: "
                            f"{', '.join(hits[:2])}"
                        )
    passed = not offenders
    desc = (
        "No ``actions/cache@*`` step keys cache by an "
        "attacker-controllable context."
        if passed else
        f"{len(offenders)} cache key(s) include untrusted PR-"
        f"controllable input: {', '.join(offenders[:3])}"
        f"{'…' if len(offenders) > 3 else ''}. An attacker "
        f"opens a PR with a crafted ref / title / body, "
        f"poisons the cache, and the next trusted-branch run "
        f"executes their payload."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
