"""GHA-011, cache key must not derive from attacker-controllable input."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.anchors import ecr_repo
from ...base import Finding, ResourceAnchor, Severity, walk_strings
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import CACHE_TAINT_RE

# ECR registry URI shape — used to extract push targets from the
# workflow for AC-017's cross-provider reachability. The canonicalizer
# in :mod:`_primitives.anchors` validates the full shape; this regex
# only narrows the candidate set down from "every string in the file"
# to "things that look ECR-like."
_ECR_URI_CANDIDATE_RE = re.compile(
    r"\b\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9._/-]+"
)

RULE = Rule(
    id="GHA-011",
    title="Cache key derives from attacker-controllable input",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-345",),
    recommendation=(
        "Build the cache key from values the attacker can't control: "
        "`${{ runner.os }}`, `${{ hashFiles('**/*.lock') }}` (only "
        "when the lockfile is enforced by branch protection), and "
        "the workflow file path. Never include `github.event.*` "
        "PR/issue fields, `github.head_ref`, or `inputs.*` in the "
        "key namespace."
    ),
    docs_note=(
        "`actions/cache` restores by key (and falls through "
        "`restore-keys` on miss). When the key includes a value the "
        "attacker controls (PR title, head ref, workflow_dispatch "
        "input), an attacker can plant a poisoned cache entry that a "
        "later default-branch run restores and treats as a clean "
        "build cache."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    # Preserve insertion order; one job with multiple offending cache
    # keys contributes once. AC-006 intersects this with GHA-002 to
    # confirm a poisoning path runs in the same job as the PR-head
    # code that supplies the malicious cache content.
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses") or ""
            if not isinstance(uses, str) or "actions/cache@" not in uses:
                continue
            with_block = step.get("with") or {}
            if not isinstance(with_block, dict):
                continue
            for key_name in ("key", "restore-keys"):
                raw = with_block.get(key_name)
                if raw is None:
                    continue
                text = raw if isinstance(raw, str) else "\n".join(str(v) for v in raw)
                if CACHE_TAINT_RE.search(text):
                    offenders.append(f"{job_id}[{idx}].{key_name}")
                    anchor_jobs[job_id] = None
    passed = not offenders
    desc = (
        "No actions/cache key derives from attacker-controllable input."
        if passed else
        f"actions/cache key/restore-keys derive from attacker-"
        f"controllable values in: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A PR can seed a "
        f"poisoned cache entry that a later default-branch run "
        f"restores and treats as a clean build cache."
    )
    # ResourceAnchor phase 1: extract any ECR registry URI mentioned
    # in the workflow (a ``docker push``, a ``docker/build-push-action``
    # ``tags:`` input, an ``aws ecr`` step) so AC-017 can intersect
    # cache-poisonable workflows with mutable-tag ECR repos by URI
    # rather than the prior whole-scan co-occurrence. We only collect
    # anchors when the rule actually fires — a passed workflow has
    # nothing to chain. Order-preserving dict de-dupes multiple
    # references to the same repo URI within the file.
    ecr_anchors: dict[str, ResourceAnchor] = {}
    if not passed:
        for s in walk_strings(doc):
            for m in _ECR_URI_CANDIDATE_RE.finditer(s):
                built = ecr_repo(m.group(0))
                if built is not None:
                    ecr_anchors[built.identity] = built
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        job_anchors=tuple(anchor_jobs),
        resource_anchors=tuple(ecr_anchors.values()),
    )
