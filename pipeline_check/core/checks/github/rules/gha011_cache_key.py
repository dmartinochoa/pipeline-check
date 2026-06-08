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
    exploit_example=(
        "# Vulnerable: the cache key namespace derives from the PR head ref.\n"
        "on: [pull_request]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/cache@v4\n"
        "        with:\n"
        "          path: ~/.cache/build\n"
        "          key: build-${{ github.head_ref }}\n"
        "          restore-keys: |\n"
        "            build-\n"
        "\n"
        "# Attack: open a PR from a branch you name. Your PR run writes\n"
        "# poisoned artifacts under `build-<your-branch>`. Caches are\n"
        "# shared across a repo's branches, so a later push to the\n"
        "# default branch misses its own key and falls through\n"
        "# `restore-keys: build-` to your entry, restoring attacker-\n"
        "# controlled content into the release build before it runs.\n"
        "\n"
        "# Safe: key only on values the attacker can't control.\n"
        "          key: build-${{ runner.os }}-${{ hashFiles('**/*.lock') }}"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    # Preserve insertion order; one job with multiple offending cache
    # keys contributes once. AC-006 intersects this with GHA-002 to
    # confirm a poisoning path runs in the same job as the PR-head
    # code that supplies the malicious cache content.
    anchor_jobs: dict[str, None] = {}
    offending_jobs: dict[str, Any] = {}
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses") or ""
            if not isinstance(uses, str) or not (
                "actions/cache@" in uses
                or "actions/cache/restore@" in uses
                or "actions/cache/save@" in uses
            ):
                continue
            with_block = step.get("with") or {}
            if not isinstance(with_block, dict):
                continue
            for key_name in ("key", "restore-keys"):
                raw = with_block.get(key_name)
                if raw is None:
                    continue
                if isinstance(raw, str):
                    text = raw
                elif isinstance(raw, (list, tuple)):
                    text = "\n".join(str(v) for v in raw)
                else:
                    # Numeric/boolean scalar key (e.g. ``key: 123``):
                    # stringify rather than iterate it.
                    text = str(raw)
                if CACHE_TAINT_RE.search(text):
                    offenders.append(f"{job_id}[{idx}].{key_name}")
                    anchor_jobs[job_id] = None
                    offending_jobs[job_id] = job
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
    # ResourceAnchor phase 1: extract ECR registry URIs that appear
    # WITHIN the offending jobs only (a ``docker push`` /
    # ``docker/build-push-action`` ``tags:`` input / ``aws ecr`` step
    # that shares an execution context with the poisonable cache
    # step). AC-017 can then intersect cache-poisonable workflows
    # with mutable-tag ECR repos honestly: the cache primitive and
    # the push live in the same job, so the poisoned cache content
    # actually reaches the image push. Walking the whole document
    # would anchor unrelated push jobs (e.g., a separate ``deploy``
    # job that pulls from a different ECR repo) and overstate
    # reachability. Cross-job ``needs:`` relationships would
    # legitimately chain too but require dataflow plumbing the
    # rule pack doesn't have today; that's the deliberate
    # under-claim, AC-017 falls back to co-occurrence in that case.
    ecr_anchors: dict[str, ResourceAnchor] = {}
    if not passed:
        for job in offending_jobs.values():
            for s in walk_strings(job):
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
